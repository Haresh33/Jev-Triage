/**
 * Log sources: settings from the environment, the registry the engine reads, and running one search across every
 * configured source (an organisation may have an EDR and a SIEM; both are searched in parallel and merged).
 */

import { existsSync, readFileSync } from "node:fs";
import { crowdstrikeSource } from "./crowdstrike";
import { defenderSource } from "./defender";
import { elasticSource } from "./elastic";
import { secopsSource, type ServiceAccount } from "./secops";
import { splunkSource } from "./splunk";
import { summarise, type Discovered } from "./summarise";
import { LOG_PROVIDERS, PROVIDER_NAME, type LogEvent, type LogProvider, type LogSearchSettings, type LogSearchView, type LogSource, type Pivot, type PivotKind } from "./types";
import { visionOneSource } from "./visionone";
import { pivotKey } from "./pivots";

export * from "./types";
export { alertTime, pivotKey, pivotsFor } from "./pivots";

type Env = Record<string, string | undefined>;
const PIVOTS: PivotKind[] = ["host_activity", "process_tree", "user_activity", "hash_prevalence", "ip_prevalence", "domain_prevalence"];

function baseUrl(env: Env, name: string, fallback: string): string {
  const raw = (env[name]?.trim() || fallback).replace(/\/+$/, "");
  let u: URL; try { u = new URL(raw); } catch { throw new Error(`${name} is not a valid URL.`); }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error(`${name} must use https (plain http only for a server on this machine).`);
  return raw;
}
const need = (env: Env, names: string[]) => names.every((n) => env[n]?.trim());

export type LogConfig = { providers: LogProvider[]; search: LogSearchSettings; build(): LogSource[] };

/** Reads the log-source settings. With LOG_SOURCES unset, every provider whose credentials are complete is used. */
export function logConfigFromEnv(env: Env = process.env): LogConfig {
  const int = (name: string, fallback: number, min: number, max: number) => { const raw = env[name]?.trim(); const n = raw ? Number(raw) : fallback; if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be a whole number between ${min} and ${max}.`); return n; };
  const complete: Record<LogProvider, boolean> = {
    crowdstrike: need(env, ["CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"]),
    splunk: need(env, ["SPLUNK_URL", "SPLUNK_TOKEN"]),
    secops: need(env, ["SECOPS_PROJECT", "SECOPS_INSTANCE"]) && Boolean(env.SECOPS_CREDENTIALS_FILE?.trim() || env.SECOPS_CREDENTIALS_JSON?.trim()),
    elastic: need(env, ["ELASTIC_URL", "ELASTIC_API_KEY"]),
    defender: need(env, ["DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"]),
    visionone: need(env, ["VISIONONE_TOKEN"]),
  };
  const listed = env.LOG_SOURCES?.trim();
  let providers: LogProvider[];
  if (!listed) providers = LOG_PROVIDERS.filter((p) => complete[p]);
  else if (listed === "none") providers = [];
  else {
    providers = listed.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean) as LogProvider[];
    for (const p of providers) {
      if (!LOG_PROVIDERS.includes(p)) throw new Error(`LOG_SOURCES: unknown source "${p}". Use ${LOG_PROVIDERS.join(", ")} or none.`);
      if (!complete[p]) throw new Error(`LOG_SOURCES includes ${p}, but its settings are incomplete (see .env.example).`);
    }
  }
  const opening = (env.LOG_SEARCH_OPENING?.trim() ?? "host_activity,process_tree").split(",").map((x) => x.trim()).filter(Boolean) as PivotKind[];
  for (const k of opening) if (!PIVOTS.includes(k)) throw new Error(`LOG_SEARCH_OPENING: unknown search "${k}". Use ${PIVOTS.join(", ")}.`);
  const search: LogSearchSettings = { windowMinutes: int("LOG_SEARCH_WINDOW_MINUTES", 30, 1, 1440), opening, timeoutMs: int("LOG_SEARCH_TIMEOUT_SECONDS", 30, 5, 300) * 1000, maxEvents: int("LOG_SEARCH_MAX_EVENTS", 200, 10, 1000) };
  // Validate everything now, so a mistake shows at startup rather than on the first alert.
  const builders: Record<LogProvider, () => LogSource> = {
    crowdstrike: () => {
      const repository = env.CROWDSTRIKE_REPOSITORY?.trim() || "search-all";
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(repository)) throw new Error("CROWDSTRIKE_REPOSITORY may contain only letters, digits, _ and -.");
      return crowdstrikeSource({ baseUrl: baseUrl(env, "CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"), clientId: env.CROWDSTRIKE_CLIENT_ID!.trim(), clientSecret: env.CROWDSTRIKE_CLIENT_SECRET!.trim(), memberCid: env.CROWDSTRIKE_MEMBER_CID?.trim() || undefined, repository, timeoutMs: search.timeoutMs });
    },
    splunk: () => splunkSource({ url: baseUrl(env, "SPLUNK_URL", ""), token: env.SPLUNK_TOKEN!.trim(), baseSearch: env.SPLUNK_BASE_SEARCH?.trim() || "index=*", timeoutMs: search.timeoutMs }),
    secops: () => {
      const location = env.SECOPS_LOCATION?.trim() || "us";
      if (!/^[a-z0-9-]{2,40}$/.test(location)) throw new Error("SECOPS_LOCATION looks wrong (for example us, eu or europe-west2).");
      const raw = env.SECOPS_CREDENTIALS_JSON?.trim() || (env.SECOPS_CREDENTIALS_FILE && existsSync(env.SECOPS_CREDENTIALS_FILE) ? readFileSync(env.SECOPS_CREDENTIALS_FILE, "utf8") : "");
      let account: ServiceAccount;
      try { account = JSON.parse(raw) as ServiceAccount; } catch { throw new Error("SECOPS_CREDENTIALS_FILE / SECOPS_CREDENTIALS_JSON must be a Google service account key (JSON)."); }
      if (!account?.client_email || !account?.private_key) throw new Error("The Google SecOps service account key has no client_email or private_key.");
      return secopsSource({ baseUrl: baseUrl(env, "SECOPS_BASE_URL", `https://${location}-chronicle.googleapis.com`), project: env.SECOPS_PROJECT!.trim(), location, instance: env.SECOPS_INSTANCE!.trim(), account, timeoutMs: search.timeoutMs });
    },
    elastic: () => {
      const index = env.ELASTIC_INDEX?.trim() || "logs-*";
      if (!/^[A-Za-z0-9._*,:-]{1,300}$/.test(index)) throw new Error("ELASTIC_INDEX may contain only index names, patterns and commas.");
      return elasticSource({ url: baseUrl(env, "ELASTIC_URL", ""), apiKey: env.ELASTIC_API_KEY!.trim(), index, timeoutMs: search.timeoutMs });
    },
    defender: () => defenderSource({ tenantId: env.DEFENDER_TENANT_ID!.trim(), clientId: env.DEFENDER_CLIENT_ID!.trim(), clientSecret: env.DEFENDER_CLIENT_SECRET!.trim(), graphUrl: baseUrl(env, "DEFENDER_GRAPH_URL", "https://graph.microsoft.com"), loginUrl: baseUrl(env, "DEFENDER_LOGIN_URL", "https://login.microsoftonline.com"), timeoutMs: search.timeoutMs }),
    visionone: () => visionOneSource({ baseUrl: baseUrl(env, "VISIONONE_BASE_URL", "https://api.xdr.trendmicro.com"), token: env.VISIONONE_TOKEN!.trim(), timeoutMs: search.timeoutMs }),
  };
  const built = providers.map((p) => builders[p]());
  return { providers, search, build: () => built };
}

// ---------------------------------------------------------------- registry (set once at startup, read by the engine)
let SOURCES: LogSource[] = [];
let SETTINGS: LogSearchSettings = { windowMinutes: 30, opening: ["host_activity", "process_tree"], timeoutMs: 30_000, maxEvents: 200 };
export function setLogSources(sources: LogSource[], settings?: LogSearchSettings): void { SOURCES = sources; if (settings) SETTINGS = settings; }
export function logSources(): LogSource[] { return SOURCES; }
export function logSearchSettings(): LogSearchSettings { return SETTINGS; }

export type LogSearcher = { settings: LogSearchSettings; sources: LogProvider[]; run(pivot: Pivot): Promise<{ view: LogSearchView; discovered: Discovered[] }> };

/** Runs one pivot on every source in parallel, merges the events and summarises them. Never throws. */
export async function runPivot(sources: LogSource[], pivot: Pivot, settings: LogSearchSettings): Promise<{ view: LogSearchView; discovered: Discovered[] }> {
  const results = await Promise.all(sources.map(async (s) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("timed out")), settings.timeoutMs + 2000); });
    try { return { s, r: await Promise.race([s.search(pivot, settings.maxEvents), timeout]) }; }
    catch (e) { return { s, r: { ok: false, events: [] as LogEvent[], truncated: false, query: "", error: `${PROVIDER_NAME[s.provider]}: ${(e as Error).message}`, durationMs: settings.timeoutMs } }; }
    finally { clearTimeout(timer); }
  }));
  const ok = results.filter((x) => x.r.ok);
  const events = ok.flatMap((x) => x.r.events).sort((a, b) => b.time.localeCompare(a.time)).slice(0, settings.maxEvents);
  const truncated = ok.some((x) => x.r.truncated);
  const errors = results.filter((x) => !x.r.ok).map((x) => x.r.error ?? `${PROVIDER_NAME[x.s.provider]} search failed.`);
  const { findings, discovered } = ok.length ? summarise(pivot, events, truncated) : { findings: [] as string[], discovered: [] as Discovered[] };
  return {
    view: { key: pivotKey(pivot), kind: pivot.kind, label: pivot.label, sources: ok.map((x) => PROVIDER_NAME[x.s.provider]), window: { start: pivot.start.toISOString(), end: pivot.end.toISOString() }, events: events.length, truncated, findings, errors },
    discovered,
  };
}

export function logSearcher(sources = SOURCES, settings = SETTINGS): LogSearcher | undefined {
  return sources.length ? { settings, sources: sources.map((s) => s.provider), run: (p) => runPivot(sources, p, settings) } : undefined;
}

export const describeLogs = (c: LogConfig) => (c.providers.length ? `${c.providers.map((p) => PROVIDER_NAME[p]).join(", ")} · opening searches: ${c.search.opening.join(", ") || "none"} · ±${c.search.windowMinutes} min` : "none configured (set credentials for CrowdStrike, Splunk, Google SecOps, Elastic, Defender or Vision One)");
