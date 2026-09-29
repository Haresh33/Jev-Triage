/**
 * All runtime settings come from environment variables (or a `.env` file, which Bun loads automatically).
 * See `.env.example` for the full list with explanations.
 */

import { resolve } from "node:path";
import { describeAi, type AiProvider, type AiSettings } from "./ai";
import { describeLogs, logConfigFromEnv } from "./logs";

export type ClaudeMode = "off" | "second_opinion" | "tiebreak";

const env = (name: string): string | undefined => {
  const v = process.env[name]?.trim();
  return v ? v : undefined;
};
const int = (name: string, fallback: number, min: number, max: number): number => {
  const raw = env(name);
  const n = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be a whole number between ${min} and ${max}.`);
  return n;
};

export type Config = ReturnType<typeof loadConfig>;

const intAlias = (names: string[], fallback: number, min: number, max: number): number => { const name = names.find((n) => env(n) !== undefined) ?? names[0]!; return int(name, fallback, min, max); };

/**
 * AI_PROVIDER  anthropic (default) or openai (any OpenAI-compatible API: OpenAI, Azure OpenAI, Gemini, OpenRouter, Ollama…)
 * AI_API_KEY   the provider's key (ANTHROPIC_API_KEY / OPENAI_API_KEY also work). Not needed for a local server.
 * AI_MODEL     model name(s), comma-separated; later ones are fallbacks (CLAUDE_MODELS also works for Anthropic)
 * AI_BASE_URL  the API address, for anything other than the provider's default
 */
function aiSettings(): AiSettings {
  const provider = (env("AI_PROVIDER") ?? "anthropic").toLowerCase() as AiProvider;
  if (!["anthropic", "openai"].includes(provider)) throw new Error("AI_PROVIDER must be anthropic or openai (openai covers any OpenAI-compatible API, e.g. Azure OpenAI, Gemini, OpenRouter, Ollama).");
  const apiKey = env("AI_API_KEY") ?? (provider === "anthropic" ? env("ANTHROPIC_API_KEY") : env("OPENAI_API_KEY"));
  const baseUrl = (env("AI_BASE_URL") ?? (provider === "anthropic" ? "https://api.anthropic.com" : "https://api.openai.com/v1")).replace(/\/+$/, "");
  let url: URL;
  try { url = new URL(baseUrl); } catch { throw new Error("AI_BASE_URL is not a valid URL."); }
  const local = ["localhost", "127.0.0.1", "[::1]", "host.docker.internal"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error("AI_BASE_URL must use https (plain http is allowed only for a server on this machine, such as Ollama).");
  const models = (env("AI_MODEL") ?? env("CLAUDE_MODELS") ?? (provider === "anthropic" ? "claude-sonnet-5,claude-sonnet-4-5-20250929" : "")).split(",").map((m) => m.trim()).filter(Boolean);
  if (provider === "openai" && (apiKey || env("AI_BASE_URL")) && !models.length) throw new Error("AI_PROVIDER=openai needs AI_MODEL (for example gpt-4.1-mini, gemini-2.5-flash, or the name of a local model).");
  return { provider, apiKey, baseUrl, models, configured: models.length > 0 && (Boolean(apiKey) || (provider === "openai" && local)) };
}

export function loadConfig() {
  const dataDir = resolve(env("DATA_DIR") ?? "./data");
  const ai = aiSettings();
  const ingestToken = env("INGEST_TOKEN");
  if (ingestToken && ingestToken.length < 24) throw new Error("INGEST_TOKEN must be at least 24 characters (for example: openssl rand -hex 24).");
  const aiMode = (env("AI_MODE") ?? env("CLAUDE_MODE") ?? (ai.configured ? "second_opinion" : "off")) as ClaudeMode;
  if (!["off", "second_opinion", "tiebreak"].includes(aiMode)) throw new Error("AI_MODE must be off, second_opinion or tiebreak.");
  if (aiMode !== "off" && !ai.configured) throw new Error(`AI_MODE=${aiMode} needs a reviewer AI. Set AI_API_KEY (and AI_PROVIDER / AI_MODEL for a non-Anthropic model), or set AI_MODE=off.`);
  const audit = env("AI_AUDIT") ?? env("CLAUDE_AUDIT") ?? (ai.configured ? "on" : "off");
  if (!["on", "off"].includes(audit)) throw new Error("AI_AUDIT must be on or off.");
  if (audit === "on" && !ai.configured) throw new Error("AI_AUDIT=on needs a reviewer AI. Set AI_API_KEY, or set AI_AUDIT=off.");
  return {
    host: env("HOST") ?? "127.0.0.1",
    port: int("PORT", 3000, 1, 65535),
    dataDir,
    databasePath: resolve(env("DATABASE_PATH") ?? `${dataDir}/jev-triage.db`),
    uploadDir: resolve(`${dataDir}/uploads`),
    memoryDir: resolve(env("MEMORY_DIR") ?? "./memory"),
    /** Labelled cases, evaluation reports and recorded lookups for `bun run eval` / `review`. */
    evalDir: resolve(env("EVAL_DIR") ?? "./eval"),
    auth: { user: env("AUTH_USER"), password: env("AUTH_PASSWORD"), allowNoAuth: env("ALLOW_NO_AUTH") === "true" },
    /** Extra host names the app may be reached by (e.g. triage.corp.example). localhost names are always allowed. */
    allowedHosts: (env("ALLOWED_HOSTS") ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean),
    /** Bearer token for POST /ingest/alert (alerts pushed in by a SIEM / XDR / EDR). Unset = the endpoint is off. */
    ingestToken,
    workerConcurrency: int("WORKER_CONCURRENCY", 2, 1, 16),
    retentionDays: int("RETENTION_DAYS", 0, 0, 3650),
    jev: { apiKey: env("TYPESAFE_API_KEY"), baseUrl: (env("TYPESAFE_BASE_URL") ?? "https://api.typesafe.ai").replace(/\/+$/, ""), model: env("JEV_MODEL") ?? "jev-latest" },
    virustotalKey: env("VIRUSTOTAL_API_KEY"),
    shodanKey: env("SHODAN_API_KEY"),
    abuseIpdbKey: env("ABUSEIPDB_API_KEY"),
    /** EDR / SIEM / XDR log search around each alert (see logs/). */
    logs: logConfigFromEnv(),
    /** Hot / warm / cold loops (see loops.ts). */
    loops: {
      relatedWindowDays: int("RELATED_WINDOW_DAYS", 14, 0, 365),
      audit: { enabled: audit === "on", samplePercent: intAlias(["AI_AUDIT_SAMPLE_PERCENT", "CLAUDE_AUDIT_SAMPLE_PERCENT"], 5, 0, 100), dailyMax: intAlias(["AI_AUDIT_DAILY_MAX", "CLAUDE_AUDIT_DAILY_MAX"], 50, 0, 100_000) },
    },
    /** The reviewer AI (any provider): second opinions, audits and `bun run review`. Never makes triage calls. */
    ai: { ...ai, mode: aiMode },
  };
}

/** Plain-language startup summary: which sources are on, never the key values. */
export function describeConfig(c: Config): string[] {
  const on = (v: unknown) => (v ? "configured" : "not set");
  return [
    `Jev (TypeSafe): ${on(c.jev.apiKey)} · model ${c.jev.model}`,
    `VirusTotal: ${on(c.virustotalKey)} · Shodan: ${on(c.shodanKey)} (free InternetDB is always used for IPs) · AbuseIPDB: ${on(c.abuseIpdbKey)}`,
    `Reviewer AI: ${c.ai.configured ? `${describeAi(c.ai)} · mode ${c.ai.mode.replace("_", " ")}` : "not configured"}`,
    `Log search: ${describeLogs(c.logs)}`,
    `Loops: hot = Jev${c.ai.mode === "tiebreak" ? " + AI tiebreak" : ""}${c.loops.relatedWindowDays ? `, related cases from the last ${c.loops.relatedWindowDays} days` : ""} · warm = ${[c.loops.relatedWindowDays ? "retro-flags" : "", c.loops.audit.enabled ? `AI audit of benign closures (${c.loops.audit.samplePercent}% sample, at most ${c.loops.audit.dailyMax}/day)` : "", c.ai.mode === "second_opinion" ? "AI second opinion" : ""].filter(Boolean).join(", ") || "off"} · cold = memory, \`bun run eval\` / \`review\``,
    `Data: ${c.databasePath}${c.retentionDays ? ` · cases deleted after ${c.retentionDays} days` : ""}`,
    `Alert webhook: ${c.ingestToken ? "on (POST /ingest/alert with the INGEST_TOKEN bearer token)" : "off (set INGEST_TOKEN to turn it on)"}`,
    `Answers requests for: ${c.auth.user && c.auth.password && !c.allowedHosts.length ? "any host name (login required)" : ["localhost", "127.0.0.1", ...c.allowedHosts].join(", ")}`,
    `Login: ${c.auth.user ? `required (user ${c.auth.user})` : c.auth.allowNoAuth && !["127.0.0.1", "::1", "localhost"].includes(c.host) ? "none: ALLOW_NO_AUTH is set (keep the port local-only, or put a login proxy in front)" : "none (this machine only)"}`,
  ];
}
