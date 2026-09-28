/**
 * Evaluation: run the agent on cases whose right answer is known and score it.
 *
 * Labelled cases come from two places:
 *   - eval/cases/*.json          cases you keep on purpose (a regression set)
 *   - the database               every case an analyst marked Malicious or Benign on the ticket
 *
 * Each case is run the way a new alert is: Jev only, up to 3 rounds, no analyst notes (the score is for
 * the agent's first look, which is what decides whether an alert needs a person at all).
 *
 * Enrichment lookups (VirusTotal, Shodan, AbuseIPDB, DNS, RDAP, InternetDB) are recorded the first time and
 * replayed after that, so when the score moves it's because the agent changed, not the threat intel.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { z } from "zod";
import type { Ctx, Db, ProviderResponse, Services } from "./platform";
import * as schema from "./schema";
import { finaliseJevOnly, investigate, type TriageResult, type Verdict } from "./triage";

export type Label = "malicious" | "benign";
export type LabelledCase = { ref: string; source: "file" | "database"; alert: string; label: Label; notes: string[]; why: string | null; decidedBy: string | null };
export type Outcome = "correct" | "false_benign" | "false_malicious" | "needs_analyst" | "error";
export type CaseOutcome = {
  ref: string; source: LabelledCase["source"]; label: Label; why: string | null; decidedBy: string | null;
  verdict: Verdict | null; outcome: Outcome; pMalicious: number | null; durationMs: number; jevRequests: number;
  orgContext: string[]; stopReason: string | null; error?: string;
  /** Kept only for cases the agent didn't get right: the review step reads it. */
  alert?: string; result?: TriageResult;
};

// ---------------------------------------------------------------- loading cases
const fileCase = z.object({
  id: z.string().min(1).max(120).optional(),
  alert: z.union([z.string().min(1), z.record(z.string(), z.unknown()), z.array(z.unknown())]),
  label: z.enum(["malicious", "benign"]),
  notes: z.array(z.string().min(1).max(2000)).max(20).optional(),
  why: z.string().max(2000).optional(),
}).strict();

/** Reads eval/cases/*.json. A file holds one case or an array of cases. */
export function loadCaseFiles(dir: string): LabelledCase[] {
  if (!existsSync(dir)) return [];
  const out: LabelledCase[] = [];
  for (const name of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    let data: unknown;
    try { data = JSON.parse(readFileSync(join(dir, name), "utf8")); } catch (error) { throw new Error(`${name}: not valid JSON (${error instanceof Error ? error.message : error})`); }
    const list = Array.isArray(data) ? data : [data];
    list.forEach((item, index) => {
      const parsed = fileCase.safeParse(item);
      if (!parsed.success) throw new Error(`${name}${Array.isArray(data) ? ` item ${index + 1}` : ""}: ${parsed.error.issues.slice(0, 2).map((i) => `${i.path.join(".") || "case"}: ${i.message}`).join("; ")}`);
      const c = parsed.data;
      out.push({ ref: `${name.replace(/\.json$/, "")}#${c.id ?? index + 1}`, source: "file", alert: typeof c.alert === "string" ? c.alert : JSON.stringify(c.alert, null, 2), label: c.label, notes: c.notes ?? [], why: c.why ?? null, decidedBy: null });
    });
  }
  return out;
}

/** Every case an analyst decided on the ticket. */
export async function loadDatabaseCases(db: Db): Promise<LabelledCase[]> {
  const rows = await db.select({ id: schema.triageCases.id, title: schema.triageCases.title, alert: schema.triageCases.inputText, label: schema.dispositions.label, reason: schema.dispositions.reason, decidedBy: schema.dispositions.decidedBy })
    .from(schema.dispositions).innerJoin(schema.triageCases, eq(schema.dispositions.caseId, schema.triageCases.id)).orderBy(schema.dispositions.decidedAt);
  return rows.map((r) => ({ ref: `case:${r.id.slice(0, 8)} ${r.title.slice(0, 60)}`, source: "database" as const, alert: r.alert, label: r.label, notes: [], why: r.reason, decidedBy: r.decidedBy }));
}

// ---------------------------------------------------------------- recorded lookups
const PUBLIC_LOOKUP_HOSTS = new Set(["dns.google", "rdap.org", "internetdb.shodan.io"]);
type Recorded = { status: number; body: string };
export type LookupCache = { services(inner: Services): Services; installFetch(): () => void; save(): void; stats: { hits: number; misses: number } };

/** Removes credentials from a URL before it's used as a cache key. */
export function cacheKeyForUrl(raw: string): string {
  const u = new URL(raw);
  for (const k of [...u.searchParams.keys()]) if (/^(key|api_?key|apikey|token|access_token)$/i.test(k)) u.searchParams.delete(k);
  return `${u.host}${u.pathname}${u.search}`;
}

/** Records lookups to `file` and replays them. Only definite answers (found / not found) are kept. */
export function lookupCache(file: string | null): LookupCache {
  const store: Record<string, Recorded | ProviderResponse> = file && existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) as Record<string, Recorded | ProviderResponse> : {};
  const stats = { hits: 0, misses: 0 };
  let dirty = false;
  const definite = (r: ProviderResponse): boolean => {
    if (!r.ok || r.dataJson === null) return false;
    try { const v = JSON.parse(r.dataJson) as { status?: unknown }; return v.status === undefined || v.status === 200 || v.status === 404; } catch { return false; }
  };
  const wrap = <A,>(key: (a: A) => string, call: (a: A) => Promise<ProviderResponse>) => async (a: A): Promise<ProviderResponse> => {
    const k = key(a); const hit = store[k] as ProviderResponse | undefined;
    if (hit) { stats.hits += 1; return { ...hit, durationMs: 0 }; }
    stats.misses += 1; const r = await call(a);
    if (definite(r)) { store[k] = r; dirty = true; }
    return r;
  };
  return {
    stats,
    services: (inner) => ({
      ...inner,
      virustotalLookup: wrap((a: { path: string; delayMs: number }) => `vt ${a.path}`, (a) => inner.virustotalLookup(a)),
      shodanEntity: wrap((a: { entity: string; kind: "ip" | "domain" }) => `shodan ${a.kind} ${a.entity.toLowerCase()}`, (a) => inner.shodanEntity(a)),
      abuseIpdbLookup: wrap((a: { ip: string }) => `abuseipdb ${a.ip}`, (a) => inner.abuseIpdbLookup(a)),
    }),
    installFetch() {
      const original = globalThis.fetch;
      const replacement = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
        let host = ""; try { host = new URL(url).host; } catch { /* not a URL */ }
        if (method !== "GET" || !PUBLIC_LOOKUP_HOSTS.has(host)) return original(input, init);
        const k = `get ${cacheKeyForUrl(url)}`; const hit = store[k] as Recorded | undefined;
        if (hit) { stats.hits += 1; return new Response(hit.body, { status: hit.status, headers: { "content-type": "application/json" } }); }
        stats.misses += 1;
        const res = await original(input, init);
        if (res.status === 200 || res.status === 404) { store[k] = { status: res.status, body: await res.clone().text() }; dirty = true; }
        return res;
      };
      globalThis.fetch = Object.assign(replacement, { preconnect: original.preconnect }) as typeof fetch;
      return () => { globalThis.fetch = original; };
    },
    save() { if (file && dirty) { writeFileSync(file, JSON.stringify(store)); dirty = false; } },
  };
}

// ---------------------------------------------------------------- running
export function outcomeFor(label: Label, verdict: Verdict): Outcome {
  if (verdict === "needs_human") return "needs_analyst";
  if (verdict === label) return "correct";
  return label === "malicious" ? "false_benign" : "false_malicious";
}

/** Runs every case (a few at a time) and scores it. `makeCtx` gives each case a fresh context. */
export async function evaluateCases(cases: LabelledCase[], makeCtx: () => Ctx, opts: { concurrency?: number; rounds?: number; onCase?: (o: CaseOutcome, done: number, total: number) => void } = {}): Promise<CaseOutcome[]> {
  const out: CaseOutcome[] = new Array(cases.length);
  let next = 0; let done = 0;
  async function worker() {
    for (;;) {
      const i = next++; const c = cases[i]; if (!c) return;
      const started = performance.now();
      let o: CaseOutcome;
      try {
        const result = finaliseJevOnly(await investigate(makeCtx(), c.alert, c.notes, [], opts.rounds ?? 3));
        const outcome = outcomeFor(c.label, result.verdict);
        o = { ref: c.ref, source: c.source, label: c.label, why: c.why, decidedBy: c.decidedBy, verdict: result.verdict, outcome, pMalicious: result.pMalicious, durationMs: Math.round(performance.now() - started), jevRequests: result.jevRequests, orgContext: (result.orgContext ?? []).map((x) => x.id), stopReason: result.stopReason, ...(outcome === "correct" ? {} : { alert: c.alert, result }) };
      } catch (error) {
        o = { ref: c.ref, source: c.source, label: c.label, why: c.why, decidedBy: c.decidedBy, verdict: null, outcome: "error", pMalicious: null, durationMs: Math.round(performance.now() - started), jevRequests: 0, orgContext: [], stopReason: null, error: error instanceof Error ? error.message : String(error) };
      }
      out[i] = o; done += 1; opts.onCase?.(o, done, cases.length);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(opts.concurrency ?? 2, cases.length)) }, worker));
  return out;
}

// ---------------------------------------------------------------- scoring
export type Summary = {
  cases: number; malicious: number; benign: number;
  correct: number; falseBenign: number; falseMalicious: number; needsAnalyst: number; errors: number;
  /** Right answers out of all cases. */
  accuracy: number;
  /** Right answers out of the cases the agent decided (closed without a person). */
  decidedAccuracy: number | null;
  /** Share of cases the agent closed on its own. */
  automationRate: number;
  /** Malicious cases the agent didn't call benign (caught or sent to an analyst). */
  maliciousCaughtOrEscalated: number | null;
  medianSeconds: number | null; p90Seconds: number | null; jevRequestsPerCase: number | null;
};
const pct = (n: number, d: number) => (d ? Math.round((n / d) * 1000) / 10 : 0);
function quantile(xs: number[], q: number): number | null { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(q * s.length))]!; }

export function summarise(outcomes: CaseOutcome[]): Summary {
  const count = (o: Outcome) => outcomes.filter((x) => x.outcome === o).length;
  const correct = count("correct"); const fb = count("false_benign"); const fm = count("false_malicious");
  const decided = correct + fb + fm; const ran = outcomes.filter((x) => x.outcome !== "error");
  const malicious = outcomes.filter((x) => x.label === "malicious");
  const secs = ran.map((x) => x.durationMs / 1000);
  return {
    cases: outcomes.length, malicious: malicious.length, benign: outcomes.length - malicious.length,
    correct, falseBenign: fb, falseMalicious: fm, needsAnalyst: count("needs_analyst"), errors: count("error"),
    accuracy: pct(correct, outcomes.length), decidedAccuracy: decided ? pct(correct, decided) : null, automationRate: pct(decided, outcomes.length),
    maliciousCaughtOrEscalated: malicious.length ? pct(malicious.filter((x) => x.outcome !== "false_benign" && x.outcome !== "error").length, malicious.length) : null,
    medianSeconds: quantile(secs, 0.5) === null ? null : Math.round(quantile(secs, 0.5)! * 10) / 10,
    p90Seconds: quantile(secs, 0.9) === null ? null : Math.round(quantile(secs, 0.9)! * 10) / 10,
    jevRequestsPerCase: ran.length ? Math.round((ran.reduce((a, x) => a + x.jevRequests, 0) / ran.length) * 10) / 10 : null,
  };
}

export type Change = { ref: string; label: Label; before: Outcome; after: Outcome; beforeVerdict: Verdict | null; afterVerdict: Verdict | null; direction: "fixed" | "broken" | "changed" };
/** Cases whose outcome differs between two runs over the same cases. */
export function compareRuns(before: CaseOutcome[], after: CaseOutcome[]): Change[] {
  const byRef = new Map(before.map((x) => [x.ref, x]));
  const rank = (o: Outcome) => (o === "correct" ? 2 : o === "needs_analyst" ? 1 : 0);
  return after.flatMap((a) => {
    const b = byRef.get(a.ref); if (!b || b.outcome === a.outcome) return [];
    return [{ ref: a.ref, label: a.label, before: b.outcome, after: a.outcome, beforeVerdict: b.verdict, afterVerdict: a.verdict, direction: rank(a.outcome) > rank(b.outcome) ? "fixed" as const : rank(a.outcome) < rank(b.outcome) ? "broken" as const : "changed" as const }];
  });
}

// ---------------------------------------------------------------- report
export type Report = {
  createdAt: string;
  settings: { jev: string; memory: string; lookups: string; sources: string[]; rounds: number };
  summary: Summary;
  outcomes: CaseOutcome[];
  trial?: { proposalFile: string; ids: string[]; summary: Summary; changes: Change[]; outcomes: CaseOutcome[] };
};

const LABEL: Record<Outcome, string> = { correct: "correct", false_benign: "**missed: called benign**", false_malicious: "**false alarm: called malicious**", needs_analyst: "sent to analyst", error: "error" };
const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();

function summaryTable(s: Summary): string {
  return [
    "| | |", "|---|---|",
    `| Cases | ${s.cases} (${s.malicious} malicious, ${s.benign} benign) |`,
    `| Correct | ${s.correct} (**${s.accuracy}%**) |`,
    `| Missed: malicious called benign | **${s.falseBenign}** |`,
    `| False alarms: benign called malicious | ${s.falseMalicious} |`,
    `| Sent to an analyst | ${s.needsAnalyst} |`,
    ...(s.errors ? [`| Errors | ${s.errors} |`] : []),
    `| Closed without a person | ${s.automationRate}% (right ${s.decidedAccuracy ?? "–"}% of the time) |`,
    `| Malicious cases not missed | ${s.maliciousCaughtOrEscalated ?? "–"}% |`,
    `| Time per case | median ${s.medianSeconds ?? "–"} s, 90th percentile ${s.p90Seconds ?? "–"} s |`,
    `| Jev requests per case | ${s.jevRequestsPerCase ?? "–"} |`,
  ].join("\n");
}

export function renderReport(r: Report): string {
  const misses = r.outcomes.filter((x) => x.outcome !== "correct");
  const lines = [
    `# Evaluation ${r.createdAt.slice(0, 16).replace("T", " ")}`, "",
    `Jev: ${r.settings.jev} · Memory: ${r.settings.memory} · Lookups: ${r.settings.lookups} · Cases from: ${r.settings.sources.join(", ")}`, "",
    summaryTable(r.summary), "",
    `## Cases the agent didn't get right (${misses.length})`, "",
  ];
  if (!misses.length) lines.push("None.");
  else {
    lines.push("| Case | Right answer | Agent | P(malicious) | Context used | Analyst's reason |", "|---|---|---|---|---|---|");
    const order: Outcome[] = ["false_benign", "false_malicious", "error", "needs_analyst"];
    for (const x of [...misses].sort((a, b) => order.indexOf(a.outcome) - order.indexOf(b.outcome))) {
      lines.push(`| ${esc(x.ref)} | ${x.label} | ${LABEL[x.outcome]}${x.error ? `: ${esc(x.error).slice(0, 120)}` : ""} | ${x.pMalicious ?? "–"} | ${x.orgContext.join(", ") || "–"} | ${esc(x.why ?? "").slice(0, 160) || "–"} |`);
    }
  }
  if (r.trial) {
    const t = r.trial;
    lines.push("", `## With proposals ${t.ids.join(", ")} from ${t.proposalFile}`, "", summaryTable(t.summary), "");
    if (!t.changes.length) lines.push("No case changed outcome.");
    else {
      lines.push("| Case | Right answer | Before | After | |", "|---|---|---|---|---|");
      for (const c of t.changes) lines.push(`| ${esc(c.ref)} | ${c.label} | ${LABEL[c.before]} | ${LABEL[c.after]} | ${c.direction === "fixed" ? "fixed" : c.direction === "broken" ? "**worse**" : "changed"} |`);
    }
  }
  lines.push("", "Next: `bun run review` asks the reviewer AI to propose fixes for these cases. Nothing changes until you approve a proposal.");
  return `${lines.join("\n")}\n`;
}
