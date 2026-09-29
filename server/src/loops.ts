/**
 * Hot, warm and cold loops.
 *
 *   HOT   seconds, every alert, Jev only. Triage, the guardrail, reviewed memory, and a short list of related
 *         recent cases (a database lookup of a few milliseconds). Nothing in the warm or cold loop can delay it.
 *   WARM  minutes, in the background, after the hot verdict is saved. It never changes a verdict; it adds flags
 *         that put a case back in front of an analyst:
 *           - retro-flags: a case confirmed (or called) malicious flags recent auto-closed cases that share a host,
 *             account or indicator with it (no AI);
 *           - AI audit: the reviewer AI (any model) rechecks the riskiest benign closures, plus a small random sample;
 *           - the reviewer AI's second opinion on cases Jev couldn't settle (claude.ts).
 *   COLD  days, offline, a person approves every change: analyst decisions → `bun run eval` → `bun run review`
 *         → `bun run memory approve` (evaluate.ts, review.ts, proposals.ts, memory.ts).
 *
 * This file holds the warm-loop pieces: the entity index, the related-case lookup, flags, and the audit choice.
 */

import { and, eq, gte, inArray, isNull, lte, ne, or, sql } from "drizzle-orm";
import type { Db } from "./platform";
import * as schema from "./schema";
import type { CaseFacts } from "./memory";

export type EntityKind = "account" | "host" | "ip" | "domain" | "hash";
export type Entity = { kind: EntityKind; value: string };
export type RelatedOutcome = "analyst_malicious" | "analyst_benign" | "agent_malicious" | "open";
export type RelatedCase = { caseId: string; title: string; createdAt: string; daysAgo: number; shared: string[]; outcome: RelatedOutcome; reason: string | null };
export type FlagKind = "related_confirmed_malicious" | "related_agent_malicious" | "claude_disagrees";

// ---------------------------------------------------------------- settings
export type LoopSettings = {
  /** Days of case history searched for related cases (0 = off). */
  relatedWindowDays: number;
  /** The reviewer AI rechecks risky benign closures in the background. */
  audit: { enabled: boolean; samplePercent: number; dailyMax: number };
};
let SETTINGS: LoopSettings = { relatedWindowDays: 14, audit: { enabled: false, samplePercent: 5, dailyMax: 50 } };
export function setLoopSettings(s: LoopSettings): void { SETTINGS = s; }
export function loopSettings(): LoopSettings { return SETTINGS; }

// ---------------------------------------------------------------- entities
/** Names that appear on unrelated machines and would link cases that have nothing to do with each other. */
const GENERIC_ACCOUNTS = new Set(["system", "root", "administrator", "admin", "local service", "network service", "localsystem", "nt authority", "user", "guest", "default", "unknown", "n/a", "na", "none", "null", "-", "sa", "ec2-user", "ubuntu", "nobody", "www-data"]);
const GENERIC_HOSTS = new Set(["localhost", "unknown", "n/a", "none", "null", "-", "host", "server", "workstation"]);
const COMMON_DOMAINS = ["microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com", "live.com", "microsoftonline.com", "msftconnecttest.com", "azure.com", "azureedge.net", "windows.net", "google.com", "googleapis.com", "gstatic.com", "gmail.com", "apple.com", "icloud.com", "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamai.net", "github.com", "githubusercontent.com", "cloudflare.com", "digicert.com", "verisign.com", "outlook.com", "teams.microsoft.com"];
const isCommonDomain = (d: string) => COMMON_DOMAINS.some((c) => d === c || d.endsWith(`.${c}`));
const isUselessIp = (ip: string) => /^(127\.|0\.|169\.254\.|255\.255\.255\.255$)/.test(ip) || ip === "::1" || ip === "::";

/** Normalised hosts, accounts and indicators for correlation (at most 40). */
export function entitiesFrom(f: CaseFacts): Entity[] {
  const out = new Map<string, Entity>();
  const add = (kind: EntityKind, value: string) => { const v = value.trim().toLowerCase(); if (v.length >= 2 && v.length <= 300) out.set(`${kind} ${v}`, { kind, value: v }); };
  for (const u of f.users) { const bare = u.trim().toLowerCase().replace(/\\\\/g, "\\").split("\\").pop()!.split("@")[0]!; if (!GENERIC_ACCOUNTS.has(bare) && !bare.endsWith("$")) add("account", bare); }
  for (const h of f.hosts) { const short = h.trim().toLowerCase().split(".")[0]!; if (!GENERIC_HOSTS.has(short)) add("host", short); }
  for (const ip of f.ips) if (!isUselessIp(ip.trim())) add("ip", ip);
  for (const d of f.domains) if (d.includes(".") && !isCommonDomain(d.trim().toLowerCase())) add("domain", d);
  for (const h of f.hashes) add("hash", h);
  return [...out.values()].slice(0, 40);
}
export const describeEntity = (e: Entity) => `${e.kind} ${e.value}`;

/** Replaces the stored entities for a case (called whenever its result is saved). */
export function indexCaseEntities(db: Db, caseId: string, entities: Entity[]): void {
  db.transaction((tx) => {
    tx.delete(schema.caseEntities).where(eq(schema.caseEntities.caseId, caseId)).run();
    if (entities.length) tx.insert(schema.caseEntities).values(entities.map((e) => ({ caseId, kind: e.kind, value: e.value }))).onConflictDoNothing().run();
  });
}

// ---------------------------------------------------------------- related cases
const DAY = 86_400_000;
const RANK: Record<RelatedOutcome, number> = { analyst_malicious: 0, agent_malicious: 1, open: 2, analyst_benign: 3 };

/** Cases sharing any of `entities`, created within the window around `around`, excluding `excludeId`. */
function sharing(db: Db, viewerId: string, excludeId: string, entities: Entity[], from: Date, to: Date): Map<string, string[]> {
  if (!entities.length) return new Map();
  const rows = db.select({ caseId: schema.caseEntities.caseId, kind: schema.caseEntities.kind, value: schema.caseEntities.value })
    .from(schema.caseEntities).innerJoin(schema.triageCases, eq(schema.caseEntities.caseId, schema.triageCases.id))
    .where(and(or(...entities.map((e) => and(eq(schema.caseEntities.kind, e.kind), eq(schema.caseEntities.value, e.value)))), eq(schema.triageCases.viewerId, viewerId), ne(schema.triageCases.id, excludeId), gte(schema.triageCases.createdAt, from), lte(schema.triageCases.createdAt, to))).all();
  const byCase = new Map<string, string[]>();
  for (const r of rows) byCase.set(r.caseId, [...(byCase.get(r.caseId) ?? []), describeEntity(r)]);
  return byCase;
}

/**
 * Related recent cases worth showing to Jev and the analyst: ones a person decided, ones this system called
 * malicious, and open ones. The agent's own benign closures are left out, so it can't reinforce its own mistakes.
 */
export function findRelatedCases(db: Db, viewerId: string, excludeId: string, entities: Entity[], windowDays: number, now = new Date(), limit = 6): RelatedCase[] {
  if (windowDays <= 0) return [];
  const byCase = sharing(db, viewerId, excludeId, entities, new Date(now.getTime() - windowDays * DAY), now);
  if (!byCase.size) return [];
  const ids = [...byCase.keys()];
  const cases = db.select({ id: schema.triageCases.id, title: schema.triageCases.title, createdAt: schema.triageCases.createdAt, verdict: schema.triageCases.verdict }).from(schema.triageCases).where(inArray(schema.triageCases.id, ids)).all();
  const decisions = new Map(db.select().from(schema.dispositions).where(inArray(schema.dispositions.caseId, ids)).all().map((d) => [d.caseId, d]));
  const out: RelatedCase[] = [];
  for (const c of cases) {
    const d = decisions.get(c.id);
    const outcome: RelatedOutcome | null = d ? (d.label === "malicious" ? "analyst_malicious" : "analyst_benign") : c.verdict === "malicious" ? "agent_malicious" : c.verdict === "needs_human" ? "open" : null;
    if (!outcome) continue; // the agent's own benign closure, or not finished yet
    out.push({ caseId: c.id, title: c.title.slice(0, 160), createdAt: c.createdAt.toISOString(), daysAgo: Math.max(0, Math.floor((now.getTime() - c.createdAt.getTime()) / DAY)), shared: byCase.get(c.id)!.slice(0, 4), outcome, reason: d?.reason?.slice(0, 300) ?? null });
  }
  return out.sort((a, b) => RANK[a.outcome] - RANK[b.outcome] || b.createdAt.localeCompare(a.createdAt)).slice(0, limit);
}

export function relatedFinder(db: Db, viewerId: string, caseId: string, windowDays = SETTINGS.relatedWindowDays): ((entities: Entity[]) => Promise<RelatedCase[]>) | undefined {
  return windowDays > 0 ? async (entities) => findRelatedCases(db, viewerId, caseId, entities, windowDays) : undefined;
}

export const whenText = (daysAgo: number) => (daysAgo === 0 ? "today" : daysAgo === 1 ? "yesterday" : `${daysAgo} days ago`);

// ---------------------------------------------------------------- flags
function addFlag(db: Db, caseId: string, kind: FlagKind, detail: string, relatedCaseId: string | null): boolean {
  const existing = db.select({ id: schema.caseFlags.id }).from(schema.caseFlags).where(and(eq(schema.caseFlags.caseId, caseId), eq(schema.caseFlags.kind, kind), relatedCaseId ? eq(schema.caseFlags.relatedCaseId, relatedCaseId) : isNull(schema.caseFlags.relatedCaseId), isNull(schema.caseFlags.resolvedAt))).get();
  if (existing) return false;
  db.insert(schema.caseFlags).values({ id: crypto.randomUUID(), caseId, kind, detail: detail.slice(0, 1000), relatedCaseId, createdAt: new Date() }).run();
  return true;
}

/**
 * Retro-flag: `source` was confirmed (or called) malicious, so recent cases the agent closed as benign that share a
 * host, account or indicator with it are flagged for an analyst. Looks both before and after the source case.
 */
export function flagRelatedClosures(db: Db, sourceId: string, kind: "related_confirmed_malicious" | "related_agent_malicious", windowDays = SETTINGS.relatedWindowDays): number {
  if (windowDays <= 0) return 0;
  const source = db.select().from(schema.triageCases).where(eq(schema.triageCases.id, sourceId)).get();
  if (!source) return 0;
  const entities = db.select({ kind: schema.caseEntities.kind, value: schema.caseEntities.value }).from(schema.caseEntities).where(eq(schema.caseEntities.caseId, sourceId)).all();
  const t = source.createdAt.getTime();
  const byCase = sharing(db, source.viewerId, sourceId, entities, new Date(t - windowDays * DAY), new Date(t + windowDays * DAY));
  if (!byCase.size) return 0;
  const ids = [...byCase.keys()];
  const decided = new Set(db.select({ id: schema.dispositions.caseId }).from(schema.dispositions).where(inArray(schema.dispositions.caseId, ids)).all().map((d) => d.id));
  const closures = db.select({ id: schema.triageCases.id }).from(schema.triageCases).where(and(inArray(schema.triageCases.id, ids), eq(schema.triageCases.verdict, "benign"))).all().filter((c) => !decided.has(c.id));
  // A confirmed flag replaces the earlier "called malicious, not confirmed" one from the same case.
  if (kind === "related_confirmed_malicious") db.update(schema.caseFlags).set({ resolvedAt: new Date(), resolvedBy: "auto: replaced by the confirmed-malicious flag" }).where(and(eq(schema.caseFlags.relatedCaseId, sourceId), eq(schema.caseFlags.kind, "related_agent_malicious"), isNull(schema.caseFlags.resolvedAt))).run();
  let n = 0;
  const who = kind === "related_confirmed_malicious" ? "an analyst confirmed malicious" : "this system called malicious (not yet confirmed)";
  for (const c of closures) if (addFlag(db, c.id, kind, `Closed as benign, but shares ${byCase.get(c.id)!.slice(0, 3).join(", ")} with “${source.title.slice(0, 120)}”, which ${who}.`, sourceId)) n += 1;
  return n;
}

/** This benign closure shares a host, account or indicator with a case the system called malicious (not yet confirmed). */
export function flagClosureRelatedTo(db: Db, caseId: string, related: RelatedCase): boolean {
  return addFlag(db, caseId, "related_agent_malicious", `Closed as benign, but shares ${related.shared.slice(0, 3).join(", ")} with “${related.title.slice(0, 120)}” (${whenText(related.daysAgo)}), which this system called malicious (not yet confirmed).`, related.caseId);
}

export function flagClaudeDisagrees(db: Db, caseId: string, detail: string): void { addFlag(db, caseId, "claude_disagrees", detail, null); }

/** An analyst decided `caseId`: its own flags are done. If it was benign, flags it raised on other cases are withdrawn. */
export function resolveFlagsOnDecision(db: Db, caseId: string, label: "malicious" | "benign", by: string): void {
  const now = new Date();
  db.update(schema.caseFlags).set({ resolvedAt: now, resolvedBy: by }).where(and(eq(schema.caseFlags.caseId, caseId), isNull(schema.caseFlags.resolvedAt))).run();
  if (label === "benign") db.update(schema.caseFlags).set({ resolvedAt: now, resolvedBy: `auto: ${by} marked the related case benign` }).where(and(eq(schema.caseFlags.relatedCaseId, caseId), isNull(schema.caseFlags.resolvedAt))).run();
}

export function openFlagCounts(db: Db, caseIds: string[]): Map<string, number> {
  if (!caseIds.length) return new Map();
  const rows = db.select({ caseId: schema.caseFlags.caseId, n: sql<number>`count(*)` }).from(schema.caseFlags).where(and(inArray(schema.caseFlags.caseId, caseIds), isNull(schema.caseFlags.resolvedAt))).groupBy(schema.caseFlags.caseId).all();
  return new Map(rows.map((r) => [r.caseId, Number(r.n)]));
}

// ---------------------------------------------------------------- AI audit of benign closures
type AuditInput = { verdict: string; decidedBy: string; pMalicious: number | null; behaviors: Array<{ statement: string; strength: string }>; relatedCases?: RelatedCase[] };

/** Why this benign closure deserves a second look, or null. Risky closures first; then a small random sample. */
export function auditReason(r: AuditInput, samplePercent = SETTINGS.audit.samplePercent, random = Math.random): string | null {
  if (r.verdict !== "benign" || r.decidedBy !== "jev") return null;
  if ((r.pMalicious ?? 0) >= 0.08) return `close to the benign threshold (Jev ${Math.round((r.pMalicious ?? 0) * 100)}%)`;
  const suspicious = r.behaviors.filter((b) => b.strength === "strong" || b.strength === "moderate");
  if (suspicious.length) return `closed with ${suspicious.length} suspicious behaviour(s): ${suspicious[0]!.statement.slice(0, 120)}`;
  const unconfirmed = (r.relatedCases ?? []).find((c) => c.outcome === "agent_malicious" || c.outcome === "open");
  if (unconfirmed) return `related to a case that is ${unconfirmed.outcome === "open" ? "still open" : "not yet confirmed malicious"}`;
  if (samplePercent > 0 && random() * 100 < samplePercent) return "random sample of benign closures";
  return null;
}

/** Audits started in the last 24 hours (for the daily cap). */
export function auditsInLastDay(db: Db, now = new Date()): number {
  const row = db.select({ n: sql<number>`count(*)` }).from(schema.jobs).where(and(eq(schema.jobs.kind, "claudeAudit"), gte(schema.jobs.createdAt, new Date(now.getTime() - DAY)))).get();
  return Number(row?.n ?? 0);
}
