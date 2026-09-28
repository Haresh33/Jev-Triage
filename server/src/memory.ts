/**
 * Memory: what your team knows that a single alert doesn't show, reviewed and approved by people.
 *
 *   memory/context.yaml             organisation context: accounts, hosts, IPs, domains, hashes, tools, detections
 *   memory/question-criteria.yaml   what "yes" and "no" mean for specific questions (sent to Jev with the question)
 *   memory/lessons.md               a human log of misses and what fixed them (not read by the engine)
 *
 * At triage time only the entries that match the case are added to Jev's state, in their own labelled field,
 * so the state stays small and Jev can tell your team's context from the (attacker-controllable) alert.
 * Memory explains activity; it never clears the guardrail on its own (that still needs an analyst /note).
 *
 * Files are re-read when they change, so an approved entry takes effect on the next case without a restart.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

const date = z.union([z.string(), z.date()]).transform((v) => (v instanceof Date ? v.toISOString().slice(0, 10) : v)).pipe(z.string().regex(/^\d{4}-\d{2}-\d{2}/, "use YYYY-MM-DD"));

export const entrySchema = z.object({
  id: z.string().min(1).max(80).regex(/^[a-z0-9][a-z0-9._-]*$/i, "letters, digits, . _ - only"),
  kind: z.enum(["account", "host", "ip", "domain", "hash", "tool", "detection"]),
  match: z.array(z.string().min(1).max(300)).min(1).max(50),
  note: z.string().min(5).max(400),
  added_by: z.string().min(1).max(120),
  added_on: date,
  source: z.string().max(200).optional(),
  expires: date.optional(),
}).strict();
export type MemoryEntry = z.infer<typeof entrySchema>;

export const criteriaSchema = z.object({
  yes: z.string().min(5).max(400),
  no: z.string().min(5).max(400),
  added_by: z.string().min(1).max(120),
  added_on: date,
  source: z.string().max(200).optional(),
}).strict();
export type QuestionCriteria = z.infer<typeof criteriaSchema>;

const contextFile = z.object({ entries: z.array(entrySchema).max(5000).nullish() }).passthrough();
const criteriaFile = z.object({ criteria: z.record(z.string().regex(/^[a-z0-9_]+$/), criteriaSchema).nullish() }).passthrough();

/** What the engine knows about a case, for matching. */
export type CaseFacts = { users: string[]; hosts: string[]; ips: string[]; domains: string[]; hashes: string[]; commands: string[]; title: string };
export type MatchedContext = { id: string; kind: MemoryEntry["kind"]; note: string };

export type Memory = {
  entries: MemoryEntry[];
  criteria: Record<string, QuestionCriteria>;
  /** Entries relevant to this case (at most 12), most specific kinds first. */
  match(facts: CaseFacts): MatchedContext[];
  /** Criteria for a question id ("ioc_malicious@url:…" uses "ioc_malicious"). */
  criteriaFor(questionId: string): QuestionCriteria | undefined;
};

// ---------------------------------------------------------------- matching helpers
const lc = (s: string) => s.trim().toLowerCase();
/** "CORP\\sam", "sam@corp.com" and "sam" all name the same account. */
function accountForms(v: string): string[] {
  const x = lc(v).replace(/\\\\/g, "\\");
  const bare = x.split("\\").pop()!.split("@")[0]!;
  return [...new Set([x, bare])];
}
function hostForms(v: string): string[] { const x = lc(v); return [...new Set([x, x.split(".")[0]!])]; }
function ipToInt(ip: string): number | null {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!;
}
function ipMatches(pattern: string, ip: string): boolean {
  if (!pattern.includes("/")) return lc(pattern) === lc(ip);
  const [base, bitsRaw] = pattern.split("/"); const bits = Number(bitsRaw);
  const b = ipToInt(base ?? ""); const v = ipToInt(ip);
  if (b === null || v === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((b & mask) >>> 0) === ((v & mask) >>> 0);
}
const domainMatches = (pattern: string, d: string) => { const p = lc(pattern).replace(/^\*\./, ""); const x = lc(d); return x === p || x.endsWith(`.${p}`); };

const ORDER: Record<MemoryEntry["kind"], number> = { hash: 0, account: 1, host: 2, ip: 3, domain: 4, tool: 5, detection: 6 };

export function buildMemory(entries: MemoryEntry[], criteria: Record<string, QuestionCriteria>, today = new Date()): Memory {
  const now = today.toISOString().slice(0, 10);
  const live = entries.filter((e) => !e.expires || e.expires >= now);
  return {
    entries: live,
    criteria,
    criteriaFor(questionId) { return criteria[questionId.split("@")[0] ?? questionId]; },
    match(facts) {
      const users = new Set(facts.users.flatMap(accountForms));
      const hosts = new Set(facts.hosts.flatMap(hostForms));
      const hashes = new Set(facts.hashes.map(lc));
      const commands = facts.commands.map(lc);
      const title = lc(facts.title);
      const hits = live.filter((e) => e.match.some((m) => {
        switch (e.kind) {
          case "account": return accountForms(m).some((f) => users.has(f));
          case "host": return hostForms(m).some((f) => hosts.has(f));
          case "ip": return facts.ips.some((ip) => ipMatches(m, ip));
          case "domain": return facts.domains.some((d) => domainMatches(m, d));
          case "hash": return hashes.has(lc(m));
          case "tool": return lc(m).length >= 4 && commands.some((c) => c.includes(lc(m)));
          case "detection": return lc(m).length >= 4 && title.includes(lc(m));
        }
      }));
      return hits.sort((a, b) => ORDER[a.kind] - ORDER[b.kind]).slice(0, 12).map((e) => ({ id: e.id, kind: e.kind, note: e.note }));
    },
  };
}

export const EMPTY_MEMORY: Memory = buildMemory([], {});

/** Reads and validates the memory folder. Throws with a readable message when a file is invalid. */
export function readMemory(dir: string): Memory {
  const read = (name: string): unknown => {
    const file = join(dir, name);
    if (!existsSync(file)) return {};
    const text = readFileSync(file, "utf8");
    return text.trim() ? (Bun.YAML.parse(text) ?? {}) : {};
  };
  const ctx = contextFile.safeParse(read("context.yaml"));
  if (!ctx.success) throw new Error(`memory/context.yaml is invalid: ${ctx.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  const crit = criteriaFile.safeParse(read("question-criteria.yaml"));
  if (!crit.success) throw new Error(`memory/question-criteria.yaml is invalid: ${crit.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  const entries = ctx.data.entries ?? [];
  const ids = new Set<string>();
  for (const e of entries) { if (ids.has(e.id)) throw new Error(`memory/context.yaml: duplicate id "${e.id}"`); ids.add(e.id); }
  return buildMemory(entries, crit.data.criteria ?? {});
}

/** Re-reads the folder only when a file changed; keeps the last good version if an edit is invalid. */
export function memoryLoader(dir: string, log: (m: string) => void = console.warn): () => Memory {
  let cached = EMPTY_MEMORY; let stamp = "";
  return () => {
    const next = ["context.yaml", "question-criteria.yaml"].map((f) => { try { return String(statSync(join(dir, f)).mtimeMs); } catch { return "-"; } }).join("|");
    if (next === stamp) return cached;
    try { cached = readMemory(dir); stamp = next; } catch (error) { log(`[memory] ${error instanceof Error ? error.message : String(error)} (keeping the previous version)`); stamp = next; }
    return cached;
  };
}
