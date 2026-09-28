/**
 * bun run eval: score the agent on cases whose right answer is known.
 *
 *   bun run eval                              eval/cases/*.json + every case an analyst marked on a ticket
 *   bun run eval --try <proposal file> [ids]  also run with those proposals added to memory, and show what changes
 *   bun run eval --no-memory                  score without the memory folder (to see what memory adds)
 *   bun run eval --stand-in                   no keys, no network: checks the plumbing, not real accuracy
 *   bun run eval --with-logs                  also search the configured EDR / SIEM / XDR around each alert
 *
 * Other options: --cases <dir>, --no-database, --only-database, --fresh-lookups, --concurrency <n>,
 * --limit <n>, --max-missed <n> (exit with an error if more malicious cases are called benign; for CI).
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { loadConfig } from "../server/src/config";
import { openDatabase } from "../server/src/db";
import { compareRuns, evaluateCases, loadCaseFiles, loadDatabaseCases, lookupCache, renderReport, summarise, type CaseOutcome, type LabelledCase, type Report } from "../server/src/evaluate";
import { createJobQueue } from "../server/src/jobs";
import { EMPTY_MEMORY, readMemory, type Memory } from "../server/src/memory";
import type { Ctx, Services } from "../server/src/platform";
import { memoryWithProposals, readProposalFile, select } from "../server/src/proposals";
import { createServices } from "../server/src/services";
import { logSearcher } from "../server/src/logs";

const argv = process.argv.slice(2);
const flag = (name: string) => argv.includes(name);
const value = (name: string) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const intOpt = (name: string, fallback: number) => { const v = value(name); const n = v === undefined ? fallback : Number(v); if (!Number.isInteger(n) || n < 0) die(`${name} needs a whole number.`); return n; };
function die(message: string): never { console.error(`eval: ${message}`); process.exit(2); }

const config = loadConfig();
const standIn = flag("--stand-in");
if (!standIn && !config.jev.apiKey) die("TYPESAFE_API_KEY is not set. Set it in .env, or use --stand-in to check the setup without keys.");

// ---- cases
const casesDir = resolve(value("--cases") ?? join(config.evalDir, "cases"));
const cases: LabelledCase[] = [];
const sources: string[] = [];
try {
  if (!flag("--only-database")) { const c = loadCaseFiles(casesDir); cases.push(...c); sources.push(`${relative(process.cwd(), casesDir) || "."} (${c.length})`); }
  if (!flag("--no-database") && existsSync(config.databasePath)) {
    const { db, sqlite } = openDatabase(config.databasePath);
    const c = await loadDatabaseCases(db); sqlite.close();
    cases.push(...c); sources.push(`analyst decisions in the database (${c.length})`);
  }
} catch (error) { die(error instanceof Error ? error.message : String(error)); }
const limit = intOpt("--limit", 0);
if (limit && cases.length > limit) { cases.splice(limit); sources.push(`first ${limit} only (--limit)`); }
if (!cases.length) die(`no labelled cases. Add files to ${relative(process.cwd(), casesDir)}/ (see eval/cases/README.md), or mark cases Malicious / Benign on their tickets.`);

// ---- memory
let memory: Memory;
try { memory = flag("--no-memory") ? EMPTY_MEMORY : readMemory(config.memoryDir); } catch (error) { die(error instanceof Error ? error.message : String(error)); }
const tryFile = value("--try");
const tryIds: string[] = [];
if (tryFile) for (const a of argv.slice(argv.indexOf("--try") + 2)) { if (a.startsWith("--")) break; tryIds.push(...a.split(",").filter(Boolean)); }

// ---- services: real (with recorded lookups) or the offline stand-in
let services: Services;
let restoreFetch = () => {};
let cache: ReturnType<typeof lookupCache> | null = null;
if (standIn) {
  const helpers = await import("../tests/helpers");
  services = helpers.standInServices("reads_evidence");
  restoreFetch = helpers.stubPublicFetch();
} else {
  mkdirSync(config.evalDir, { recursive: true });
  cache = lookupCache(flag("--fresh-lookups") ? null : join(config.evalDir, "lookup-cache.json"));
  services = cache.services(createServices(config));
  restoreFetch = cache.installFetch();
}
const { db } = openDatabase(":memory:");
const jobs = createJobQueue(db);
const logs = flag("--with-logs") && !standIn ? logSearcher(config.logs.build(), config.logs.search) : undefined;
if (flag("--with-logs") && !logs) die(standIn ? "--with-logs can't be combined with --stand-in." : "--with-logs needs a log source (see Log search in .env.example).");
const ctxWith = (m: Memory) => (): Ctx => ({ db: () => db, viewer: { id: "eval" }, services, jobs, memory: m, logs });

// ---- run
const concurrency = intOpt("--concurrency", 2) || 1;
const progress = (o: CaseOutcome, done: number, total: number) => {
  const mark = o.outcome === "correct" ? "ok  " : o.outcome === "needs_analyst" ? "?   " : o.outcome === "error" ? "ERR " : "MISS";
  process.stdout.write(`  [${String(done).padStart(String(total).length)}/${total}] ${mark} ${o.ref.slice(0, 70)}  (${o.label} → ${o.verdict ?? o.error}, ${(o.durationMs / 1000).toFixed(1)} s)\n`);
};
console.log(`Evaluating ${cases.length} case(s) · Jev: ${standIn ? "stand-in (no network)" : config.jev.model} · memory: ${memory.entries.length} context entries, ${Object.keys(memory.criteria).length} question wording(s)`);
const outcomes = await evaluateCases(cases, ctxWith(memory), { concurrency, onCase: progress });

let trial: Report["trial"];
if (tryFile) {
  let proposals;
  try { proposals = select(readProposalFile(tryFile), tryIds.length ? tryIds : ["all"]); } catch (error) { die(error instanceof Error ? error.message : String(error)); }
  if (!proposals.length) die(`nothing pending in ${tryFile} to try.`);
  console.log(`\nAgain with proposals ${proposals.map((p) => p.id).join(", ")} added to memory:`);
  const withProposals = memoryWithProposals(config.memoryDir, proposals);
  const after = await evaluateCases(cases, ctxWith(withProposals), { concurrency, onCase: progress });
  trial = { proposalFile: relative(process.cwd(), resolve(tryFile)), ids: proposals.map((p) => p.id), summary: summarise(after), changes: compareRuns(outcomes, after), outcomes: after };
}
restoreFetch();
cache?.save();

// ---- report
const report: Report = {
  createdAt: new Date().toISOString(),
  settings: { jev: standIn ? "stand-in (no network)" : config.jev.model, memory: flag("--no-memory") ? "off" : `${memory.entries.length} context entries, ${Object.keys(memory.criteria).length} question wording(s)`, lookups: `${standIn ? "none" : flag("--fresh-lookups") ? "fresh" : `recorded (${cache!.stats.hits} replayed, ${cache!.stats.misses} new)`}${logs ? ` · log search: ${logs.sources.join(", ")}` : ""}`, sources, rounds: 3 },
  summary: summarise(outcomes), outcomes, ...(trial ? { trial } : {}),
};
const dir = join(config.evalDir, "reports"); mkdirSync(dir, { recursive: true });
const stamp = report.createdAt.replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
const base = join(dir, `eval-${stamp}`);
writeFileSync(`${base}.json`, JSON.stringify(report, null, 1));
const md = renderReport(report);
writeFileSync(`${base}.md`, md);
console.log(`\n${md}`);
console.log(`Report: ${relative(process.cwd(), base)}.md (and .json, which \`bun run review\` reads)`);

const maxMissed = value("--max-missed");
if (maxMissed !== undefined && report.summary.falseBenign > Number(maxMissed)) { console.error(`eval: ${report.summary.falseBenign} malicious case(s) called benign (allowed ${maxMissed}).`); process.exit(1); }
