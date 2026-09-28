/**
 * bun run review: the reviewer AI reads the cases the agent got wrong in the latest evaluation report and proposes
 * fixes. It writes memory/proposals/review-<time>.yaml and changes nothing else: approve or reject the
 * proposals with `bun run memory`.
 *
 *   bun run review                         latest report in eval/reports
 *   bun run review eval/reports/x.json     a specific report
 *   --limit <n>                            review at most n cases (default 20; missed malicious cases first)
 *
 * Needs a reviewer AI (AI_API_KEY, any model). This is the only place the AI works on the cold loop; triage itself stays Jev-only.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { loadConfig } from "../server/src/config";
import type { Report } from "../server/src/evaluate";
import { readMemory } from "../server/src/memory";
import { describeProposal, writeProposalFile } from "../server/src/proposals";
import { reviewReport } from "../server/src/review";
import { aiTool, describeAi } from "../server/src/ai";

function die(message: string): never { console.error(`review: ${message}`); process.exit(2); }
const argv = process.argv.slice(2);
const limitAt = argv.indexOf("--limit");
const limit = limitAt >= 0 ? Number(argv[limitAt + 1]) : 20;
if (!Number.isInteger(limit) || limit < 1) die("--limit needs a whole number of 1 or more.");

const config = loadConfig();
if (!config.ai.configured) die("no reviewer AI is configured. Set AI_API_KEY (and AI_PROVIDER / AI_MODEL for a non-Anthropic model). Triage doesn't need it.");

const reportsDir = join(config.evalDir, "reports");
const given = argv.find((a, i) => !a.startsWith("--") && argv[i - 1] !== "--limit");
const reportPath = given ? resolve(given) : existsSync(reportsDir) ? readdirSync(reportsDir).filter((f) => /^eval-.*\.json$/.test(f)).sort().map((f) => join(reportsDir, f)).pop() : undefined;
if (!reportPath || !existsSync(reportPath)) die("no evaluation report found. Run `bun run eval` first.");
const report = JSON.parse(readFileSync(reportPath, "utf8")) as Report;
const memory = (() => { try { return readMemory(config.memoryDir); } catch (error) { return die(error instanceof Error ? error.message : String(error)); } })();

const misses = report.outcomes.filter((o) => o.outcome !== "correct" && o.outcome !== "error").length;
if (!misses) { console.log(`Nothing to review: every case in ${relative(process.cwd(), reportPath)} was right.`); process.exit(0); }
console.log(`Reviewing ${Math.min(misses, limit)} of ${misses} case(s) from ${relative(process.cwd(), reportPath)} with ${describeAi(config.ai)}…`);

const result = await reviewReport(report, relative(process.cwd(), reportPath), memory, async (prompt) => {
  const r = await aiTool(config.ai, prompt);
  return { ok: r.ok, value: r.ok && r.dataJson ? JSON.parse(r.dataJson) : undefined, error: r.error, model: r.model };
}, { limit, onCase: (ref, note) => console.log(`  ${ref.slice(0, 70)}: ${note.replace(/_/g, " ")}`) });

const { failures, ...file } = result;
for (const f of failures) console.warn(`  could not review ${f}`);
if (!file.proposals.length && !file.set_aside.length) { console.log("\nThe reviewer AI proposed no changes."); process.exit(failures.length ? 1 : 0); }

const dir = join(config.memoryDir, "proposals"); mkdirSync(dir, { recursive: true });
const out = join(dir, `review-${file.created.replace(/[-:]/g, "").replace("T", "-").slice(0, 15)}.yaml`);
writeProposalFile(out, file);
console.log(`\n${file.proposals.length} proposal(s):\n`);
for (const p of file.proposals) console.log(`  ${describeProposal(p).replace(/\n/g, "\n  ")}\n`);
if (file.set_aside.length) {
  console.log(`${file.set_aside.length} suggestion(s) set aside by the automatic checks:`);
  for (const s of file.set_aside) console.log(`  - ${s.item} (${s.case}): ${s.reason}`);
}
const rel = relative(process.cwd(), out);
console.log(`\nWritten to ${rel}. Nothing has changed yet. Next:
  bun run eval --try ${rel} p1 p2      see what the proposals would change
  bun run memory approve ${rel} p1     apply the ones you agree with
  bun run memory reject ${rel} p2 --reason "..."`);
