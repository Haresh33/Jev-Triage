/**
 * Proposals: changes to memory that the reviewer AI suggested and a person has to approve.
 *
 *   memory/proposals/review-<time>.yaml   written by `bun run review`, one file per review
 *
 * `bun run memory approve <file> <id...>` appends the approved items to context.yaml, question-criteria.yaml
 * or lessons.md (with who approved them, when, and which case they came from) and marks them approved.
 * Existing comments in those files are kept: items are appended as text, and the folder is re-read afterwards;
 * if the result doesn't load, the files are put back as they were.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { z } from "zod";
import { buildMemory, entrySchema, readMemory, type Memory } from "./memory";

const base = {
  id: z.string().regex(/^p\d+$/),
  status: z.enum(["pending", "approved", "rejected"]),
  case: z.string(),
  label: z.enum(["malicious", "benign"]),
  agent_verdict: z.string().nullable(),
  diagnosis: z.string(),
  why: z.string(),
  decided: z.object({ by: z.string(), on: z.string(), reason: z.string().optional() }).optional(),
};
export const newEntrySchema = entrySchema.pick({ id: true, kind: true, match: true, note: true, expires: true });
export const newCriteriaSchema = z.object({ question_id: z.string().regex(/^[a-z0-9_]+$/), yes: z.string().min(5).max(400), no: z.string().min(5).max(400) });
export const proposalSchema = z.discriminatedUnion("type", [
  z.object({ ...base, type: z.literal("memory_entry"), entry: newEntrySchema }),
  z.object({ ...base, type: z.literal("question_criteria"), criteria: newCriteriaSchema }),
  z.object({ ...base, type: z.literal("lesson"), lesson: z.string().min(5).max(2000) }),
  z.object({ ...base, type: z.literal("engine_suggestion"), suggestion: z.string().min(5).max(2000) }),
]);
export type Proposal = z.infer<typeof proposalSchema>;
export const proposalFileSchema = z.object({
  created: z.string(),
  model: z.string(),
  report: z.string(),
  proposals: z.array(proposalSchema).nullish().transform((v) => v ?? []),
  /** Suggestions the automatic checks refused, kept so a person can see what was dropped and why. */
  set_aside: z.array(z.object({ case: z.string(), item: z.string(), reason: z.string() })).nullish().transform((v) => v ?? []),
});
export type ProposalFile = z.infer<typeof proposalFileSchema>;

const HEADER = `# Proposed changes to memory from the reviewer AI's review of cases the agent got wrong.
# Nothing here is used until a person approves it:
#   bun run memory approve <this file> p1 p3      (or "all")
#   bun run memory reject  <this file> p2 --reason "..."
# Read each one first. The AI saw the alert text, which an attacker can control.
`;

export function readProposalFile(path: string): ProposalFile {
  const parsed = proposalFileSchema.safeParse(Bun.YAML.parse(readFileSync(path, "utf8")) ?? {});
  if (!parsed.success) throw new Error(`${basename(path)} is not a valid proposal file: ${parsed.error.issues.slice(0, 2).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  return parsed.data;
}
export function writeProposalFile(path: string, data: ProposalFile): void {
  writeFileSync(path, `${HEADER}\n${Bun.YAML.stringify(data, null, 2).replace(/[ \t]+$/gm, "")}\n`);
}
export function proposalFiles(dir: string): string[] {
  return existsSync(dir) ? readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort().map((f) => join(dir, f)) : [];
}

/** Picks proposals by id ("all" = every pending one). Throws on an unknown id. */
export function select(file: ProposalFile, ids: string[]): Proposal[] {
  if (ids.length === 1 && ids[0] === "all") return file.proposals.filter((p) => p.status === "pending");
  return ids.map((id) => { const p = file.proposals.find((x) => x.id === id); if (!p) throw new Error(`No proposal "${id}" in this file.`); return p; });
}

/** Current memory plus the given proposals, without writing anything (used by `bun run eval --try`). */
export function memoryWithProposals(memoryDir: string, proposals: Proposal[], today = new Date()): Memory {
  const current = readMemory(memoryDir);
  const day = today.toISOString().slice(0, 10);
  const entries = [...current.entries, ...proposals.flatMap((p) => p.type === "memory_entry" ? [{ ...p.entry, added_by: "trial", added_on: day }] : [])];
  const criteria = { ...current.criteria };
  for (const p of proposals) if (p.type === "question_criteria") criteria[p.criteria.question_id] = { yes: p.criteria.yes, no: p.criteria.no, added_by: "trial", added_on: day };
  return buildMemory(entries, criteria, today);
}

// ---------------------------------------------------------------- appending to the memory files
const q = (s: string) => JSON.stringify(s); // a JSON string is a valid double-quoted YAML scalar
const said = (v: string | null) => (v === "needs_human" ? "needs analyst" : v ?? "nothing (error)");

function appendToList(text: string, key: string, block: string, emptyForm: RegExp): string {
  const header = new RegExp(`^${key}:[ \\t]*$`, "m");
  let t = text;
  if (emptyForm.test(t)) t = t.replace(emptyForm, `${key}:`);
  else if (!header.test(t)) t = `${t.replace(/\s*$/, "")}\n\n${key}:\n`;
  // Items are appended at the end of the file, so the key must be the last top-level key (true for the shipped files).
  const after = t.slice(t.search(header));
  if (/\n[A-Za-z_][\w-]*:/.test(after.slice(after.indexOf("\n")))) throw new Error(`"${key}:" is not the last section of the file; add this item by hand.`);
  return `${t.replace(/\s*$/, "")}\n${block}`;
}

export type Approval = { by: string; today: Date; fileName: string };

function entryBlock(p: Extract<Proposal, { type: "memory_entry" }>, a: Approval): string {
  const e = p.entry;
  return [
    `  - id: ${q(e.id)}`, `    kind: ${e.kind}`, `    match: [${e.match.map(q).join(", ")}]`, `    note: ${q(e.note)}`,
    `    added_by: ${q(a.by)}`, `    added_on: ${a.today.toISOString().slice(0, 10)}`,
    `    source: ${q(`${a.fileName} ${p.id}, case ${p.case}`.slice(0, 200))}`,
    ...(e.expires ? [`    expires: ${e.expires}`] : []), "",
  ].join("\n");
}
function criteriaBlock(p: Extract<Proposal, { type: "question_criteria" }>, a: Approval): string {
  const c = p.criteria;
  return [`  ${c.question_id}:`, `    yes: ${q(c.yes)}`, `    no: ${q(c.no)}`, `    added_by: ${q(a.by)}`, `    added_on: ${a.today.toISOString().slice(0, 10)}`, `    source: ${q(`${a.fileName} ${p.id}, case ${p.case}`.slice(0, 200))}`, ""].join("\n");
}
function lessonBlock(p: Extract<Proposal, { type: "lesson" | "engine_suggestion" }>, a: Approval): string {
  const body = p.type === "lesson" ? p.lesson : `For developers: ${p.suggestion}`;
  return `\n## ${a.today.toISOString().slice(0, 10)} · ${p.case}\n\nRight answer ${p.label}; the agent said ${said(p.agent_verdict)}. ${p.diagnosis}\n\n${body}\n\n_Approved by ${a.by} from ${a.fileName} ${p.id}._\n`;
}

/**
 * Applies approved proposals to the memory folder and marks them approved in the proposal file.
 * All-or-nothing: if any item can't be applied, or the folder doesn't load afterwards, nothing is changed.
 */
export function approveProposals(memoryDir: string, proposalPath: string, ids: string[], by: string, today = new Date()): string[] {
  const file = readProposalFile(proposalPath);
  const chosen = select(file, ids);
  if (!chosen.length) return ["Nothing pending to approve."];
  for (const p of chosen) if (p.status !== "pending") throw new Error(`${p.id} is already ${p.status}.`);
  const paths = { context: join(memoryDir, "context.yaml"), criteria: join(memoryDir, "question-criteria.yaml"), lessons: join(memoryDir, "lessons.md") };
  const read = (f: string) => (existsSync(f) ? readFileSync(f, "utf8") : "");
  const original = { context: read(paths.context), criteria: read(paths.criteria), lessons: read(paths.lessons) };
  const next = { ...original };
  const current = readMemory(memoryDir);
  const a: Approval = { by, today, fileName: basename(proposalPath) };
  const messages: string[] = [];
  for (const p of chosen) {
    if (p.type === "memory_entry") {
      if (current.entries.some((e) => e.id === p.entry.id) || next.context.includes(`id: ${q(p.entry.id)}`)) throw new Error(`${p.id}: memory already has an entry "${p.entry.id}". Edit context.yaml by hand, then reject this proposal.`);
      next.context = appendToList(next.context, "entries", entryBlock(p, a), /^entries:[ \t]*\[\][ \t]*$/m);
      messages.push(`${p.id}: added ${p.entry.kind} context "${p.entry.id}" to context.yaml`);
    } else if (p.type === "question_criteria") {
      if (current.criteria[p.criteria.question_id] || new RegExp(`^  ${p.criteria.question_id}:`, "m").test(next.criteria)) throw new Error(`${p.id}: "${p.criteria.question_id}" already has wording. Edit question-criteria.yaml by hand, then reject this proposal.`);
      next.criteria = appendToList(next.criteria, "criteria", criteriaBlock(p, a), /^criteria:[ \t]*\{\}[ \t]*$/m);
      messages.push(`${p.id}: added wording for "${p.criteria.question_id}" to question-criteria.yaml`);
    } else {
      next.lessons = `${(next.lessons || "# Lessons\n").replace(/\s*$/, "")}\n${lessonBlock(p, a)}`;
      messages.push(`${p.id}: added a ${p.type === "lesson" ? "lesson" : "developer note"} to lessons.md`);
    }
  }
  const write = (v: typeof original) => { for (const k of ["context", "criteria", "lessons"] as const) if (v[k] !== read(paths[k])) writeFileSync(paths[k], v[k]); };
  write(next);
  try {
    const after = readMemory(memoryDir);
    for (const p of chosen) {
      if (p.type === "memory_entry" && !after.entries.some((e) => e.id === p.entry.id) && !(p.entry.expires && p.entry.expires < today.toISOString().slice(0, 10))) throw new Error(`${p.id} did not load back`);
      if (p.type === "question_criteria" && !after.criteria[p.criteria.question_id]) throw new Error(`${p.id} did not load back`);
    }
  } catch (error) {
    write(original);
    throw new Error(`Memory would not load after the change, so nothing was changed: ${error instanceof Error ? error.message : error}`);
  }
  const on = today.toISOString().slice(0, 10);
  for (const p of chosen) { p.status = "approved"; p.decided = { by, on }; }
  writeProposalFile(proposalPath, file);
  return messages;
}

export function rejectProposals(proposalPath: string, ids: string[], by: string, reason: string | undefined, today = new Date()): string[] {
  const file = readProposalFile(proposalPath);
  const chosen = select(file, ids);
  for (const p of chosen) if (p.status !== "pending") throw new Error(`${p.id} is already ${p.status}.`);
  for (const p of chosen) { p.status = "rejected"; p.decided = { by, on: today.toISOString().slice(0, 10), ...(reason ? { reason } : {}) }; }
  writeProposalFile(proposalPath, file);
  return chosen.map((p) => `${p.id}: rejected`);
}

/** One line per proposal, for `bun run memory list` / `show`. */
export function describeProposal(p: Proposal): string {
  const what = p.type === "memory_entry" ? `context ${p.entry.kind} [${p.entry.match.join(", ")}]: "${p.entry.note}"${p.entry.expires ? ` (until ${p.entry.expires})` : ""}`
    : p.type === "question_criteria" ? `wording for ${p.criteria.question_id}: yes = "${p.criteria.yes}" / no = "${p.criteria.no}"`
    : p.type === "lesson" ? `lesson: ${p.lesson}` : `developer note: ${p.suggestion}`;
  return `${p.id} [${p.status}] ${what}\n     from ${p.case} (right answer ${p.label}, agent said ${said(p.agent_verdict)}).${p.why ? ` ${p.why}` : ""}`;
}
