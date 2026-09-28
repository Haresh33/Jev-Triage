/**
 * bun run memory: look after the memory folder and approve or reject proposals.
 *
 *   bun run memory                                   what's in memory, and pending proposals
 *   bun run memory show <file>                       every proposal in a file, with the AI's reasoning
 *   bun run memory approve <file> <id...|all> [--by <name>]
 *   bun run memory reject  <file> <id...|all> [--by <name>] [--reason "..."]
 *   bun run memory check                             validate the folder (exit code 1 if invalid; for CI)
 *
 * <file> can be a path or just the file name in memory/proposals. --by defaults to $USER.
 */

import { existsSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { loadConfig } from "../server/src/config";
import { readMemory } from "../server/src/memory";
import { approveProposals, describeProposal, proposalFiles, readProposalFile, rejectProposals } from "../server/src/proposals";

function die(message: string): never { console.error(`memory: ${message}`); process.exit(2); }
const argv = process.argv.slice(2);
const opt = (name: string) => { const i = argv.indexOf(name); if (i < 0) return undefined; const v = argv[i + 1]; if (!v || v.startsWith("--")) die(`${name} needs a value.`); argv.splice(i, 2); return v; };
const by = opt("--by") ?? process.env.USER ?? process.env.USERNAME ?? "unknown";
const reason = opt("--reason");
const [command = "list", fileArg, ...ids] = argv;
const { memoryDir } = loadConfig();
const proposalsDir = join(memoryDir, "proposals");
const rel = (p: string) => relative(process.cwd(), p) || p;
const fileFor = (arg: string | undefined) => {
  if (!arg) die("name a proposal file (see `bun run memory`).");
  const path = existsSync(arg) ? arg : join(proposalsDir, arg);
  if (!existsSync(path)) die(`no proposal file ${arg}.`);
  return path;
};
const run = (f: () => string[]) => { try { for (const line of f()) console.log(line); } catch (error) { die(error instanceof Error ? error.message : String(error)); } };

switch (command) {
  case "list": {
    try {
      const m = readMemory(memoryDir);
      console.log(`Memory (${rel(memoryDir)}): ${m.entries.length} context entries in use, ${Object.keys(m.criteria).length} question wording(s).`);
      for (const e of m.entries) console.log(`  ${e.id} [${e.kind}] ${e.match.join(", ")}${e.expires ? ` (until ${e.expires})` : ""}`);
    } catch (error) { console.log(`Memory is invalid: ${error instanceof Error ? error.message : error}`); }
    const files = proposalFiles(proposalsDir);
    let pending = 0;
    for (const f of files) {
      try {
        const p = readProposalFile(f).proposals.filter((x) => x.status === "pending");
        if (!p.length) continue;
        pending += p.length;
        console.log(`\n${basename(f)}: ${p.length} pending`);
        for (const x of p) console.log(`  ${describeProposal(x).split("\n")[0]}`);
      } catch (error) { console.log(`\n${basename(f)}: ${error instanceof Error ? error.message : error}`); }
    }
    console.log(pending ? `\nApprove with: bun run memory approve <file> <id...>` : "\nNo pending proposals.");
    break;
  }
  case "show": {
    const path = fileFor(fileArg);
    try {
      const f = readProposalFile(path);
      console.log(`${basename(path)} · from ${f.report} · ${f.model} · ${f.created.slice(0, 16).replace("T", " ")}\n`);
      for (const p of f.proposals) console.log(`${describeProposal(p)}\n     diagnosis: ${p.diagnosis}\n`);
      if (f.set_aside.length) { console.log("Set aside by the automatic checks:"); for (const s of f.set_aside) console.log(`  - ${s.item} (${s.case}): ${s.reason}`); }
    } catch (error) { die(error instanceof Error ? error.message : String(error)); }
    break;
  }
  case "approve": {
    const path = fileFor(fileArg);
    if (!ids.length) die("say which proposals to approve (ids like p1 p2, or all).");
    run(() => approveProposals(memoryDir, path, ids, by));
    console.log("The running app picks this up on its next case. Run `bun run eval` to confirm the score.");
    break;
  }
  case "reject": {
    const path = fileFor(fileArg);
    if (!ids.length) die("say which proposals to reject (ids like p1 p2, or all).");
    run(() => rejectProposals(path, ids, by, reason));
    break;
  }
  case "check": {
    try { const m = readMemory(memoryDir); console.log(`OK: ${m.entries.length} context entries in use, ${Object.keys(m.criteria).length} question wording(s).`); }
    catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); }
    break;
  }
  default: die(`unknown command "${command}". Use list, show, approve, reject or check.`);
}
