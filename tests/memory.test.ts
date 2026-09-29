// Memory: matching rules, expiry, validation, what reaches Jev, and that it can never clear the guardrail.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildMemory, readMemory, type MemoryEntry } from "../server/src/memory";
import { investigate } from "../server/src/triage";
import { standInServices, stubPublicFetch, testCtx } from "./helpers";

const entry = (e: Partial<MemoryEntry> & Pick<MemoryEntry, "id" | "kind" | "match">): MemoryEntry => ({ note: `${e.id} note text`, added_by: "tester", added_on: "2026-09-01", ...e });
const facts = (f: Partial<Parameters<ReturnType<typeof buildMemory>["match"]>[0]> = {}) => ({ users: [], hosts: [], ips: [], domains: [], hashes: [], commands: [], title: "", ...f });

describe("matching", () => {
  const m = buildMemory([
    entry({ id: "acct", kind: "account", match: ["CORP\\svc_patching"] }),
    entry({ id: "host", kind: "host", match: ["SRV-APP-07"] }),
    entry({ id: "net", kind: "ip", match: ["10.20.9.0/24"] }),
    entry({ id: "dom", kind: "domain", match: ["corp.example"] }),
    entry({ id: "hash", kind: "hash", match: ["AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999"] }),
    entry({ id: "tool", kind: "tool", match: ["patch_agent.exe"] }),
    entry({ id: "det", kind: "detection", match: ["PsExec remote execution"] }),
  ], {}, new Date("2026-09-28"));
  const ids = (f: ReturnType<typeof facts>) => m.match(f).map((x) => x.id);

  test("accounts match with or without domain, and by UPN", () => {
    for (const u of ["CORP\\svc_patching", "svc_patching", "svc_patching@corp.example", "corp\\\\SVC_PATCHING"]) expect(ids(facts({ users: [u] }))).toEqual(["acct"]);
    expect(ids(facts({ users: ["svc_patching2"] }))).toEqual([]);
  });
  test("hosts match by short or full name", () => {
    expect(ids(facts({ hosts: ["srv-app-07.corp.example"] }))).toEqual(["host"]);
  });
  test("IP ranges, subdomains and hashes", () => {
    expect(ids(facts({ ips: ["10.20.9.10"] }))).toEqual(["net"]);
    expect(ids(facts({ ips: ["10.20.10.10"] }))).toEqual([]);
    expect(ids(facts({ domains: ["vpn.corp.example"] }))).toEqual(["dom"]);
    expect(ids(facts({ domains: ["corp.example.evil.top"] }))).toEqual([]);
    expect(ids(facts({ hashes: ["aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"] }))).toEqual(["hash"]);
  });
  test("tools match text in a command line; detections match the title", () => {
    expect(ids(facts({ commands: ["PsExec64.exe \\\\SRV-APP-08 -s C:\\Tools\\patch_agent.exe /install"] }))).toEqual(["tool"]);
    expect(ids(facts({ title: "EDR alert: PsExec remote execution" }))).toEqual(["det"]);
  });
  test("most specific kinds come first", () => {
    expect(ids(facts({ users: ["svc_patching"], hosts: ["SRV-APP-07"], title: "PsExec remote execution" }))).toEqual(["acct", "host", "det"]);
  });
  test("expired entries are ignored", () => {
    const old = buildMemory([entry({ id: "w", kind: "host", match: ["h1"], expires: "2026-09-27" })], {}, new Date("2026-09-28"));
    expect(old.match(facts({ hosts: ["h1"] }))).toEqual([]);
    expect(old.entries.length).toBe(0);
  });
});

describe("files", () => {
  const dir = mkdtempSync(join(tmpdir(), "jev-memory-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  test("valid YAML loads; question wording is looked up by base id", () => {
    writeFileSync(join(dir, "context.yaml"), `entries:\n  - id: a1\n    kind: account\n    match: ["CORP\\\\svc_backup"]\n    note: "svc_backup is the backup service account."\n    added_by: j.doe\n    added_on: 2026-09-28\n`);
    writeFileSync(join(dir, "question-criteria.yaml"), `criteria:\n  ioc_malicious:\n    yes: "Reputation or behaviour shows attacker use."\n    no: "Evidence shows a legitimate owner and purpose."\n    added_by: j.doe\n    added_on: 2026-09-28\n`);
    const m = readMemory(dir);
    expect(m.match(facts({ users: ["svc_backup"] }))[0]?.id).toBe("a1");
    expect(m.criteriaFor("ioc_malicious@url:http://x")?.yes).toContain("Reputation");
  });
  test("invalid or duplicate entries give a readable error", () => {
    writeFileSync(join(dir, "context.yaml"), `entries:\n  - id: a1\n    kind: printer\n    match: ["x"]\n    note: "bad kind"\n    added_by: me\n    added_on: 2026-09-28\n`);
    expect(() => readMemory(dir)).toThrow("context.yaml is invalid");
    const e = `  - id: dup\n    kind: host\n    match: ["h"]\n    note: "note text"\n    added_by: me\n    added_on: 2026-09-28\n`;
    writeFileSync(join(dir, "context.yaml"), `entries:\n${e}${e}`);
    expect(() => readMemory(dir)).toThrow('duplicate id "dup"');
  });
});

describe("in the investigation", () => {
  let restore: () => void;
  beforeAll(() => { restore = stubPublicFetch(); });
  afterAll(() => restore());
  const PSEXEC = "EDR alert: PsExec used for remote execution\nHost: SRV-APP-07\nUser: CORP\\svc_patching\nCommand: PsExec64.exe \\\\SRV-APP-08 -s C:\\Tools\\patch_agent.exe /install";
  const LSASS = JSON.stringify({ title: "Credential access", user: "CORP\\svc_patching", process: { cmdline: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\l.dmp full" } });
  const memory = buildMemory([entry({ id: "acct-svc-patching", kind: "account", match: ["CORP\\svc_patching"], note: "svc_patching is the patch automation account; it runs PsExec during the monthly patch window." })],
    { verdict_malicious: { yes: "An attacker is acting.", no: "Expected, authorised or test activity.", added_by: "t", added_on: "2026-09-28" } });

  function spy() {
    const states: string[] = []; const questions: string[] = [];
    const s = standInServices("reputation_only"); const orig = s.jevEvaluate;
    s.jevEvaluate = async (a) => { states.push(a.state); questions.push(a.questionsJson); return orig(a); };
    return { s, states, questions };
  }

  test("matching context is sent to Jev in its own field and shown on the ticket", async () => {
    const { s, states } = spy();
    const r = await investigate({ ...testCtx(s), memory }, PSEXEC, [], [], 1);
    expect(r.orgContext?.map((c) => c.id)).toEqual(["acct-svc-patching"]);
    const caseState = states.find((x) => x.includes("organisationContext"));
    expect(caseState).toContain("patch automation account");
    expect(caseState).toContain("not proof that this particular activity was authorised");
  });
  test("no match, or no memory, means no extra field", async () => {
    const { s, states } = spy();
    const r = await investigate({ ...testCtx(s), memory }, "certutil -hashfile C:\\iso\\win11.iso SHA256", [], [], 1);
    expect(r.orgContext).toBeUndefined();
    expect(states.some((x) => x.includes("organisationContext"))).toBe(false);
  });
  test("approved question wording is sent as the yes/no criteria", async () => {
    const { s, questions } = spy();
    await investigate({ ...testCtx(s), memory }, PSEXEC, [], [], 1);
    const verdict = questions.map((q) => JSON.parse(q)).find((q) => q.malicious);
    expect(verdict.malicious.criteria).toEqual({ true: "An attacker is acting.", false: "Expected, authorised or test activity." });
  });
  test("memory never clears strong attacker tradecraft on its own", async () => {
    const r = await investigate({ ...testCtx(standInServices("reputation_only")), memory }, LSASS, [], [], 2);
    expect(r.orgContext?.length).toBe(1);
    expect(r.verdict).toBe("needs_human");
    expect(r.guardrail.conflicts.join(" ")).toContain("attacker tradecraft");
  });
});
