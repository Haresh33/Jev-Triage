// Outbound calls: the exact requests sent to Jev, VirusTotal, Shodan, AbuseIPDB and the reviewer AI (network mocked).
import { afterEach, describe, expect, test } from "bun:test";
import { loadConfig } from "../server/src/config";
import { createServices } from "../server/src/services";

type Captured = { url: string; init: RequestInit };
const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });

function mockFetch(respond: (url: string, init: RequestInit) => { status: number; body: unknown }): Captured[] {
  const calls: Captured[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = String(input); calls.push({ url, init });
    const { status, body } = respond(url, init);
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof fetch;
  return calls;
}
function configWith(env: Record<string, string>) {
  const saved = { ...process.env };
  for (const k of ["TYPESAFE_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_MODE", "CLAUDE_MODELS", "CLAUDE_AUDIT", "AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_BASE_URL", "AI_MODE", "AI_AUDIT", "JEV_MODEL", "TYPESAFE_BASE_URL"]) delete process.env[k];
  Object.assign(process.env, env);
  try { return loadConfig(); } finally { process.env = saved; }
}
const header = (init: RequestInit, name: string) => new Headers(init.headers).get(name);

describe("Jev (TypeSafe)", () => {
  test("sends state, model and typed questions to /v1/systemone with a Bearer key", async () => {
    const calls = mockFetch(() => ({ status: 200, body: { model: "jev-1.13.0", usage: {}, answers: { q0: { type: "noul", noul: 0.9 } } } }));
    const svc = createServices(configWith({ TYPESAFE_API_KEY: "ts-key", JEV_MODEL: "jev-1.13.0" }));
    const res = await svc.jevEvaluate({ state: JSON.stringify({ framing: "x", state: { alert: "a" } }), questionsJson: JSON.stringify({ q0: { type: "noul", instructions: "Is it bad?" } }) });
    expect(res.ok).toBe(true);
    expect(JSON.parse(res.dataJson ?? "{}").answers.q0.noul).toBe(0.9);
    expect(calls[0]?.url).toBe("https://api.typesafe.ai/v1/systemone");
    expect(header(calls[0]!.init, "authorization")).toBe("Bearer ts-key");
    const body = JSON.parse(String(calls[0]!.init.body));
    expect(body).toEqual({ state: { framing: "x", state: { alert: "a" } }, model: "jev-1.13.0", questions: { q0: { type: "noul", instructions: "Is it bad?" } } });
  });
  test("explains a missing or rejected key", async () => {
    expect((await createServices(configWith({})).jevEvaluate({ state: "{}", questionsJson: "{}" })).error).toContain("TYPESAFE_API_KEY");
    mockFetch(() => ({ status: 401, body: {} }));
    expect((await createServices(configWith({ TYPESAFE_API_KEY: "bad" })).jevEvaluate({ state: "{}", questionsJson: "{}" })).error).toContain("rejected");
  });
});

describe("VirusTotal", () => {
  test("uses x-apikey and returns { status, body }", async () => {
    const calls = mockFetch(() => ({ status: 200, body: { data: { id: "x" } } }));
    const res = await createServices(configWith({ VIRUSTOTAL_API_KEY: "vt-key" })).virustotalLookup({ path: "/files/abc", delayMs: 0 });
    expect(calls[0]?.url).toBe("https://www.virustotal.com/api/v3/files/abc");
    expect(header(calls[0]!.init, "x-apikey")).toBe("vt-key");
    expect(JSON.parse(res.dataJson ?? "{}")).toEqual({ status: 200, body: { data: { id: "x" } } });
  });
  test("refuses path traversal without calling out", async () => {
    const calls = mockFetch(() => ({ status: 200, body: {} }));
    const res = await createServices(configWith({ VIRUSTOTAL_API_KEY: "k" })).virustotalLookup({ path: "/../../etc", delayMs: 0 });
    expect(JSON.parse(res.dataJson ?? "{}").status).toBe(400);
    expect(calls.length).toBe(0);
  });
  test("reports a missing key so the engine records the lookup as unavailable", async () => {
    expect((await createServices(configWith({})).virustotalLookup({ path: "/files/a", delayMs: 0 })).ok).toBe(false);
  });
});

describe("Shodan and AbuseIPDB", () => {
  test("Shodan resolves a domain then compacts the host record", async () => {
    mockFetch((url) => url.includes("/dns/resolve") ? { status: 200, body: { "evil.top": "1.2.3.4" } } : { status: 200, body: { ip_str: "1.2.3.4", org: "Hoster", ports: [22, 443], vulns: { "CVE-2024-1": {} }, data: [{ port: 443, product: "nginx", version: "1.2" }] } });
    const res = await createServices(configWith({ SHODAN_API_KEY: "s" })).shodanEntity({ entity: "evil.top", kind: "domain" });
    expect(JSON.parse(res.dataJson ?? "{}")).toEqual({ entity: "evil.top", resolvedIp: "1.2.3.4", host: { ip: "1.2.3.4", org: "Hoster", hostnames: [], ports: [22, 443], vulns: ["CVE-2024-1"], services: [{ port: 443, product: "nginx", version: "1.2" }] } });
  });
  test("AbuseIPDB sends the Key header", async () => {
    const calls = mockFetch(() => ({ status: 200, body: { data: { abuseConfidenceScore: 100 } } }));
    await createServices(configWith({ ABUSEIPDB_API_KEY: "ab" })).abuseIpdbLookup({ ip: "1.2.3.4" });
    expect(calls[0]?.url).toContain("https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4");
    expect(header(calls[0]!.init, "key")).toBe("ab");
  });
});

describe("Claude (optional)", () => {
  test("forces the tool call and returns its input", async () => {
    const calls = mockFetch(() => ({ status: 200, body: { content: [{ type: "tool_use", name: "submit_tiebreak", input: { verdict: "needs_human", summary: "Not enough evidence to decide either way.", rationale: "unknown file" } }] } }));
    const res = await createServices(configWith({ ANTHROPIC_API_KEY: "sk" })).aiComplete({ mode: "tiebreak", stateJson: "{}" });
    expect(JSON.parse(res.dataJson ?? "{}").verdict).toBe("needs_human");
    const body = JSON.parse(String(calls[0]!.init.body));
    expect(body.tool_choice).toEqual({ type: "tool", name: "submit_tiebreak" });
    expect(header(calls[0]!.init, "x-api-key")).toBe("sk");
  });
  test("falls back to the next model only when the first is unknown", async () => {
    let n = 0;
    const calls = mockFetch(() => (++n === 1 ? { status: 404, body: {} } : { status: 200, body: { content: [{ type: "tool_use", name: "submit_questions", input: { questions: ["Is the parent Office?"] } }] } }));
    const res = await createServices(configWith({ ANTHROPIC_API_KEY: "sk" })).aiComplete({ mode: "questions", stateJson: "{}" });
    expect(res.ok).toBe(true);
    expect(calls.length).toBe(2);
  });
});

describe("reviewer AI: any OpenAI-compatible model", () => {
  const cfg = (extra: Record<string, string> = {}) => configWith({ AI_PROVIDER: "openai", AI_API_KEY: "ok-key", AI_MODEL: "gpt-test,fallback-model", ...extra });
  const toolReply = (args: unknown) => ({ status: 200, body: { choices: [{ message: { role: "assistant", tool_calls: [{ type: "function", function: { name: "submit_tiebreak", arguments: JSON.stringify(args) } }] } }] } });
  test("forces the function call, sends a Bearer key and reads the arguments", async () => {
    const calls = mockFetch(() => toolReply({ verdict: "benign", summary: "Routine patch push by the patch account.", rationale: "expected" }));
    const res = await createServices(cfg()).aiComplete({ mode: "audit", stateJson: "{}" });
    expect(JSON.parse(res.dataJson ?? "{}").verdict).toBe("benign");
    expect(calls[0]!.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(header(calls[0]!.init, "authorization")).toBe("Bearer ok-key");
    const body = JSON.parse(String(calls[0]!.init.body));
    expect(body.model).toBe("gpt-test");
    expect(body.tool_choice).toEqual({ type: "function", function: { name: "submit_audit" } });
    expect(body.tools[0].function.parameters.required).toContain("verdict");
  });
  test("plain JSON text is accepted from models without tool calling", async () => {
    mockFetch(() => ({ status: 200, body: { choices: [{ message: { content: "```json\n{\"questions\": [\"Is the parent Office?\"]}\n```" } }] } }));
    const res = await createServices(cfg()).aiComplete({ mode: "questions", stateJson: "{}" });
    expect(JSON.parse(res.dataJson!)).toEqual({ questions: ["Is the parent Office?"] });
  });
  test("retries with max_completion_tokens for models that need it, and falls back to the next model", async () => {
    let n = 0;
    const calls = mockFetch(() => { n += 1; return n === 1 ? { status: 400, body: { error: { message: "Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead." } } } : n === 2 ? { status: 404, body: {} } : toolReply({ verdict: "malicious", summary: "Encoded download cradle from a temp folder.", rationale: "tradecraft" }); });
    const res = await createServices(cfg()).aiComplete({ mode: "tiebreak", stateJson: "{}" });
    expect(res.ok).toBe(true);
    expect(JSON.parse(String(calls[1]!.init.body)).max_completion_tokens).toBeGreaterThan(0);
    expect(JSON.parse(String(calls[2]!.init.body)).model).toBe("fallback-model");
  });
  test("Azure uses an api-key header; a local server needs no key", async () => {
    let calls = mockFetch(() => toolReply({ verdict: "benign", summary: "Routine patch push by the patch account.", rationale: "expected" }));
    await createServices(cfg({ AI_BASE_URL: "https://acme.openai.azure.com/openai/v1" })).aiComplete({ mode: "audit", stateJson: "{}" });
    expect(header(calls[0]!.init, "api-key")).toBe("ok-key");
    expect(header(calls[0]!.init, "authorization")).toBeNull();
    const local = configWith({ AI_PROVIDER: "openai", AI_BASE_URL: "http://localhost:11434/v1", AI_MODEL: "llama3.1" });
    expect(local.ai.configured).toBe(true);
    calls = mockFetch(() => toolReply({ verdict: "benign", summary: "Routine patch push by the patch account.", rationale: "expected" }));
    await createServices(local).aiComplete({ mode: "audit", stateJson: "{}" });
    expect(calls[0]!.url).toBe("http://localhost:11434/v1/chat/completions");
    expect(header(calls[0]!.init, "authorization")).toBeNull();
  });
});

describe("configuration", () => {
  test("the reviewer AI is off without a key and cannot be forced on without one", () => {
    expect(configWith({}).ai.mode).toBe("off");
    expect(configWith({}).loops.audit.enabled).toBe(false);
    expect(configWith({ ANTHROPIC_API_KEY: "sk" }).ai.mode).toBe("second_opinion");
    expect(configWith({ ANTHROPIC_API_KEY: "sk" }).loops.audit.enabled).toBe(true);
    expect(configWith({ ANTHROPIC_API_KEY: "sk", CLAUDE_MODE: "off", CLAUDE_AUDIT: "off" }).ai.mode).toBe("off");
    expect(() => configWith({ AI_MODE: "tiebreak" })).toThrow("needs a reviewer AI");
    expect(() => configWith({ AI_AUDIT: "on" })).toThrow("needs a reviewer AI");
  });
  test("OpenAI-compatible providers need a model name and https", () => {
    expect(() => configWith({ AI_PROVIDER: "openai", AI_API_KEY: "k" })).toThrow("needs AI_MODEL");
    expect(() => configWith({ AI_PROVIDER: "openai", AI_API_KEY: "k", AI_MODEL: "m", AI_BASE_URL: "http://ai.example.com/v1" })).toThrow("must use https");
    expect(() => configWith({ AI_PROVIDER: "gemini" })).toThrow("AI_PROVIDER must be");
    expect(configWith({ AI_PROVIDER: "openai", OPENAI_API_KEY: "k", AI_MODEL: "gemini-2.5-flash", AI_BASE_URL: "https://generativelanguage.googleapis.com/v1beta/openai/" }).ai.baseUrl).toBe("https://generativelanguage.googleapis.com/v1beta/openai");
  });
});
