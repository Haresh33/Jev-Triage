/**
 * Jev Triage server: serves the UI, the JSON API (POST /api/<action>) and runs the background worker.
 *
 *   bun run start        production (binds to HOST:PORT, default 127.0.0.1:3000)
 *   bun run dev          restart on file changes
 */

import { timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import tailwind from "bun-plugin-tailwind";
import { and, inArray, lt } from "drizzle-orm";
import { Actions, JobHandlers, ingestAlert, setClaudeMode } from "./actions";
import { describeConfig, loadConfig, type Config } from "./config";
import { openDatabase } from "./db";
import { createJobQueue, startWorker, type Worker } from "./jobs";
import { setLoopSettings } from "./loops";
import { setLogSources, type LogSource } from "./logs";
import { memoryLoader, type Memory } from "./memory";
import type { ActionDef, Ctx, Services } from "./platform";
import * as schema from "./schema";
import { createServices } from "./services";

const CLIENT_HTML = resolve(import.meta.dir, "../../client/index.html");
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

/** The host name a request was addressed to, without the port ("[::1]:3000" -> "::1"). */
function requestHost(req: Request): string {
  const host = (req.headers.get("host") ?? "").trim().toLowerCase();
  if (host.startsWith("[")) return host.slice(1, host.indexOf("]"));
  return host.replace(/:\d+$/, "");
}

/**
 * DNS-rebinding protection. A hostile web page can point its own domain at 127.0.0.1 and then talk to this
 * server as if it were that site. Its requests still carry its own domain in the Host header, so only answer
 * requests addressed to this machine (localhost, 127.0.0.1, ::1) or to a name listed in ALLOWED_HOSTS.
 * With a login configured the password already stops this, so the check applies only when ALLOWED_HOSTS is set.
 */
function hostAllowed(req: Request, config: Config): boolean {
  const loginRequired = Boolean(config.auth.user && config.auth.password);
  if (loginRequired && config.allowedHosts.length === 0) return true;
  const host = requestHost(req);
  return LOOPBACK.has(host) || config.allowedHosts.includes(host);
}

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SECURITY_HEADERS, ...extra } });
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Returns the logged-in user, or null when a login is required and missing/wrong. */
function authenticate(req: Request, config: Config): string | null {
  const { user, password } = config.auth;
  if (!user || !password) return "local";
  const header = req.headers.get("authorization") ?? "";
  if (!header.startsWith("Basic ")) return null;
  const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  const sep = decoded.indexOf(":");
  if (sep < 0) return null;
  return safeEqual(decoded.slice(0, sep), user) && safeEqual(decoded.slice(sep + 1), password) ? user : null;
}
const UNAUTHORIZED = () => new Response("Login required.", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="Jev Triage", charset="UTF-8"', ...SECURITY_HEADERS } });

/** Bundles the React UI (TypeScript, CSS, Tailwind) in memory at startup. */
async function buildClient(): Promise<Map<string, { body: Blob; type: string }>> {
  const result = await Bun.build({ entrypoints: [CLIENT_HTML], plugins: [tailwind], minify: process.env.NODE_ENV === "production", publicPath: "/", target: "browser" });
  if (!result.success) throw new Error(`UI build failed:\n${result.logs.map((l) => String(l)).join("\n")}`);
  const files = new Map<string, { body: Blob; type: string }>();
  for (const out of result.outputs) {
    const path = `/${out.path.replace(/^\.\//, "")}`;
    files.set(path === "/index.html" ? "/" : path, { body: out, type: out.type });
  }
  return files;
}

export type App = { server: ReturnType<typeof Bun.serve>; worker: Worker; stop(): Promise<void> };

export async function startApp(config: Config, overrides: { services?: Services; log?: (msg: string) => void; pollMs?: number; getMemory?: () => Memory; logSources?: LogSource[] } = {}): Promise<App> {
  const log = overrides.log ?? ((m: string) => console.log(m));
  if (!LOOPBACK.has(config.host) && !(config.auth.user && config.auth.password) && !config.auth.allowNoAuth) {
    throw new Error(`HOST=${config.host} makes the app reachable from other machines. Set AUTH_USER and AUTH_PASSWORD (or ALLOW_NO_AUTH=true if a proxy in front of it handles login).`);
  }
  setClaudeMode(config.ai.mode);
  setLoopSettings(config.loops);
  setLogSources(overrides.logSources ?? config.logs.build(), config.logs.search);
  const { db, sqlite } = openDatabase(config.databasePath);
  const services = overrides.services ?? createServices(config);
  const queue = createJobQueue(db);
  const getMemory = overrides.getMemory ?? memoryLoader(config.memoryDir, log);
  const handlers = {
    processCase: (ctx: Ctx, args: unknown) => JobHandlers.processCase.handler(ctx, JobHandlers.processCase.request.parse(args)),
    processClaudeSecondOpinion: (ctx: Ctx, args: unknown) => JobHandlers.processClaudeSecondOpinion.handler(ctx, JobHandlers.processClaudeSecondOpinion.request.parse(args)),
    warmCase: (ctx: Ctx, args: unknown) => JobHandlers.warmCase.handler(ctx, JobHandlers.warmCase.request.parse(args)),
    claudeAudit: (ctx: Ctx, args: unknown) => JobHandlers.claudeAudit.handler(ctx, JobHandlers.claudeAudit.request.parse(args)),
  };
  const ui = await buildClient();
  const actions = Actions as Record<string, ActionDef>;

  // Optional retention: delete cases (and their notes) older than RETENTION_DAYS, and finished jobs after 7 days.
  const retention = setInterval(() => {
    const now = Date.now();
    if (config.retentionDays > 0) {
      const cutoff = new Date(now - config.retentionDays * 86_400_000);
      const old = db.select({ id: schema.triageCases.id }).from(schema.triageCases).where(lt(schema.triageCases.createdAt, cutoff)).all().map((r) => r.id);
      if (old.length) {
        db.delete(schema.analystNotes).where(inArray(schema.analystNotes.caseId, old)).run();
        db.delete(schema.triageCases).where(inArray(schema.triageCases.id, old)).run();
        log(`[retention] deleted ${old.length} case(s) older than ${config.retentionDays} days`);
      }
    }
    db.delete(schema.jobs).where(and(inArray(schema.jobs.status, ["done", "failed"]), lt(schema.jobs.updatedAt, new Date(now - 7 * 86_400_000)))).run();
  }, 60 * 60_000);

  const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    maxRequestBodySize: 2 * 1024 * 1024,
    async fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === "/healthz") return json({ ok: true });

      if (!hostAllowed(req, config)) {
        log(`[security] refused a request addressed to "${requestHost(req).slice(0, 100)}" (not an allowed host)`);
        return json({ error: "This host name is not allowed. If you reach the app by another name, add it to ALLOWED_HOSTS." }, 403);
      }

      // Alerts pushed in by a SIEM / XDR / EDR: its own token, so the sender never holds the UI login.
      if (url.pathname === "/ingest/alert") {
        if (!config.ingestToken) return json({ error: "Not found." }, 404);
        if (req.method !== "POST") return json({ error: "Use POST." }, 405, { Allow: "POST" });
        const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
        if (!token || !safeEqual(token, config.ingestToken)) return json({ error: "Invalid or missing ingest token." }, 401);
        const text = await req.text();
        let alert = text;
        try { const parsed: unknown = JSON.parse(text); alert = JSON.stringify(parsed, null, 2); } catch { /* plain-text alert */ }
        const source = (req.headers.get("x-alert-source") ?? "webhook").replace(/[^\w .:@/-]/g, "").slice(0, 60) || "webhook";
        const key = (req.headers.get("idempotency-key") ?? "").slice(0, 200) || `sha256:${new Bun.CryptoHasher("sha256").update(text).digest("hex")}`;
        const owner = config.auth.user ?? "local";
        const ctx: Ctx = { db: () => db, viewer: { id: owner }, services, jobs: queue, memory: getMemory() };
        const r = await ingestAlert(ctx, alert, source, key);
        if (!r.ok) return json({ error: r.error ?? "The alert could not be accepted." }, 400);
        log(`[ingest] ${r.duplicate ? "resend of" : "new"} case ${r.id} from ${source}`);
        return json({ ok: true, id: r.id, duplicate: Boolean(r.duplicate) }, r.duplicate ? 200 : 202);
      }

      const user = authenticate(req, config);
      if (!user) return UNAUTHORIZED();

      if (url.pathname.startsWith("/api/")) {
        if (req.method !== "POST") return json({ error: "Use POST." }, 405, { Allow: "POST" });
        // Cross-site protection: only JSON from this origin (a form on another site cannot send application/json).
        if (!(req.headers.get("content-type") ?? "").includes("application/json")) return json({ error: "Send JSON." }, 415);
        const origin = req.headers.get("origin");
        if (origin && origin !== url.origin) return json({ error: "Cross-origin request refused." }, 403);
        const action = actions[url.pathname.slice(5)];
        if (!action) return json({ error: "Unknown action." }, 404);
        let body: unknown;
        try { body = await req.json(); } catch { return json({ error: "Invalid JSON." }, 400); }
        const parsed = action.request.safeParse(body);
        if (!parsed.success) return json({ error: `Invalid request: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "body"} ${i.message}`).join("; ")}` }, 400);
        try {
          const ctx: Ctx = { db: () => db, viewer: { id: user }, services, jobs: queue, memory: getMemory() };
          return json(await action.handler(ctx, parsed.data));
        } catch (error) {
          log(`[api] ${url.pathname} failed: ${error instanceof Error ? error.message : String(error)}`);
          return json({ error: "The server could not complete this request." }, 500);
        }
      }

      if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed.", { status: 405, headers: SECURITY_HEADERS });
      const file = ui.get(url.pathname) ?? ui.get("/");
      if (!file) return new Response("Not found.", { status: 404, headers: SECURITY_HEADERS });
      const cache = url.pathname === "/" || !ui.has(url.pathname) ? "no-store" : "public, max-age=31536000, immutable";
      return new Response(file.body, { headers: { "Content-Type": file.type, "Cache-Control": cache, ...SECURITY_HEADERS } });
    },
  });

  // Start background work only once the port is ours, so a failed start leaves nothing running.
  const worker = startWorker({ db, services, queue, handlers, concurrency: config.workerConcurrency, pollMs: overrides.pollMs, log, getMemory });

  return {
    server, worker,
    async stop() { clearInterval(retention); server.stop(true); await worker.stop(); sqlite.close(); },
  };
}

if (import.meta.main) {
  let config: Config;
  try { config = loadConfig(); } catch (error) { console.error(`Configuration error: ${error instanceof Error ? error.message : String(error)}`); process.exit(1); }
  const app = await startApp(config);
  console.log(`Jev Triage is running at http://${config.host === "0.0.0.0" ? "localhost" : config.host}:${config.port}`);
  for (const line of describeConfig(config)) console.log(`  ${line}`);
  const memory = memoryLoader(config.memoryDir)();
  console.log(`  Memory: ${memory.entries.length} context entr${memory.entries.length === 1 ? "y" : "ies"}, ${Object.keys(memory.criteria).length} question wording(s) (${config.memoryDir})`);
  if (!config.jev.apiKey) console.warn("  Warning: TYPESAFE_API_KEY is not set, so investigations will fail until it is.");
  const shutdown = async () => { console.log("Stopping…"); await app.stop(); process.exit(0); };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
