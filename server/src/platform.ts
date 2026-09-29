/**
 * The only place that knows how the app runs. Actions and the engine receive a `Ctx` with:
 *   - db()      the Drizzle database (SQLite file)
 *   - viewer    who is using the app (the login user, or "local")
 *   - services  outbound calls: Jev, VirusTotal, Shodan, AbuseIPDB, Claude, upload storage
 *   - jobs      the background job queue
 * Tests build a Ctx with stand-in services; the server builds one with the real ones.
 */

import type { BunSQLiteDatabase } from "drizzle-orm/bun-sqlite";
import { z } from "zod";
import type { LogSearcher } from "./logs";
import type { Entity, RelatedCase } from "./loops";
import type { Memory } from "./memory";
import type * as schema from "./schema";

export { z };

/** Result of one outbound provider call. `dataJson` is the provider's JSON (or a compact envelope). */
export type ProviderResponse = { ok: boolean; dataJson: string | null; error: string | null; durationMs: number };
export type ExtractResult = { ok: boolean; text: string; manifestJson: string; kind: string; truncated: boolean; error: string | null };

export type Services = {
  jevEvaluate(args: { state: string; questionsJson: string }): Promise<ProviderResponse>;
  shodanEntity(args: { entity: string; kind: "ip" | "domain" }): Promise<ProviderResponse>;
  virustotalLookup(args: { path: string; delayMs: number }): Promise<ProviderResponse>;
  abuseIpdbLookup(args: { ip: string }): Promise<ProviderResponse>;
  aiComplete(args: { mode: "questions" | "tiebreak" | "audit"; stateJson: string }): Promise<ProviderResponse>;
  writeAlertUploadChunk(args: { uploadId: string; chunkBase64: string; reset: boolean }): Promise<{ ok: boolean; error: string | null }>;
  discardAlertUpload(args: { uploadId: string }): Promise<{ ok: boolean }>;
  extractAlertText(args: { uploadId: string; fileName: string; password?: string }): Promise<ExtractResult>;
};

export type JobKind = "processCase" | "processClaudeSecondOpinion" | "warmCase" | "claudeAudit";
export type JobQueue = { enqueue(kind: JobKind, args: Record<string, unknown>, viewerId: string): Promise<{ ok: boolean; id?: string; error?: string }> };

export type Db = BunSQLiteDatabase<typeof schema>;
export type Viewer = { id: string };
/**
 * `memory` is the reviewed organisation context (cold loop; absent = none).
 * `logs` searches the organisation's EDR / SIEM / XDR around the alert (absent = no log source configured).
 * `related` finds recent cases that share a host, account or indicator (warm context for the hot loop; absent = none).
 */
export type Ctx = { db(): Db; viewer: Viewer; services: Services; jobs: JobQueue; memory?: Memory; related?: (entities: Entity[]) => Promise<RelatedCase[]>; logs?: LogSearcher };

export type ActionDef<Req extends z.ZodType = z.ZodType, Res extends z.ZodType = z.ZodType> = {
  request: Req;
  response: Res;
  handler(ctx: Ctx, args: z.infer<Req>): Promise<z.infer<Res>>;
};
export type ActionsModule = Record<string, ActionDef>;

/** Declares one server action: its request schema, response schema and handler. */
export function defineAction<Req extends z.ZodType, Res extends z.ZodType>(def: ActionDef<Req, Res>): ActionDef<Req, Res> {
  return def;
}
