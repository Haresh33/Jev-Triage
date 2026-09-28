import { defineAction, z, type ActionsModule, type Ctx } from "./platform";
import type { ClaudeMode } from "./config";
import { and, asc, desc, eq, gte } from "drizzle-orm";
import * as schema from "./schema";
import { getClaudeTiebreak, writeClaudeQuestions } from "./claude";
import { logSearcher } from "./logs";
import { auditReason, auditsInLastDay, flagClaudeDisagrees, flagClosureRelatedTo, flagRelatedClosures, indexCaseEntities, loopSettings, openFlagCounts, relatedFinder, resolveFlagsOnDecision } from "./loops";
import { applyClaudeTiebreak, askCaseQuestion, attachSecondOpinion, finaliseJevOnly, investigate, type TriageResult } from "./triage";

/**
 * How Claude is used (set with the CLAUDE_MODE environment variable). Jev answers every question in all modes.
 *  - "off": Jev only. No language model is called. Unresolved cases go straight to "needs analyst".
 *  - "second_opinion" (default when ANTHROPIC_API_KEY is set): Jev's verdict is saved immediately. For unresolved
 *    cases, Claude then writes a few extra questions in the background (Jev answers them, and may still settle the
 *    case), and adds an advisory second opinion to the ticket. Claude never changes the verdict.
 *  - "tiebreak": Claude's tiebreak can set the verdict (the guardrail still applies). If Claude is unavailable the
 *    case finishes as "needs analyst".
 */
let CLAUDE_MODE: ClaudeMode = "off";
export function setClaudeMode(mode: ClaudeMode): void { CLAUDE_MODE = mode; }

const MAX_ALERT_CHARS = 120_000;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_CHUNK_BASE64 = 800_000;
const caseStatusSchema = z.enum(["queued", "running", "completed", "needs_questions", "needs_summary", "error"]);
const verdictSchema = z.enum(["malicious", "benign", "needs_human"]);
const caseSummarySchema = z.object({
  id: z.string(), title: z.string(), sourceName: z.string().nullable(), status: caseStatusSchema,
  stage: z.string(), verdict: verdictSchema.nullable(), maliciousProbability: z.number().nullable(),
  analystSummary: z.string().nullable(), verdictOverride: verdictSchema.nullable(), error: z.string().nullable(),
  runVersion: z.number().int(), analystSummaryRunVersion: z.number().int().nullable(),
  createdAt: z.string(), updatedAt: z.string(),
  /** Warm-loop flags still waiting for an analyst ("Recheck"). */
  openFlags: z.number().int(),
});
const flagSchema = z.object({ id: z.string(), kind: z.enum(["related_confirmed_malicious", "related_agent_malicious", "claude_disagrees"]), detail: z.string(), relatedCaseId: z.string().nullable(), createdAt: z.string(), resolvedAt: z.string().nullable(), resolvedBy: z.string().nullable() });
const caseDetailSchema = caseSummarySchema.extend({ inputText: z.string(), resultJson: z.string().nullable() });
const dispositionSchema = z.object({ label: z.enum(["malicious", "benign"]), reason: z.string().nullable(), decidedBy: z.string(), jevVerdict: verdictSchema.nullable(), decidedAt: z.string() });
const okResponse = z.object({ ok: z.boolean(), id: z.string().optional(), status: caseStatusSchema.optional(), error: z.string().optional(), flagged: z.number().int().optional() });

type CaseStatus = z.infer<typeof caseStatusSchema>;
function viewerId(ctx: Ctx): string { return ctx.viewer.id; }
function parseResult(value: string | null): TriageResult | null { if (!value) return null; try { return JSON.parse(value) as TriageResult; } catch { return null; } }
function probabilityInt(value: number | null): number | null { return value === null ? null : Math.round(value * 1000); }
function probabilityFloat(value: number | null): number | null { return value === null ? null : value / 1000; }
function rowSummary(row: typeof schema.triageCases.$inferSelect, openFlags = 0): z.infer<typeof caseSummarySchema> {
  return { openFlags, id: row.id, title: row.title, sourceName: row.sourceName, status: row.status, stage: row.stage, verdict: row.verdict, maliciousProbability: probabilityFloat(row.maliciousProbability), analystSummary: row.analystSummary, verdictOverride: row.verdictOverride, error: row.error, runVersion: row.runVersion, analystSummaryRunVersion: row.analystSummaryRunVersion, createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString() };
}
function rowDetail(row: typeof schema.triageCases.$inferSelect, openFlags = 0): z.infer<typeof caseDetailSchema> { return { ...rowSummary(row, openFlags), inputText: row.inputText, resultJson: row.resultJson }; }
function titleFrom(text: string, fileName?: string): string {
  if (fileName) return fileName.split(/[\\/]/).pop()?.slice(0, 160) || "Uploaded alert";
  try { const parsed: unknown = JSON.parse(text); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) { const obj = parsed as Record<string, unknown>; for (const key of ["title", "name", "rule_name", "alert_name", "description", "summary"]) { const value = obj[key]; if (typeof value === "string" && value.trim()) return value.trim().slice(0, 160); } } } catch { /* text input */ }
  return text.split(/\r?\n/).find((line) => line.trim())?.trim().slice(0, 160) ?? "Security alert";
}
async function createCase(ctx: Ctx, text: string, sourceName?: string): Promise<string> { const id = crypto.randomUUID(); const now = new Date(); await ctx.db().insert(schema.triageCases).values({ id, viewerId: viewerId(ctx), title: titleFrom(text, sourceName), inputText: text, sourceName: sourceName ?? null, status: "queued", stage: "ready", createdAt: now, updatedAt: now }); return id; }
async function loadCase(ctx: Ctx, id: string, ownerScoped = true): Promise<typeof schema.triageCases.$inferSelect | null> { const db = ctx.db(); const where = ownerScoped ? and(eq(schema.triageCases.id, id), eq(schema.triageCases.viewerId, viewerId(ctx))) : eq(schema.triageCases.id, id); const rows = await db.select().from(schema.triageCases).where(where).limit(1); return rows[0] ?? null; }
async function loadNotes(ctx: Ctx, id: string): Promise<string[]> { const rows = await ctx.db().select().from(schema.analystNotes).where(eq(schema.analystNotes.caseId, id)).orderBy(asc(schema.analystNotes.createdAt)); return rows.filter((x) => x.kind === "note").map((x) => x.text); }
async function saveResult(ctx: Ctx, id: string, runVersion: number, result: TriageResult, stage?: string): Promise<void> { const status: CaseStatus = result.status; const summary = result.analystSummary?.trim() || null; await ctx.db().update(schema.triageCases).set({ status, stage: stage ?? (status === "completed" ? "ticket_ready" : status), verdict: result.verdict, maliciousProbability: probabilityInt(result.pMalicious), resultJson: JSON.stringify(result), analystSummary: summary, analystSummaryRunVersion: summary ? runVersion : null, verdictOverride: null, error: null, updatedAt: new Date() }).where(and(eq(schema.triageCases.id, id), eq(schema.triageCases.runVersion, runVersion))); if (result.entities && (await stillCurrent(ctx, id, runVersion))) indexCaseEntities(ctx.db(), id, result.entities); }
async function stillCurrent(ctx: Ctx, id: string, runVersion: number): Promise<boolean> { const current = await loadCase(ctx, id, false); return !!current && current.runVersion === runVersion; }
async function markError(ctx: Ctx, id: string, message: string): Promise<void> { await ctx.db().update(schema.triageCases).set({ status: "error", stage: "error", error: message.slice(0, 500), updatedAt: new Date() }).where(eq(schema.triageCases.id, id)); }
async function rerunWithContext(ctx: Ctx, row: typeof schema.triageCases.$inferSelect, notes: string[], questions: string[], origin: "analyst" | "claude" = "analyst"): Promise<TriageResult> { const prior = parseResult(row.resultJson); return investigate(ctx, row.inputText, notes, questions, 2, prior, true, origin); }

type InvestigationMode = "initial" | "note" | "analyst_questions";
async function queueInvestigation(ctx: Ctx, id: string, runVersion: number, mode: InvestigationMode, questions: string[] = []): Promise<{ ok: boolean; error?: string }> {
  const queued = await ctx.jobs.enqueue("processCase", { caseId: id, runVersion, mode, questions }, viewerId(ctx));
  if (!queued.ok) return { ok: false, error: "The investigation could not be queued. Try running it again." };
  await ctx.db().update(schema.triageCases).set({ analystTaskId: queued.id ?? null, updatedAt: new Date() }).where(and(eq(schema.triageCases.id, id), eq(schema.triageCases.runVersion, runVersion)));
  return { ok: true };
}

/** Starts the warm loop for a saved verdict. It runs in the background and never changes the verdict. */
async function queueWarm(ctx: Ctx, id: string, runVersion: number): Promise<void> {
  const queued = await ctx.jobs.enqueue("warmCase", { caseId: id, runVersion }, viewerId(ctx));
  if (!queued.ok) console.error(`[jev-triage] warm loop could not be queued for case ${id}: ${queued.error ?? "unknown error"}`);
}
/** The hot loop's context: Jev, related recent cases (milliseconds, from the database) and the log sources. */
function hotCtx(ctx: Ctx, row: typeof schema.triageCases.$inferSelect): Ctx { return { ...ctx, related: relatedFinder(ctx.db(), row.viewerId, row.id), logs: logSearcher() }; }

async function queueClaudeSecondOpinion(ctx: Ctx, id: string, runVersion: number): Promise<{ ok: boolean; error?: string }> {
  const queued = await ctx.jobs.enqueue("processClaudeSecondOpinion", { caseId: id, runVersion }, viewerId(ctx));
  if (!queued.ok) return { ok: false, error: "Claude second opinion could not be queued." };
  await ctx.db().update(schema.triageCases).set({ analystTaskId: queued.id ?? null, updatedAt: new Date() }).where(and(eq(schema.triageCases.id, id), eq(schema.triageCases.runVersion, runVersion)));
  return { ok: true };
}

/**
 * An alert pushed in by a SIEM, XDR or EDR (the webhook in server.ts): the case opens and triage starts at once, so
 * the agent works the alert the moment it arrives. A resend with the same key within 7 days returns the existing case.
 */
export async function ingestAlert(ctx: Ctx, text: string, source: string, key: string): Promise<{ ok: boolean; id?: string; duplicate?: boolean; error?: string }> {
  const alert = text.trim();
  if (!alert) return { ok: false, error: "The alert is empty." };
  if (alert.length > MAX_ALERT_CHARS) return { ok: false, error: `The alert is larger than ${MAX_ALERT_CHARS} characters.` };
  const existing = ctx.db().select({ id: schema.triageCases.id }).from(schema.triageCases).where(and(eq(schema.triageCases.viewerId, viewerId(ctx)), eq(schema.triageCases.sourceKey, key), gte(schema.triageCases.createdAt, new Date(Date.now() - 7 * 86_400_000)))).get();
  if (existing) return { ok: true, id: existing.id, duplicate: true };
  const id = await createCase(ctx, alert);
  const runVersion = 1;
  await ctx.db().update(schema.triageCases).set({ sourceName: `webhook: ${source}`.slice(0, 160), sourceKey: key, status: "running", stage: "adaptive_investigation", runVersion, updatedAt: new Date() }).where(eq(schema.triageCases.id, id));
  const queued = await queueInvestigation(ctx, id, runVersion, "initial");
  if (!queued.ok) { await markError(ctx, id, queued.error ?? "The investigation could not be queued."); return { ok: false, id, error: queued.error }; }
  return { ok: true, id };
}

export const Actions = {
  listCases: defineAction({
    request: z.object({ limit: z.number().int().positive().max(50).default(30) }), response: z.object({ cases: z.array(caseSummarySchema) }),
    async handler(ctx, args) { const rows = await ctx.db().select().from(schema.triageCases).where(eq(schema.triageCases.viewerId, viewerId(ctx))).orderBy(desc(schema.triageCases.createdAt)).limit(args.limit); const flags = openFlagCounts(ctx.db(), rows.map((r) => r.id)); return { cases: rows.map((r) => rowSummary(r, flags.get(r.id) ?? 0)) }; },
  }),
  getCase: defineAction({
    request: z.object({ id: z.string().min(1) }), response: z.object({ case: caseDetailSchema.nullable(), notes: z.array(z.object({ id: z.string(), kind: z.enum(["note", "question"]), text: z.string(), createdAt: z.string() })), disposition: dispositionSchema.nullable(), flags: z.array(flagSchema) }),
    async handler(ctx, args) {
      const row = await loadCase(ctx, args.id); if (!row) return { case: null, notes: [], disposition: null, flags: [] };
      const flags = ctx.db().select().from(schema.caseFlags).where(eq(schema.caseFlags.caseId, row.id)).orderBy(desc(schema.caseFlags.createdAt)).all();
      const notes = await ctx.db().select().from(schema.analystNotes).where(and(eq(schema.analystNotes.caseId, args.id), eq(schema.analystNotes.viewerId, viewerId(ctx)))).orderBy(asc(schema.analystNotes.createdAt));
      const d = ctx.db().select().from(schema.dispositions).where(eq(schema.dispositions.caseId, row.id)).get();
      return { flags: flags.map((f) => ({ id: f.id, kind: f.kind, detail: f.detail, relatedCaseId: f.relatedCaseId, createdAt: f.createdAt.toISOString(), resolvedAt: f.resolvedAt?.toISOString() ?? null, resolvedBy: f.resolvedBy })), case: rowDetail(row, flags.filter((f) => !f.resolvedAt).length), notes: notes.map((n) => ({ id: n.id, kind: n.kind, text: n.text, createdAt: n.createdAt.toISOString() })), disposition: d ? { label: d.label, reason: d.reason, decidedBy: d.decidedBy, jevVerdict: d.jevVerdict, decidedAt: d.decidedAt.toISOString() } : null };
    },
  }),
  createCase: defineAction({
    request: z.object({ alertText: z.string().min(1).max(MAX_ALERT_CHARS) }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> { const text = args.alertText.trim(); if (!text) return { ok: false, error: "Paste an alert before starting triage." }; return { ok: true, id: await createCase(ctx, text), status: "queued" }; },
  }),
  beginFileUpload: defineAction({
    request: z.object({ fileName: z.string().min(1).max(240), fileSize: z.number().int().positive().max(MAX_FILE_BYTES) }), response: z.object({ ok: z.boolean(), uploadId: z.string().optional(), error: z.string().optional() }),
    async handler(ctx, args) { const id = crypto.randomUUID(); await ctx.db().insert(schema.fileUploads).values({ id, viewerId: viewerId(ctx), fileName: args.fileName, fileSize: args.fileSize, receivedBytes: 0 }); return { ok: true, uploadId: id }; },
  }),
  writeFileUploadChunk: defineAction({
    request: z.object({ uploadId: z.string().uuid(), chunkBase64: z.string().min(1).max(MAX_CHUNK_BASE64), reset: z.boolean() }), response: z.object({ ok: z.boolean(), receivedBytes: z.number().optional(), error: z.string().optional() }),
    async handler(ctx, args) { const db = ctx.db(); const rows = await db.select().from(schema.fileUploads).where(and(eq(schema.fileUploads.id, args.uploadId), eq(schema.fileUploads.viewerId, viewerId(ctx)))).limit(1); const upload = rows[0]; if (!upload) return { ok: false, error: "This upload expired. Choose the file again." }; const bytes = Buffer.from(args.chunkBase64, "base64"); if (!bytes.byteLength || bytes.byteLength > 512 * 1024 || args.reset !== (upload.receivedBytes === 0)) return { ok: false, error: "The upload was interrupted. Choose the file again." }; const next = upload.receivedBytes + bytes.byteLength; if (next > upload.fileSize || next > MAX_FILE_BYTES) { await ctx.services.discardAlertUpload({ uploadId: args.uploadId }); await db.delete(schema.fileUploads).where(eq(schema.fileUploads.id, args.uploadId)); return { ok: false, error: "The file could not be validated." }; } const written = await ctx.services.writeAlertUploadChunk({ uploadId: args.uploadId, chunkBase64: args.chunkBase64, reset: args.reset }); if (!written.ok) return { ok: false, error: written.error ?? "The upload was interrupted." }; await db.update(schema.fileUploads).set({ receivedBytes: next }).where(eq(schema.fileUploads.id, args.uploadId)); return { ok: true, receivedBytes: next }; },
  }),
  finishFileUpload: defineAction({
    request: z.object({ uploadId: z.string().uuid(), zipPassword: z.string().max(200).optional() }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> { const db = ctx.db(); const rows = await db.select().from(schema.fileUploads).where(and(eq(schema.fileUploads.id, args.uploadId), eq(schema.fileUploads.viewerId, viewerId(ctx)))).limit(1); const upload = rows[0]; if (!upload) return { ok: false, error: "This upload expired. Choose the file again." }; try { if (upload.receivedBytes !== upload.fileSize) return { ok: false, error: "The upload ended before the whole file arrived." }; const extracted = await ctx.services.extractAlertText({ uploadId: args.uploadId, fileName: upload.fileName, password: args.zipPassword }); if (!extracted.ok || !extracted.text.trim()) return { ok: false, error: extracted.error ?? "No readable alert text was found." }; const id = await createCase(ctx, extracted.text.trim().slice(0, MAX_ALERT_CHARS), upload.fileName); return { ok: true, id, status: "queued" }; } catch { return { ok: false, error: "The file could not be read. Try a text, JSON, log, or ZIP file." }; } finally { await ctx.services.discardAlertUpload({ uploadId: args.uploadId }).catch(() => undefined); await db.delete(schema.fileUploads).where(eq(schema.fileUploads.id, args.uploadId)); } },
  }),
  runCase: defineAction({
    request: z.object({ id: z.string().min(1) }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.id);
      if (!row) return { ok: false, error: "Case not found." };
      // Free VirusTotal alone can take ~3 minutes (12 lookups, 15 s apart), so only a run idle for 15 minutes counts as stalled.
      const staleRunning = row.status === "running" && Date.now() - row.updatedAt.getTime() >= 15 * 60_000;
      if (row.status === "running" && !staleRunning) return { ok: false, error: "This case is already running. If it stalls, retry becomes available after 15 minutes." };
      const runVersion = row.runVersion + 1;
      await ctx.db().update(schema.triageCases).set({ status: "running", stage: "adaptive_investigation", runVersion, analystSummary: null, analystSummaryRunVersion: null, verdictOverride: null, resultJson: null, verdict: null, maliciousProbability: null, error: null, updatedAt: new Date() }).where(eq(schema.triageCases.id, row.id));

      const queued = await queueInvestigation(ctx, row.id, runVersion, "initial");
      if (!queued.ok) {
        const message = queued.error ?? "The investigation could not be queued.";
        await markError(ctx, row.id, message);
        return { ok: false, id: row.id, status: "error", error: message };
      }
      return { ok: true, id: row.id, status: "running" };
    },
  }),
  runCommand: defineAction({
    request: z.object({ caseId: z.string().min(1), command: z.string().min(1).max(3000) }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> { const row = await loadCase(ctx, args.caseId); if (!row) return { ok: false, error: "Case not found." }; const command = args.command.trim(); const prior = parseResult(row.resultJson); if (!prior) return { ok: false, error: "Run the case before adding analyst input." };
      if (command.toLowerCase().startsWith("/ask ")) { const text = command.slice(5).trim(); if (!text) return { ok: false, error: "Add a question after /ask." }; try { const answer = await askCaseQuestion(ctx, prior, text); prior.findings.push(answer); prior.analystAnswers.push(answer); await ctx.db().insert(schema.analystNotes).values({ id: crypto.randomUUID(), caseId: row.id, viewerId: row.viewerId, kind: "question", text }); await ctx.db().update(schema.triageCases).set({ resultJson: JSON.stringify(prior), updatedAt: new Date() }).where(eq(schema.triageCases.id, row.id)); return { ok: true, id: row.id, status: row.status }; } catch (error) { return { ok: false, error: error instanceof Error ? error.message : "Jev could not answer that question." }; } }
      if (command.toLowerCase().startsWith("/note ")) { const text = command.slice(6).trim(); if (!text) return { ok: false, error: "Add context after /note." }; const runVersion = row.runVersion + 1; await ctx.db().insert(schema.analystNotes).values({ id: crypto.randomUUID(), caseId: row.id, viewerId: row.viewerId, kind: "note", text }); await ctx.db().update(schema.triageCases).set({ status: "running", stage: "reinvestigating_with_note", runVersion, analystSummary: null, analystSummaryRunVersion: null, verdictOverride: null, error: null, updatedAt: new Date() }).where(eq(schema.triageCases.id, row.id)); const queued = await queueInvestigation(ctx, row.id, runVersion, "note"); if (!queued.ok) { const message = queued.error ?? "The investigation could not be queued."; await markError(ctx, row.id, message); return { ok: false, id: row.id, status: "error", error: message }; } return { ok: true, id: row.id, status: "running" }; }
      return { ok: false, error: "Start with /ask for a Jev question or /note to add context and rerun." }; },
  }),
  /** The analyst's final verdict on a case: the ground truth the evaluation and the cold loop learn from. */
  setDisposition: defineAction({
    request: z.object({ caseId: z.string().min(1), label: z.enum(["malicious", "benign"]), reason: z.string().max(2000).optional() }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.caseId); if (!row) return { ok: false, error: "Case not found." };
      if (!row.resultJson) return { ok: false, error: "Run the case before recording a decision." };
      const values = { caseId: row.id, label: args.label, reason: args.reason?.trim() || null, decidedBy: viewerId(ctx), jevVerdict: row.verdict, runVersion: row.runVersion, decidedAt: new Date() };
      await ctx.db().insert(schema.dispositions).values(values).onConflictDoUpdate({ target: schema.dispositions.caseId, set: values });
      // Warm loop: the decision settles this case's flags; a confirmed-malicious case flags related benign closures.
      resolveFlagsOnDecision(ctx.db(), row.id, args.label, viewerId(ctx));
      const flagged = args.label === "malicious" ? flagRelatedClosures(ctx.db(), row.id, "related_confirmed_malicious") : 0;
      return { ok: true, id: row.id, status: row.status, flagged };
    },
  }),
  deleteCase: defineAction({
    request: z.object({ id: z.string().min(1) }), response: z.object({ ok: z.boolean(), error: z.string().optional() }),
    async handler(ctx, args) { const row = await loadCase(ctx, args.id); if (!row) return { ok: false, error: "Case not found." }; await ctx.db().delete(schema.analystNotes).where(eq(schema.analystNotes.caseId, row.id)); await ctx.db().delete(schema.triageCases).where(and(eq(schema.triageCases.id, row.id), eq(schema.triageCases.viewerId, viewerId(ctx)))); return { ok: true }; },
  }),
} satisfies ActionsModule;

/** Background work, run by the job queue (never exposed over HTTP). */
export const JobHandlers = {
  processCase: defineAction({
    request: z.object({ caseId: z.string().min(1), runVersion: z.number().int().nonnegative(), mode: z.enum(["initial", "note", "analyst_questions"]), questions: z.array(z.string().min(3).max(500)).max(6).default([]) }),
    response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.caseId);
      if (!row) return { ok: false, error: "Case not found." };
      if (row.runVersion !== args.runVersion) return { ok: false, error: "This investigation was superseded by a newer run." };
      try {
        const started = performance.now();
        const hot = hotCtx(ctx, row);
        const notes = await loadNotes(ctx, row.id);
        let result = args.mode === "initial"
          ? await investigate(hot, row.inputText, notes, [], 3)
          : await rerunWithContext(hot, row, notes, args.mode === "analyst_questions" ? args.questions : []);
        result.timings = { hotMs: Math.round(performance.now() - started) };
        if (CLAUDE_MODE !== "tiebreak") {
          // Jev's answer is saved immediately. Every unresolved second-opinion case then gets its own
          // background action, so a slow Claude request cannot strand or delay the primary ticket.
          result = finaliseJevOnly(result);
          const wantsOpinion = CLAUDE_MODE === "second_opinion" && result.verdict === "needs_human";
          if (wantsOpinion) {
            result.secondOpinionStatus = "pending";
            result.secondOpinionError = undefined;
          }
          if (!(await stillCurrent(ctx, row.id, args.runVersion))) return { ok: false, error: "This investigation was superseded by a newer run." };
          await saveResult(ctx, row.id, args.runVersion, result, wantsOpinion ? "second_opinion" : undefined);
          await queueWarm(ctx, row.id, args.runVersion);
          if (!wantsOpinion) return { ok: true, id: row.id, status: result.status };
          const queued = await queueClaudeSecondOpinion(ctx, row.id, args.runVersion);
          if (!queued.ok) {
            const reason = queued.error ?? "Claude second opinion could not be queued.";
            console.error(`[jev-triage] Claude second opinion enqueue failed for case ${row.id}, run ${args.runVersion}: ${reason}`);
            result.secondOpinionStatus = "failed";
            result.secondOpinionError = reason;
            if (!result.unavailableSources.includes(reason)) result.unavailableSources.push(reason);
            await saveResult(ctx, row.id, args.runVersion, result);
          }
          return { ok: true, id: row.id, status: result.status };
        }

        let claudeUnavailable = false;

        if (result.status === "needs_questions") {
          for (let claudeRound = 0; claudeRound < 2 && result.verdict === "needs_human"; claudeRound += 1) {
            try {
              const written = await writeClaudeQuestions(ctx, result);
              if (!written.questions.length) { claudeUnavailable = true; break; }
              for (const text of written.questions) await ctx.db().insert(schema.analystNotes).values({ id: crypto.randomUUID(), caseId: row.id, viewerId: row.viewerId, kind: "question", text });
              await ctx.db().update(schema.triageCases).set({ status: "running", stage: "claude_guided_rounds", updatedAt: new Date() }).where(and(eq(schema.triageCases.id, row.id), eq(schema.triageCases.runVersion, args.runVersion)));
              result = await investigate(hot, row.inputText, notes, written.questions, 1, result, true, "claude");
            } catch {
              claudeUnavailable = true;
              break;
            }
          }
        }

        if (result.status === "needs_summary") {
          try {
            const tiebreak = await getClaudeTiebreak(ctx, result);
            result = applyClaudeTiebreak(result, tiebreak.verdict, tiebreak.summary, tiebreak.rationale);
          } catch {
            claudeUnavailable = true;
          }
        }

        if (claudeUnavailable && !result.unavailableSources.includes("Claude — unavailable")) result.unavailableSources.push("Claude — unavailable");
        // No hosted analyst agent here: a case Claude could not settle finishes as "needs analyst".
        result = finaliseJevOnly(result);
        // Tiebreak mode puts the reviewer AI inside the hot loop, so the time includes it.
        result.timings = { hotMs: Math.round(performance.now() - started), includesAi: true };
        const current = await loadCase(ctx, row.id);
        if (!current || current.runVersion !== args.runVersion) return { ok: false, error: "This investigation was superseded by a newer run." };
        await saveResult(ctx, row.id, args.runVersion, result);
        await queueWarm(ctx, row.id, args.runVersion);
        return { ok: true, id: row.id, status: result.status };
      } catch (error) {
        const message = error instanceof Error ? error.message : "The investigation could not complete.";
        await markError(ctx, row.id, message);
        return { ok: false, id: row.id, status: "error", error: message };
      }
    },
  }),
  processClaudeSecondOpinion: defineAction({
    request: z.object({ caseId: z.string().min(1), runVersion: z.number().int().nonnegative() }),
    response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.caseId);
      if (!row) return { ok: false, error: "Case not found." };
      if (row.runVersion !== args.runVersion) return { ok: false, error: "This Claude review was superseded by a newer run." };
      const original = parseResult(row.resultJson);
      if (!original) return { ok: false, error: "Case state is not ready." };
      if (CLAUDE_MODE !== "second_opinion" || original.verdict !== "needs_human" || original.secondOpinionStatus !== "pending") {
        return { ok: false, error: "This case is not waiting for a Claude second opinion." };
      }

      let result = original;
      try {
        const notes = await loadNotes(ctx, row.id);
        const written = await writeClaudeQuestions(ctx, result);
        if (written.questions.length) {
          for (const text of written.questions) await ctx.db().insert(schema.analystNotes).values({ id: crypto.randomUUID(), caseId: row.id, viewerId: row.viewerId, kind: "question", text });
          result = finaliseJevOnly(await investigate(hotCtx(ctx, row), row.inputText, notes, written.questions, 1, result, true, "claude"));
        }
        // This is always advisory. Claude reviews the complete, latest state even when its questions gave
        // Jev enough evidence to settle the case, and attachSecondOpinion never changes Jev's verdict.
        const opinion = await getClaudeTiebreak(ctx, result);
        result = attachSecondOpinion(result, opinion.verdict, opinion.summary, opinion.rationale);
      } catch (error) {
        const rawReason = error instanceof Error ? error.message : "Claude could not complete the review.";
        const reason = `Claude second opinion failed: ${rawReason}`.slice(0, 500);
        console.error(`[jev-triage] Claude second opinion failed for case ${row.id}, run ${args.runVersion}: ${rawReason}`);
        result.secondOpinionStatus = "failed";
        result.secondOpinionError = reason;
        if (!result.unavailableSources.includes(reason)) result.unavailableSources.push(reason);
      }

      if (!(await stillCurrent(ctx, row.id, args.runVersion))) return { ok: false, error: "This Claude review was superseded by a newer run." };
      await saveResult(ctx, row.id, args.runVersion, result);
      // Claude's questions may have let Jev settle the case, so the warm loop looks at it again.
      if (result.verdict !== "needs_human") await queueWarm(ctx, row.id, args.runVersion);
      return { ok: true, id: row.id, status: result.status };
    },
  }),
  /**
   * Warm loop, after a verdict is saved: retro-flags (no AI), then decides whether Claude should audit a benign closure.
   * Never changes the verdict.
   */
  warmCase: defineAction({
    request: z.object({ caseId: z.string().min(1), runVersion: z.number().int().nonnegative() }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.caseId);
      if (!row) return { ok: false, error: "Case not found." };
      if (row.runVersion !== args.runVersion) return { ok: false, error: "Superseded by a newer run." };
      const result = parseResult(row.resultJson);
      if (!result) return { ok: false, error: "Case state is not ready." };
      const db = ctx.db();
      let flagged = 0;
      // This system called the case malicious: recent benign closures that share a host, account or indicator get a second look.
      if (result.verdict === "malicious") flagged += flagRelatedClosures(db, row.id, "related_agent_malicious");
      // This case was closed as benign although a related case was called malicious and not yet confirmed.
      if (result.verdict === "benign") for (const r of result.relatedCases ?? []) if (r.outcome === "agent_malicious" && flagClosureRelatedTo(db, row.id, r)) flagged += 1;
      const audit = loopSettings().audit;
      const reason = audit.enabled && !result.audit ? auditReason(result) : null;
      if (reason && auditsInLastDay(db) < audit.dailyMax) {
        result.audit = { status: "pending", reason, at: new Date().toISOString() };
        if (!(await stillCurrent(ctx, row.id, args.runVersion))) return { ok: false, error: "Superseded by a newer run." };
        await saveResult(ctx, row.id, args.runVersion, result, row.stage);
        const queued = await ctx.jobs.enqueue("claudeAudit", { caseId: row.id, runVersion: args.runVersion }, viewerId(ctx));
        if (!queued.ok) { result.audit = { ...result.audit, status: "failed", error: "The audit could not be queued." }; await saveResult(ctx, row.id, args.runVersion, result, row.stage); }
      }
      return { ok: true, id: row.id, status: result.status, flagged };
    },
  }),
  /** Warm loop: Claude rechecks one benign closure. A disagreement adds a Recheck flag; the verdict stays Jev's. */
  claudeAudit: defineAction({
    request: z.object({ caseId: z.string().min(1), runVersion: z.number().int().nonnegative() }), response: okResponse,
    async handler(ctx, args): Promise<z.infer<typeof okResponse>> {
      const row = await loadCase(ctx, args.caseId);
      if (!row) return { ok: false, error: "Case not found." };
      if (row.runVersion !== args.runVersion) return { ok: false, error: "Superseded by a newer run." };
      const result = parseResult(row.resultJson);
      if (!result?.audit || result.audit.status !== "pending") return { ok: false, error: "This case is not waiting for an audit." };
      try {
        const a = await getClaudeTiebreak(ctx, result, "audit");
        const agrees = a.verdict === "benign";
        result.audit = { ...result.audit, status: agrees ? "agrees" : "disagrees", verdict: a.verdict, summary: a.summary, rationale: a.rationale, at: new Date().toISOString() };
        if (!agrees) flagClaudeDisagrees(ctx.db(), row.id, `The AI audit of this benign closure says ${a.verdict === "malicious" ? "it looks malicious" : "a person should decide"}: ${a.rationale || a.summary.split("\n")[0]}`);
      } catch (error) {
        result.audit = { ...result.audit, status: "failed", error: (error instanceof Error ? error.message : "Claude could not complete the audit.").slice(0, 300), at: new Date().toISOString() };
      }
      if (!(await stillCurrent(ctx, row.id, args.runVersion))) return { ok: false, error: "Superseded by a newer run." };
      await saveResult(ctx, row.id, args.runVersion, result, row.stage);
      return { ok: true, id: row.id, status: result.status };
    },
  }),
} satisfies ActionsModule;
