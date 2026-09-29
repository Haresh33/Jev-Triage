import { index, integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const triageCases = sqliteTable("triage_cases", {
  id: text("id").primaryKey(),
  viewerId: text("viewer_id").notNull(),
  title: text("title").notNull(),
  inputText: text("input_text").notNull(),
  sourceName: text("source_name"),
  /** For alerts pushed in by a webhook: the sender's alert id (or a hash of the alert), to ignore resends. */
  sourceKey: text("source_key"),
  status: text("status", { enum: ["queued", "running", "completed", "needs_questions", "needs_summary", "error"] }).notNull().default("queued"),
  stage: text("stage").notNull().default("queued"),
  verdict: text("verdict", { enum: ["malicious", "benign", "needs_human"] }),
  maliciousProbability: integer("malicious_probability"),
  resultJson: text("result_json"),
  analystSummary: text("analyst_summary"),
  runVersion: integer("run_version").notNull().default(0),
  analystSummaryRunVersion: integer("analyst_summary_run_version"),
  verdictOverride: text("verdict_override", { enum: ["malicious", "benign", "needs_human"] }),
  analystTaskId: text("analyst_task_id"),
  error: text("error"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
}, (table) => [index("triage_cases_viewer_created_idx").on(table.viewerId, table.createdAt)]);

export const analystNotes = sqliteTable("analyst_notes", {
  id: text("id").primaryKey(),
  caseId: text("case_id").notNull().references(() => triageCases.id, { onDelete: "cascade" }),
  viewerId: text("viewer_id").notNull(),
  kind: text("kind", { enum: ["note", "question"] }).notNull(),
  text: text("text").notNull(),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
}, (table) => [index("analyst_notes_case_idx").on(table.caseId, table.createdAt)]);

export const fileUploads = sqliteTable("file_uploads", {
  id: text("id").primaryKey(),
  viewerId: text("viewer_id").notNull(),
  fileName: text("file_name").notNull(),
  fileSize: integer("file_size").notNull(),
  receivedBytes: integer("received_bytes").notNull().default(0),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
});

export const jobs = sqliteTable("jobs", {
  id: text("id").primaryKey(),
  kind: text("kind", { enum: ["processCase", "processClaudeSecondOpinion", "warmCase", "claudeAudit"] }).notNull(),
  argsJson: text("args_json").notNull(),
  viewerId: text("viewer_id").notNull(),
  status: text("status", { enum: ["queued", "running", "done", "failed"] }).notNull().default("queued"),
  attempts: integer("attempts").notNull().default(0),
  error: text("error"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
}, (table) => [index("jobs_status_created_idx").on(table.status, table.createdAt)]);

/** The final verdict an analyst reached on a case (one per case, latest wins). */
export const dispositions = sqliteTable("dispositions", {
  caseId: text("case_id").primaryKey().references(() => triageCases.id, { onDelete: "cascade" }),
  label: text("label", { enum: ["malicious", "benign"] }).notNull(),
  reason: text("reason"),
  decidedBy: text("decided_by").notNull(),
  /** What the agent said at the time, so disagreements can be found later. */
  jevVerdict: text("jev_verdict", { enum: ["malicious", "benign", "needs_human"] }),
  runVersion: integer("run_version").notNull(),
  decidedAt: integer("decided_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
});

/** Warm loop: the hosts, accounts and indicators a case involves, so related cases are found in milliseconds. */
export const caseEntities = sqliteTable("case_entities", {
  caseId: text("case_id").notNull().references(() => triageCases.id, { onDelete: "cascade" }),
  kind: text("kind", { enum: ["account", "host", "ip", "domain", "hash"] }).notNull(),
  value: text("value").notNull(),
}, (table) => [primaryKey({ columns: [table.caseId, table.kind, table.value] }), index("case_entities_value_idx").on(table.kind, table.value)]);

/** Warm loop: reasons an analyst should look again at a case the agent closed. Resolved when an analyst decides the case. */
export const caseFlags = sqliteTable("case_flags", {
  id: text("id").primaryKey(),
  caseId: text("case_id").notNull().references(() => triageCases.id, { onDelete: "cascade" }),
  kind: text("kind", { enum: ["related_confirmed_malicious", "related_agent_malicious", "claude_disagrees"] }).notNull(),
  detail: text("detail").notNull(),
  relatedCaseId: text("related_case_id"),
  createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull().$defaultFn(() => new Date()),
  resolvedAt: integer("resolved_at", { mode: "timestamp_ms" }),
  resolvedBy: text("resolved_by"),
}, (table) => [index("case_flags_case_idx").on(table.caseId, table.resolvedAt), index("case_flags_related_idx").on(table.relatedCaseId)]);
