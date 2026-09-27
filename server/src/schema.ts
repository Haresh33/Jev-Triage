import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const triageCases = sqliteTable("triage_cases", {
  id: text("id").primaryKey(),
  viewerId: text("viewer_id").notNull(),
  title: text("title").notNull(),
  inputText: text("input_text").notNull(),
  sourceName: text("source_name"),
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
