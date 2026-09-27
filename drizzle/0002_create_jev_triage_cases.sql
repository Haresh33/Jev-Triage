DROP TABLE IF EXISTS entries;
--> statement-breakpoint
CREATE TABLE `triage_cases` (
  `id` text PRIMARY KEY NOT NULL,
  `viewer_id` text NOT NULL,
  `title` text NOT NULL,
  `input_text` text NOT NULL,
  `source_name` text,
  `status` text DEFAULT 'queued' NOT NULL,
  `stage` text DEFAULT 'queued' NOT NULL,
  `verdict` text,
  `malicious_probability` integer,
  `result_json` text,
  `analyst_summary` text,
  `verdict_override` text,
  `analyst_task_id` text,
  `error` text,
  `created_at` integer NOT NULL,
  `updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `triage_cases_viewer_created_idx` ON `triage_cases` (`viewer_id`,`created_at`);
--> statement-breakpoint
CREATE TABLE `analyst_notes` (
  `id` text PRIMARY KEY NOT NULL,
  `case_id` text NOT NULL,
  `viewer_id` text NOT NULL,
  `kind` text NOT NULL,
  `text` text NOT NULL,
  `created_at` integer NOT NULL,
  FOREIGN KEY (`case_id`) REFERENCES `triage_cases`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `analyst_notes_case_idx` ON `analyst_notes` (`case_id`,`created_at`);
--> statement-breakpoint
CREATE TABLE `file_uploads` (
  `id` text PRIMARY KEY NOT NULL,
  `viewer_id` text NOT NULL,
  `file_name` text NOT NULL,
  `file_size` integer NOT NULL,
  `received_bytes` integer DEFAULT 0 NOT NULL,
  `created_at` integer NOT NULL
);