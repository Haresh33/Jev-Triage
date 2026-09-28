-- Warm loop: which hosts, accounts and indicators each case involves (to find related cases quickly),
-- and flags that put an auto-closed case back in front of an analyst.
CREATE TABLE `case_entities` (
  `case_id` text NOT NULL,
  `kind` text NOT NULL,
  `value` text NOT NULL,
  PRIMARY KEY (`case_id`, `kind`, `value`),
  FOREIGN KEY (`case_id`) REFERENCES `triage_cases`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `case_entities_value_idx` ON `case_entities` (`kind`, `value`);
--> statement-breakpoint
CREATE TABLE `case_flags` (
  `id` text PRIMARY KEY NOT NULL,
  `case_id` text NOT NULL,
  `kind` text NOT NULL,
  `detail` text NOT NULL,
  `related_case_id` text,
  `created_at` integer NOT NULL,
  `resolved_at` integer,
  `resolved_by` text,
  FOREIGN KEY (`case_id`) REFERENCES `triage_cases`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `case_flags_case_idx` ON `case_flags` (`case_id`, `resolved_at`);
--> statement-breakpoint
CREATE INDEX `case_flags_related_idx` ON `case_flags` (`related_case_id`);
--> statement-breakpoint
-- Alerts pushed in by a SIEM / XDR webhook: a key so a resent alert doesn't open a second case.
ALTER TABLE `triage_cases` ADD `source_key` text;
--> statement-breakpoint
CREATE INDEX `triage_cases_source_key_idx` ON `triage_cases` (`source_key`);
