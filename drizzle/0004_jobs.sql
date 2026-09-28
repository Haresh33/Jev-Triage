-- Background jobs (replaces the hosted platform's agent tasks). One row per queued investigation.
CREATE TABLE `jobs` (
  `id` text PRIMARY KEY NOT NULL,
  `kind` text NOT NULL,
  `args_json` text NOT NULL,
  `viewer_id` text NOT NULL,
  `status` text DEFAULT 'queued' NOT NULL,
  `attempts` integer DEFAULT 0 NOT NULL,
  `error` text,
  `created_at` integer NOT NULL,
  `updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `jobs_status_created_idx` ON `jobs` (`status`,`created_at`);
