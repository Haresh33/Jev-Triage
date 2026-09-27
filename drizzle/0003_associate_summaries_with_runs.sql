ALTER TABLE `triage_cases` ADD `run_version` integer NOT NULL DEFAULT 0;
--> statement-breakpoint
ALTER TABLE `triage_cases` ADD `analyst_summary_run_version` integer;
--> statement-breakpoint
UPDATE `triage_cases`
SET `analyst_summary_run_version` = `run_version`,
    `status` = 'completed',
    `stage` = 'ticket_ready'
WHERE `analyst_summary` IS NOT NULL;
