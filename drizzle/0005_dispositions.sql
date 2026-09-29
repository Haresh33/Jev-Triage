-- Analyst decisions: the final verdict a person reached on a case. Ground truth for evaluation and the cold loop.
CREATE TABLE `dispositions` (
  `case_id` text PRIMARY KEY NOT NULL,
  `label` text NOT NULL,
  `reason` text,
  `decided_by` text NOT NULL,
  `jev_verdict` text,
  `run_version` integer NOT NULL,
  `decided_at` integer NOT NULL,
  FOREIGN KEY (`case_id`) REFERENCES `triage_cases`(`id`) ON UPDATE no action ON DELETE cascade
);
