/**
 * Log search: the agent looks at the logs around an alert the way an analyst would (what else ran on the host,
 * the process tree, the account's sign-ins, where else a file, IP or domain was seen).
 *
 * Each provider (CrowdStrike, Splunk, Google SecOps, Elastic, Microsoft Defender, Trend Vision One) turns the same
 * small set of searches ("pivots") into its own query language and maps the results to one event shape.
 */

export type LogProvider = "crowdstrike" | "splunk" | "secops" | "elastic" | "defender" | "visionone";
export const LOG_PROVIDERS: LogProvider[] = ["crowdstrike", "splunk", "secops", "elastic", "defender", "visionone"];
export const PROVIDER_NAME: Record<LogProvider, string> = { crowdstrike: "CrowdStrike Falcon", splunk: "Splunk", secops: "Google SecOps", elastic: "Elastic", defender: "Microsoft Defender XDR", visionone: "Trend Vision One" };

export type PivotKind = "host_activity" | "process_tree" | "user_activity" | "hash_prevalence" | "ip_prevalence" | "domain_prevalence";

/** One search an analyst would run. `value` is always validated (see safety.ts) before any provider sees it. */
export type Pivot = {
  kind: PivotKind;
  /** The host, account, hash, IP or domain searched for. */
  value: string;
  /** For process_tree: the process (file) name, e.g. PsExec64.exe. */
  process?: string;
  start: Date;
  end: Date;
  /** Human wording, shown to Jev and on the ticket. */
  label: string;
};

export type LogEvent = {
  time: string;
  category: "process" | "network" | "dns" | "logon" | "file" | "other";
  host?: string;
  user?: string;
  action?: string;
  process?: string;
  commandLine?: string;
  parent?: string;
  parentCommandLine?: string;
  sha256?: string;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  domain?: string;
  logonType?: string;
  outcome?: string;
};

export type SearchResult = { ok: boolean; events: LogEvent[]; truncated: boolean; query: string; error?: string; durationMs: number };

export interface LogSource {
  provider: LogProvider;
  /** Runs one pivot. Never throws: failures come back as { ok: false, error }. */
  search(pivot: Pivot, maxEvents: number): Promise<SearchResult>;
}

export type LogSearchSettings = { windowMinutes: number; opening: PivotKind[]; timeoutMs: number; maxEvents: number };

/** What the engine keeps from one search (sent to Jev and shown on the ticket). */
export type LogSearchView = {
  key: string;
  kind: PivotKind;
  label: string;
  sources: string[];
  window: { start: string; end: string };
  events: number;
  truncated: boolean;
  findings: string[];
  errors: string[];
};
