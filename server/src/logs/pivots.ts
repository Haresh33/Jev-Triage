/**
 * Which log searches fit a case, and when the alert happened.
 *
 *   host_activity      what ran and connected on the host, ± the window around the alert
 *   process_tree       the alerted process: what started it and what it started
 *   user_activity      the account's sign-ins and activity in the 24 hours before the alert
 *   hash_prevalence    where else the file ran in the last 7 days
 *   ip_prevalence      which other hosts talked to the outside IP in the last 7 days
 *   domain_prevalence  which other hosts looked up the domain in the last 7 days
 */

import type { Entity } from "../loops";
import { isSafe } from "./safety";
import type { LogSearchSettings, Pivot, PivotKind } from "./types";

const MIN = 60_000; const HOUR = 60 * MIN; const DAY = 24 * HOUR;
const TIME_KEY = /(^|[._])(@?timestamp|time|datetime|eventtime|event_time|createdtime|createddatetime|detectedtime|detecteddatetime|detected_at|detectedat|firstseen|first_seen|creationtime|occurred|occurredat|starttime|start_time|date|created|created_at|createdat|triggertime|alerttime|alert_time|eventtimedt)$/i;

function parseTime(v: unknown, now: Date): Date | null {
  let d: Date | null = null;
  if (typeof v === "number" && Number.isFinite(v)) d = new Date(v > 1e12 ? v : v * 1000);
  else if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(v.trim())) d = new Date(v.trim().replace(" ", "T"));
  else if (typeof v === "string" && /^\d{10}(\d{3})?$/.test(v.trim())) d = new Date(Number(v.trim()) * (v.trim().length === 10 ? 1000 : 1));
  if (!d || Number.isNaN(d.getTime())) return null;
  // Ignore obviously wrong times (far future, or before 2000).
  if (d.getTime() > now.getTime() + DAY || d.getFullYear() < 2000) return null;
  return d;
}

/** When the alerted activity happened: the first time-like field in a JSON alert, else the first ISO time in the text, else now. */
export function alertTime(raw: string, now = new Date()): { at: Date; fromAlert: boolean } {
  try {
    const walk = (value: unknown, key: string): Date | null => {
      if (Array.isArray(value)) { for (const v of value) { const d = walk(v, key); if (d) return d; } return null; }
      if (value && typeof value === "object") { for (const [k, v] of Object.entries(value)) { const d = walk(v, k); if (d) return d; } return null; }
      return TIME_KEY.test(key) ? parseTime(value, now) : null;
    };
    const found = walk(JSON.parse(raw), "");
    if (found) return { at: found, fromAlert: true };
  } catch { /* not JSON */ }
  const m = raw.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?\b/);
  const d = m ? parseTime(m[0], now) : null;
  return d ? { at: d, fromAlert: true } : { at: now, fromAlert: false };
}

const PRIVATE_IP = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.)/;
/** The program a command line runs: the first token (a quoted path may contain spaces), without its folder. */
const basename = (p: string) => { const t = p.trim(); const first = t.startsWith('"') ? t.slice(1, t.indexOf('"', 1) > 0 ? t.indexOf('"', 1) : undefined) : t.split(/\s/)[0]!; return first.split(/[\\/]/).pop()!; };

export type PivotInputs = { entities: Entity[]; processes: string[]; commandLines: string[]; at: Date; now?: Date };

/** All searches that fit the case, in the order an analyst would usually run them. */
export function pivotsFor(inputs: PivotInputs, settings: Pick<LogSearchSettings, "windowMinutes">): Pivot[] {
  const now = inputs.now ?? new Date();
  const at = inputs.at;
  const w = settings.windowMinutes * MIN;
  const clamp = (start: number, end: number) => ({ start: new Date(Math.min(start, now.getTime() - MIN)), end: new Date(Math.min(end, now.getTime())) });
  const of = (kind: Entity["kind"]) => inputs.entities.filter((e) => e.kind === kind).map((e) => e.value);
  const out: Pivot[] = [];
  const add = (kind: PivotKind, value: string, span: { start: Date; end: Date }, label: string, process?: string) => out.push({ kind, value, start: span.start, end: span.end, label, ...(process ? { process } : {}) });
  const around = clamp(at.getTime() - w, at.getTime() + w);
  const host = of("host").find((h) => isSafe("host", h));
  const exe = [...inputs.processes, ...inputs.commandLines].map(basename).find((p) => /\.[a-z0-9]{2,4}$/i.test(p) && isSafe("process", p));
  if (host) add("host_activity", host, around, `Activity on ${host}, ${settings.windowMinutes} min either side of the alert`);
  if (host && exe) add("process_tree", host, around, `Process tree around ${exe} on ${host}`, exe);
  const account = of("account").find((a) => isSafe("account", a));
  if (account) add("user_activity", account, clamp(at.getTime() - DAY, at.getTime() + w), `Sign-ins and activity of ${account} in the 24 hours before the alert`);
  for (const h of of("hash").filter((x) => isSafe("sha256", x)).slice(0, 2)) add("hash_prevalence", h, clamp(at.getTime() - 7 * DAY, at.getTime() + DAY), `Where else file ${h.slice(0, 12)}… ran in the last 7 days`);
  for (const ip of of("ip").filter((x) => isSafe("ip", x) && !PRIVATE_IP.test(x)).slice(0, 2)) add("ip_prevalence", ip, clamp(at.getTime() - 7 * DAY, at.getTime() + DAY), `Which hosts talked to ${ip} in the last 7 days`);
  for (const d of of("domain").filter((x) => isSafe("domain", x)).slice(0, 2)) add("domain_prevalence", d, clamp(at.getTime() - 7 * DAY, at.getTime() + DAY), `Which hosts looked up ${d} in the last 7 days`);
  return out;
}

export const pivotKey = (p: Pivot) => `${p.kind}:${p.value}:${p.process ?? ""}`;
