/**
 * Turns raw events into a few short findings for Jev and the ticket: what ran, where it connected, who signed in,
 * and how widespread a file, IP or domain is. Code does this, not a language model, so it's fast and free.
 */

import type { LogEvent, Pivot } from "./types";

const PRIVATE_IP = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.|::1$|fe80:|fc|fd)/i;
const clip = (s: string, n = 220) => (s.length > n ? `${s.slice(0, n)}…` : s);
const hhmm = (t: string) => { const d = new Date(t); return Number.isNaN(d.getTime()) ? t : d.toISOString().slice(0, 16).replace("T", " "); };
function top<T>(items: T[], key: (x: T) => string | undefined, n: number): Array<[string, number]> {
  const m = new Map<string, number>();
  for (const x of items) { const k = key(x); if (k) m.set(k, (m.get(k) ?? 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}
const list = (xs: Array<[string, number]>) => xs.map(([k, c]) => (c > 1 ? `${k} (${c})` : k)).join(", ");

export type Discovered = { type: "ip" | "domain" | "sha256"; value: string; why: string };

export function summarise(pivot: Pivot, events: LogEvent[], truncated: boolean): { findings: string[]; discovered: Discovered[] } {
  const f: string[] = [];
  const more = truncated ? " (more events exist; showing the most recent)" : "";
  if (!events.length) return { findings: ["No matching events in this window."], discovered: [] };
  const by = (c: LogEvent["category"]) => events.filter((e) => e.category === c);
  const proc = by("process"); const net = by("network"); const dns = by("dns"); const logon = by("logon"); const file = by("file");
  const counts = [[proc.length, "process starts"], [net.length, "network connections"], [dns.length, "DNS lookups"], [logon.length, "sign-in events"], [file.length, "file events"], [by("other").length, "other events"]].filter(([n]) => (n as number) > 0).map(([n, w]) => `${n} ${w}`).join(", ");
  const hosts = top(events, (e) => e.host?.toLowerCase(), 8);
  const times = events.map((e) => e.time).filter(Boolean).sort();

  if (pivot.kind === "hash_prevalence" || pivot.kind === "ip_prevalence" || pivot.kind === "domain_prevalence") {
    const distinct = new Set(events.map((e) => e.host?.toLowerCase()).filter(Boolean)).size;
    f.push(`Seen on ${distinct} host${distinct === 1 ? "" : "s"}${hosts.length ? `: ${list(hosts)}` : ""}${distinct > hosts.length ? ` and ${distinct - hosts.length} more` : ""}. ${events.length} events${more}; first ${hhmm(times[0]!)}, last ${hhmm(times.at(-1)!)}.`);
    const procs = top(events, (e) => e.process?.toLowerCase(), 5); if (procs.length) f.push(`Processes involved: ${list(procs)}.`);
    const users = top(events, (e) => e.user, 5); if (users.length) f.push(`Accounts: ${list(users)}.`);
  } else if (pivot.kind === "user_activity") {
    const ok = logon.filter((e) => /success|succeeded|logon$|^logonsuccess|allow/i.test(`${e.outcome ?? ""} ${e.action ?? ""}`) && !/fail/i.test(`${e.outcome ?? ""} ${e.action ?? ""}`)).length;
    const failed = logon.filter((e) => /fail|denied|block|error/i.test(`${e.outcome ?? ""} ${e.action ?? ""}`)).length;
    f.push(`${counts}${more}.`);
    if (logon.length) f.push(`Sign-ins: ${ok} succeeded, ${failed} failed${logon.length - ok - failed > 0 ? `, ${logon.length - ok - failed} other` : ""}.`);
    const src = top(logon, (e) => e.srcIp, 6); if (src.length) f.push(`Sign-in sources: ${list(src)}.`);
    const types = top(logon, (e) => e.logonType, 5); if (types.length) f.push(`Sign-in types: ${list(types)}.`);
    if (hosts.length) f.push(`Hosts: ${list(hosts)}.`);
    const procs = top(proc, (e) => e.process?.toLowerCase(), 6); if (procs.length) f.push(`Processes run by the account: ${list(procs)}.`);
  } else {
    f.push(`${counts}${more}.`);
    const seen = new Set<string>();
    const lines = [...proc].sort((a, b) => b.time.localeCompare(a.time)).filter((e) => { const k = (e.commandLine ?? e.process ?? "").toLowerCase(); if (!k || seen.has(k)) return false; seen.add(k); return true; }).slice(0, 8);
    for (const e of lines) f.push(`${hhmm(e.time)} ${e.user ? `${e.user}: ` : ""}${e.parent ? `${e.parent} → ` : ""}${clip(e.commandLine ?? e.process ?? "")}`);
    const dests = top(net, (e) => (e.dstIp ? `${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ""}${e.domain ? ` (${e.domain})` : ""}` : e.domain), 6);
    if (dests.length) f.push(`Connections to: ${list(dests)}.`);
    const lookups = top(dns, (e) => e.domain?.toLowerCase(), 6); if (lookups.length) f.push(`DNS lookups: ${list(lookups)}.`);
    const users = top(proc, (e) => e.user, 4); if (users.length > 1) f.push(`Accounts on the host: ${list(users)}.`);
  }

  // New leads: outside addresses, domains and file hashes that appeared in the logs.
  const discovered: Discovered[] = [];
  const seenValues = new Set([pivot.value.toLowerCase()]);
  const push = (type: Discovered["type"], value: string | undefined, why: string) => { const v = value?.toLowerCase().trim(); if (!v || seenValues.has(v) || discovered.length >= 6) return; seenValues.add(v); discovered.push({ type, value: v, why }); };
  for (const [ip] of top(net.filter((e) => e.dstIp && !PRIVATE_IP.test(e.dstIp)), (e) => e.dstIp, 3)) push("ip", ip, `seen in ${pivot.label.toLowerCase()}`);
  for (const [d] of top([...dns, ...net], (e) => e.domain, 3)) push("domain", d, `seen in ${pivot.label.toLowerCase()}`);
  for (const [h] of top(proc, (e) => (e.sha256 && /^[a-f0-9]{64}$/i.test(e.sha256) ? e.sha256 : undefined), 2)) push("sha256", h, `seen in ${pivot.label.toLowerCase()}`);
  return { findings: f.slice(0, 14).map((x) => clip(x, 320)), discovered };
}
