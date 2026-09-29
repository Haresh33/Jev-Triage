/**
 * Elasticsearch / Elastic Security: POST /{index}/_search with the Query DSL and Elastic Common Schema fields.
 * The query is JSON, so values are data and can't change its structure. API key auth (Authorization: ApiKey).
 * ELASTIC_INDEX defaults to logs-* (Elastic Defend writes logs-endpoint.events.*; add winlogbeat-* etc. as needed).
 */

import { describeFailure, http, isRecord, num, str } from "./http";
import { assertSafe, iso } from "./safety";
import type { LogEvent, LogSource, Pivot } from "./types";

export type ElasticSettings = { url: string; apiKey: string; index: string; timeoutMs: number };

const ci = (field: string, value: string) => ({ term: { [field]: { value, case_insensitive: true } } });
const anyOf = (...clauses: unknown[]) => ({ bool: { should: clauses, minimum_should_match: 1 } });
const hostClause = (h: string) => anyOf(ci("host.name", h), ci("host.hostname", h), { prefix: { "host.name": { value: `${h}.`, case_insensitive: true } } });
const SOURCE = ["@timestamp", "event.category", "event.action", "event.outcome", "host.name", "host.hostname", "user.name", "process.name", "process.command_line", "process.parent.name", "process.parent.command_line", "process.hash.sha256", "file.hash.sha256", "source.ip", "destination.ip", "destination.port", "destination.domain", "dns.question.name", "url.domain"];

/** The search body for one pivot. */
export function elasticQuery(p: Pivot, max: number): Record<string, unknown> {
  const filter: unknown[] = [{ range: { "@timestamp": { gte: iso(p.start), lte: iso(p.end) } } }];
  switch (p.kind) {
    case "host_activity": filter.push(hostClause(assertSafe("host", p.value)), { terms: { "event.category": ["process", "network"] } }); break;
    case "process_tree": { const x = assertSafe("process", p.process ?? ""); filter.push(hostClause(assertSafe("host", p.value)), anyOf(ci("process.name", x), ci("process.parent.name", x))); break; }
    case "user_activity": filter.push(ci("user.name", assertSafe("account", p.value))); break;
    case "hash_prevalence": { const h = assertSafe("sha256", p.value); filter.push(anyOf(ci("process.hash.sha256", h), ci("file.hash.sha256", h))); break; }
    case "ip_prevalence": { const ip = assertSafe("ip", p.value); filter.push(anyOf({ term: { "destination.ip": ip } }, { term: { "source.ip": ip } })); break; }
    case "domain_prevalence": { const d = assertSafe("domain", p.value); filter.push(anyOf(ci("dns.question.name", d), ci("url.domain", d), ci("destination.domain", d))); break; }
  }
  return { size: max, sort: [{ "@timestamp": "desc" }], _source: SOURCE, query: { bool: { filter } }, track_total_hits: false };
}

const get = (o: unknown, path: string): unknown => path.split(".").reduce<unknown>((v, k) => (isRecord(v) ? (k in v ? v[k] : undefined) : undefined), o) ?? (isRecord(o) ? o[path] : undefined);

export function elasticEvent(src: Record<string, unknown>): LogEvent {
  const cats = ([] as unknown[]).concat(get(src, "event.category") ?? []).map(String);
  const category: LogEvent["category"] = cats.includes("authentication") ? "logon" : cats.includes("process") ? "process" : get(src, "dns.question.name") ? "dns" : cats.includes("network") ? "network" : cats.includes("file") ? "file" : "other";
  return {
    time: str(get(src, "@timestamp")) ?? "", category, host: str(get(src, "host.name")) ?? str(get(src, "host.hostname")), user: str(get(src, "user.name")),
    action: str(get(src, "event.action")), outcome: str(get(src, "event.outcome")), process: str(get(src, "process.name")), commandLine: str(get(src, "process.command_line")),
    parent: str(get(src, "process.parent.name")), parentCommandLine: str(get(src, "process.parent.command_line")), sha256: str(get(src, "process.hash.sha256")) ?? str(get(src, "file.hash.sha256")),
    srcIp: str(get(src, "source.ip")), dstIp: str(get(src, "destination.ip")), dstPort: num(get(src, "destination.port")), domain: str(get(src, "dns.question.name")) ?? str(get(src, "url.domain")) ?? str(get(src, "destination.domain")),
  };
}

export function elasticSource(s: ElasticSettings): LogSource {
  return {
    provider: "elastic",
    async search(p, max) {
      const started = performance.now(); let body: Record<string, unknown>;
      try { body = elasticQuery(p, max); } catch (e) { return { ok: false, events: [], truncated: false, query: "", error: String((e as Error).message), durationMs: 0 }; }
      const query = JSON.stringify(body);
      const r = await http(`${s.url}/${s.index.split(",").map((i) => encodeURIComponent(i.trim())).join(",")}/_search?ignore_unavailable=true&allow_no_indices=true`, { method: "POST", headers: { Authorization: `ApiKey ${s.apiKey}`, "Content-Type": "application/json" }, body: query }, s.timeoutMs);
      const durationMs = Math.round(performance.now() - started);
      const hits = isRecord(r.json) && isRecord(r.json.hits) && Array.isArray(r.json.hits.hits) ? r.json.hits.hits : null;
      if (r.status !== 200 || !hits) return { ok: false, events: [], truncated: false, query, error: describeFailure("Elastic", r), durationMs };
      const events = hits.filter(isRecord).map((h) => (isRecord(h._source) ? elasticEvent(h._source) : null)).filter((e): e is LogEvent => e !== null);
      return { ok: true, events, truncated: events.length >= max, query, durationMs };
    },
  };
}
