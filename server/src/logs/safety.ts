/**
 * Values from an alert go into SPL, KQL, CQL, UDM search and TMV1-Query strings. The alert can be written by an
 * attacker, so every value is checked against a strict pattern first (no quotes, pipes, brackets, wildcards,
 * spaces or control characters), and each provider also escapes it for its own language. A value that fails the
 * check is simply not searched.
 */

const PATTERNS = {
  host: /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/,
  account: /^[A-Za-z0-9][A-Za-z0-9._@$-]{0,127}$/,
  process: /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/,
  sha256: /^[a-f0-9]{64}$/,
  ipv4: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
  ipv6: /^[0-9a-f:]{2,39}$/,
  domain: /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/,
} as const;
export type SafeKind = keyof typeof PATTERNS | "ip";

export function isSafe(kind: SafeKind, value: string): boolean {
  if (kind === "ip") return PATTERNS.ipv4.test(value) || (PATTERNS.ipv6.test(value) && value.includes(":"));
  return PATTERNS[kind].test(value);
}

/** Throws if a value that reached a query builder isn't safe (defence in depth; pivots are validated when built). */
export function assertSafe(kind: SafeKind, value: string): string {
  if (!isSafe(kind, value)) throw new Error(`refused to search for an unsafe ${kind} value`);
  return value;
}

/** Double-quoted string literal with backslash escapes (SPL, KQL, CQL, UDM search, TMV1-Query all accept this form). */
export function quoted(value: string): string {
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error("refused a value with control characters");
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** A regex body matching `value` literally (for providers where host names need prefix or suffix matching). */
export function regexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\/-]/g, (c) => `\\${c}`);
}

export const iso = (d: Date) => d.toISOString();
/** ISO 8601 without milliseconds (Vision One accepts at most 20 characters). */
export const isoSeconds = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
