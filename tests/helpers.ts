/**
 * Test helpers: a stand-in for Jev and the lookups (no network, no keys), and a Ctx builder.
 *
 * The stand-in Jev reads the state the way a cautious analyst would: strong behaviours mean attacker activity,
 * an analyst note that names an approval or test clears it, everything else stays unsure. It exists to test the
 * engine's plumbing and guardrails, not to predict real Jev's scores.
 */

import { openDatabase } from "../server/src/db";
import { createJobQueue } from "../server/src/jobs";
import type { Ctx, ProviderResponse, Services } from "../server/src/platform";

type Lean = "reads_evidence" | "reputation_only";

const reply = (value: unknown): ProviderResponse => ({ ok: true, dataJson: JSON.stringify(value), error: null, durationMs: 1 });
const unavailable = (why: string): ProviderResponse => ({ ok: false, dataJson: null, error: why, durationMs: 1 });

export function standInServices(lean: Lean = "reads_evidence", calls: string[] = []): Services {
  return {
    async jevEvaluate({ state, questionsJson }) {
      calls.push("jev");
      const questions = JSON.parse(questionsJson) as Record<string, { type: string; instructions: string; criteria?: Record<string, string> | string[] }>;
      const strong = /; strong\]/.test(state);
      let notes = "";
      try { const parsed = JSON.parse(state) as { state?: { analystNotes?: unknown } }; notes = JSON.stringify(parsed.state?.analystNotes ?? []); } catch { /* indicator-only state */ }
      const approved = /approved|authori[sz]ed|red team|change (ticket )?chg-\d+/i.test(notes);
      const answers: Record<string, unknown> = {};
      for (const [name, q] of Object.entries(questions)) {
        const text = q.instructions;
        if (q.type === "noul") {
          let p = 0.1;
          if (text.startsWith("Is the activity malicious")) p = lean === "reputation_only" ? 0.05 : strong && !approved ? 0.95 : approved ? 0.05 : 0.3;
          else if (text.startsWith("Is this indicator malicious")) p = 0.05;
          else if (/concrete evidence that the command or change was authori|security test, red-team/.test(text)) p = approved ? 0.93 : 0.05;
          else if (strong && /behaviors show|attacker actions/.test(text)) p = 0.93;
          answers[name] = { type: "noul", noul: p };
        } else {
          const options = Array.isArray(q.criteria) ? q.criteria.map(String) : Object.keys(q.criteria ?? {});
          const pick = options.includes("not_stated") ? "not_stated" : options.includes("conclude") ? "conclude" : options[0] ?? "";
          answers[name] = { type: "choice", choice: pick, confidence: 0.6, probabilities: { [pick]: 0.6 } };
        }
      }
      return reply({ model: "stand-in", usage: {}, answers });
    },
    async shodanEntity() { calls.push("shodan"); return unavailable("not configured"); },
    async virustotalLookup() { calls.push("virustotal"); return reply({ status: 404, body: null }); },
    async abuseIpdbLookup() { calls.push("abuseipdb"); return unavailable("not configured"); },
    async aiComplete() { calls.push("claude"); return unavailable("not configured"); },
    async writeAlertUploadChunk() { return { ok: true, error: null }; },
    async discardAlertUpload() { return { ok: true }; },
    async extractAlertText() { return { ok: false, text: "", manifestJson: "[]", kind: "file", truncated: false, error: "not in tests" }; },
  };
}

/** A context backed by a fresh in-memory database. */
export function testCtx(services: Services = standInServices()): Ctx {
  const { db } = openDatabase(":memory:");
  return { db: () => db, viewer: { id: "tester" }, services, jobs: createJobQueue(db) };
}

/** The engine also reaches public, key-free sources (DNS-over-HTTPS, RDAP, Shodan InternetDB) with fetch: stub them. */
export function stubPublicFetch(): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
  return () => { globalThis.fetch = original; };
}
