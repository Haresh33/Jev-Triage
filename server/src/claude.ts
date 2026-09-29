import type { Ctx } from "./platform";
import type { Finding, TriageResult, Verdict } from "./triage";

export type ClaudeQuestionSet = {
  questions: string[];
};

export type ClaudeTiebreak = {
  verdict: Verdict; // "needs_human" when the evidence does not support a confident call
  summary: string;
  rationale: string;
};

type ClaudeMode = "questions" | "tiebreak" | "audit";

type ClaudeResponse = {
  questions?: unknown;
  verdict?: unknown;
  summary?: unknown;
  rationale?: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseResponse(value: string | null): ClaudeResponse | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function compactFinding(finding: Finding): Record<string, unknown> {
  return {
    round: finding.round,
    subject: finding.subject,
    question: finding.question,
    answer: finding.answer,
    probability: finding.probability,
    origin: finding.origin,
  };
}

function fullCaseState(result: TriageResult, compact = false): Record<string, unknown> {
  return {
    alert: result.state.alert.slice(0, compact ? 8_000 : 24_000),
    // Cloud events carry a raw copy of the event ("detail") for rule matching; the alert itself is already included above.
    facts: Object.fromEntries(Object.entries(result.state.facts).map(([key, value]) => [key, Array.isArray(value) ? value.slice(0, compact ? 8 : 20).map((item) => typeof item === "string" ? item.slice(0, 800) : isRecord(item) && "detail" in item ? { ...item, detail: undefined } : item) : value])),
    domains: result.domains ?? [],
    observedBehaviors: (result.behaviors ?? []).slice(0, compact ? 20 : 60).map((behavior) => ({
      statement: behavior.statement,
      attackTechnique: behavior.technique,
      strength: behavior.strength,
      evidence: behavior.evidence.slice(0, compact ? 500 : 1_200),
    })),
    rankedExplanations: (result.hypotheses ?? []).slice(0, compact ? 6 : 12),
    indicators: result.state.evidence.slice(0, compact ? 15 : 40).map((evidence) => ({
      value: evidence.indicator.value,
      type: evidence.indicator.type,
      origin: evidence.indicator.origin,
      signals: evidence.signals.slice(0, compact ? 5 : 10).map((signal) => signal.slice(0, 700)),
      labels: evidence.labels.slice(0, 8),
      hardHits: evidence.strongHits.slice(0, 5),
      unavailable: evidence.unavailable.slice(0, 6),
      jevProbability: typeof evidence.sources.jevProbability === "number" ? evidence.sources.jevProbability : null,
    })),
    jevAnswers: result.findings.slice(compact ? -50 : -150).map(compactFinding),
    analystNotes: result.state.notes.slice(compact ? -8 : -20),
    ...(result.orgContext?.length ? { organisationContext: { about: "Reviewed context from the organisation's security team: what is normal, not proof this activity was authorised.", entries: result.orgContext.map((c) => c.note) } } : {}),
    ...(result.logSearches?.length ? { surroundingLogs: result.logSearches.map((v) => ({ search: v.label, sources: v.sources, events: v.events, findings: v.findings, failed: v.errors })) } : {}),
    ...(result.relatedCases?.length ? { relatedCases: result.relatedCases.map((r) => ({ daysAgo: r.daysAgo, alert: r.title, shares: r.shared, outcome: r.outcome, analystReason: r.reason })) } : {}),
    unresolved: result.unresolved,
    decisionTrail: {
      rounds: result.rounds,
      followedLeads: result.leads,
      stopReason: result.stopReason,
      jevRequests: result.jevRequests,
      jevQuestions: result.jevQuestions,
      investigatedAt: result.investigatedAt,
    },
    currentAssessment: {
      verdict: result.verdict,
      maliciousProbability: result.pMalicious,
      category: result.category,
      severity: result.severity,
      stage: result.stage,
      stopReason: result.stopReason,
      guardrailConflicts: result.guardrail.conflicts,
    },
  };
}

async function callClaude(ctx: Ctx, mode: ClaudeMode, result: TriageResult): Promise<ClaudeResponse> {
  let stateJson = JSON.stringify(fullCaseState(result));
  if (stateJson.length > 79_000) stateJson = JSON.stringify(fullCaseState(result, true));
  const response = await ctx.services.aiComplete({ mode, stateJson });
  if (!response.ok) throw new Error(response.error ?? "Claude could not complete this step.");
  const parsed = parseResponse(response.dataJson);
  if (!parsed) throw new Error("Claude returned an unreadable response.");
  return parsed;
}

export async function writeClaudeQuestions(ctx: Ctx, result: TriageResult): Promise<ClaudeQuestionSet> {
  const raw = await callClaude(ctx, "questions", result);
  const questions = Array.isArray(raw.questions)
    ? raw.questions.filter((value): value is string => typeof value === "string").map((value) => value.trim()).filter((value) => value.length >= 3).slice(0, 5)
    : [];
  return { questions: [...new Set(questions)] };
}

export async function getClaudeTiebreak(ctx: Ctx, result: TriageResult, mode: "tiebreak" | "audit" = "tiebreak"): Promise<ClaudeTiebreak> {
  const raw = await callClaude(ctx, mode, result);
  if (raw.verdict !== "malicious" && raw.verdict !== "benign" && raw.verdict !== "needs_human") throw new Error("Claude did not return a usable verdict.");
  const verdict = raw.verdict;
  const summary = typeof raw.summary === "string" ? raw.summary.trim().slice(0, 2000) : "";
  const rationale = typeof raw.rationale === "string" ? raw.rationale.trim().slice(0, 1000) : "";
  if (summary.length < 20) throw new Error("Claude returned an incomplete analyst summary.");
  return { verdict, summary, rationale };
}
