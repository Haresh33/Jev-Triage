/**
 * The reviewer AI: the model used for second opinions, audits of benign closures and `bun run review`.
 * Jev makes every triage call; this model only works in the warm and cold loops (or, in tiebreak mode, settles
 * cases Jev couldn't).
 *
 * Any model works through one of two request formats:
 *   - "anthropic": the Anthropic Messages API (Claude).
 *   - "openai":    the OpenAI Chat Completions API, which most providers also offer: OpenAI, Azure OpenAI,
 *                  Google Gemini (…/v1beta/openai), OpenRouter, Mistral, Groq, Together, and local servers such
 *                  as Ollama, vLLM or LM Studio.
 *
 * Every request asks for structured output through a forced tool (function) call; if a model answers with plain
 * JSON text instead, that's accepted too.
 */

import type { ProviderResponse } from "./platform";

export type AiProvider = "anthropic" | "openai";
export type AiSettings = { provider: AiProvider; apiKey: string | undefined; baseUrl: string; models: string[]; configured: boolean };
export type ToolPrompt = { system: string; user: string; tool: { name: string; description: string; input_schema: unknown }; maxTokens: number };

const UA = "jev-triage/1.0";
const MAX_RESPONSE_BYTES = 1_500_000;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const elapsed = (started: number) => Math.max(0, Math.round(performance.now() - started));

async function postJson(url: string, headers: Record<string, string>, body: unknown, timeoutMs: number): Promise<{ status: number; body: unknown }> {
  try {
    const res = await fetch(url, { method: "POST", redirect: "error", signal: AbortSignal.timeout(timeoutMs), headers: { "Content-Type": "application/json", Accept: "application/json", "User-Agent": UA, ...headers }, body: JSON.stringify(body) });
    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) return { status: 0, body: null };
    let parsed: unknown = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
    return { status: res.status, body: parsed };
  } catch {
    return { status: 0, body: null };
  }
}

/** A JSON object from a model's text answer (tolerates ```json fences and text around the object). */
export function jsonFromText(text: string): Record<string, unknown> | null {
  const t = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  for (const candidate of [t, t.slice(t.indexOf("{"), t.lastIndexOf("}") + 1)]) {
    try { const v: unknown = JSON.parse(candidate); if (isRecord(v)) return v; } catch { /* try the next form */ }
  }
  return null;
}

type Attempt = { status: number; input: Record<string, unknown> | null; retryPlain?: boolean };

async function anthropicAttempt(ai: AiSettings, model: string, p: ToolPrompt): Promise<Attempt> {
  const { status, body } = await postJson(`${ai.baseUrl}/v1/messages`, { "x-api-key": ai.apiKey ?? "", "anthropic-version": "2023-06-01" },
    { model, max_tokens: p.maxTokens, temperature: 0, system: p.system, messages: [{ role: "user", content: p.user }], tools: [p.tool], tool_choice: { type: "tool", name: p.tool.name } }, 90_000);
  if (status !== 200 || !isRecord(body) || !Array.isArray(body.content)) return { status, input: null };
  const block = body.content.find((b: unknown) => isRecord(b) && b.type === "tool_use" && b.name === p.tool.name);
  if (isRecord(block) && isRecord(block.input)) return { status, input: block.input };
  const text = body.content.filter((b: unknown) => isRecord(b) && b.type === "text").map((b) => String((b as Record<string, unknown>).text ?? "")).join("\n");
  return { status, input: jsonFromText(text) };
}

async function openaiAttempt(ai: AiSettings, model: string, p: ToolPrompt, newStyle: boolean): Promise<Attempt> {
  const azure = /\.openai\.azure\.com$/i.test(new URL(ai.baseUrl).hostname);
  const headers: Record<string, string> = ai.apiKey ? (azure ? { "api-key": ai.apiKey } : { Authorization: `Bearer ${ai.apiKey}` }) : {};
  // Newer OpenAI reasoning models take max_completion_tokens and no temperature; most other servers take max_tokens.
  const limits = newStyle ? { max_completion_tokens: p.maxTokens * 4 } : { max_tokens: p.maxTokens, temperature: 0 };
  const { status, body } = await postJson(`${ai.baseUrl}/chat/completions`, headers, {
    model, ...limits,
    messages: [{ role: "system", content: `${p.system}\n\nAnswer by calling ${p.tool.name}. If you cannot call tools, reply with only the JSON object for its arguments.` }, { role: "user", content: p.user }],
    tools: [{ type: "function", function: { name: p.tool.name, description: p.tool.description, parameters: p.tool.input_schema } }],
    tool_choice: { type: "function", function: { name: p.tool.name } },
  }, 90_000);
  if (status === 400 && !newStyle) {
    const message = JSON.stringify(body ?? "").toLowerCase();
    if (message.includes("max_completion_tokens") || message.includes("temperature")) return { status, input: null, retryPlain: true };
  }
  if (status !== 200 || !isRecord(body) || !Array.isArray(body.choices)) return { status, input: null };
  const message = isRecord(body.choices[0]) && isRecord(body.choices[0].message) ? body.choices[0].message : null;
  if (!message) return { status, input: null };
  // Only one tool is offered, so a call under a slightly different name is still its answer.
  const calls = Array.isArray(message.tool_calls) ? message.tool_calls.filter((c: unknown) => isRecord(c) && isRecord(c.function)) : [];
  const call = calls.find((c) => (c as { function: { name?: unknown } }).function.name === p.tool.name) ?? calls[0];
  if (isRecord(call) && isRecord(call.function)) {
    const args = call.function.arguments;
    if (isRecord(args)) return { status, input: args };
    if (typeof args === "string") return { status, input: jsonFromText(args) };
  }
  return { status, input: typeof message.content === "string" ? jsonFromText(message.content) : null };
}

/**
 * One structured request to the reviewer AI. Tries each model in AI_MODEL in turn, moving on only when a model is
 * unknown or unavailable (400/404). Never throws.
 */
export async function aiTool(ai: AiSettings, prompt: ToolPrompt): Promise<ProviderResponse & { model?: string }> {
  const started = performance.now();
  const fail = (error: string): ProviderResponse => ({ ok: false, dataJson: null, error, durationMs: elapsed(started) });
  if (!ai.configured) return fail("No reviewer AI is configured (set AI_API_KEY, or ANTHROPIC_API_KEY).");
  let lastStatus = 0;
  for (const [index, model] of ai.models.entries()) {
    let a = ai.provider === "anthropic" ? await anthropicAttempt(ai, model, prompt) : await openaiAttempt(ai, model, prompt, false);
    if (a.retryPlain) a = await openaiAttempt(ai, model, prompt, true);
    lastStatus = a.status;
    if (a.status === 200) return a.input ? { ok: true, dataJson: JSON.stringify(a.input), error: null, durationMs: elapsed(started), model } : fail("The reviewer AI returned an unreadable response.");
    if (!(a.status === 400 || a.status === 404) || index === ai.models.length - 1) break;
  }
  return fail(lastStatus === 401 || lastStatus === 403 ? "Reviewer AI authentication failed. Check AI_API_KEY."
    : lastStatus === 429 ? "Reviewer AI rate limit reached." : lastStatus === 0 ? "The reviewer AI could not be reached or timed out."
    : lastStatus >= 500 ? `Reviewer AI service error (${lastStatus}).` : `Reviewer AI request failed (${lastStatus}).`);
}

export const describeAi = (ai: AiSettings) => `${ai.models[0] ?? "?"} via ${ai.provider === "anthropic" ? "Anthropic" : new URL(ai.baseUrl).host}`;
