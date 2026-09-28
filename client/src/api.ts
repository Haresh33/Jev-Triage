// Typed client for the server's actions. Types come straight from `server/src/actions.ts` (type-only import,
// so no server code reaches the browser). Each call is POST /api/<action> with a JSON body.

import type { z } from "zod";
import type { Actions } from "../../server/src/actions";

type ActionMap = typeof Actions;
type Client = { [K in keyof ActionMap]: (args: z.input<ActionMap[K]["request"]>) => Promise<z.infer<ActionMap[K]["response"]>> };

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

async function call(action: string, args: unknown): Promise<unknown> {
  const res = await fetch(`./api/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(args ?? {}),
    credentials: "same-origin",
  });
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const message = body && typeof body === "object" && "error" in body && typeof body.error === "string" ? body.error : `Request failed (${res.status}).`;
    throw new ApiError(message, res.status);
  }
  return body;
}

export const api = new Proxy({} as Client, { get: (_t, action: string) => (args: unknown) => call(action, args) });

export type ApiRequest<C, K extends keyof C> = C[K] extends (args: infer A) => Promise<unknown> ? A : never;
export type ApiResponse<C, K extends keyof C> = C[K] extends (...args: never[]) => Promise<infer R> ? R : never;
