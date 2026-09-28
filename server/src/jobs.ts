/**
 * Background job queue, stored in the database so a restart does not lose queued investigations.
 * A small worker loop picks queued jobs (oldest first) and runs the matching action handler.
 *
 * Safety: the actions themselves check `runVersion`, so a job for a superseded run, or one re-run after a
 * crash, never overwrites newer results.
 */

import { and, asc, eq, lt } from "drizzle-orm";
import type { Memory } from "./memory";
import type { Ctx, Db, JobKind, JobQueue, Services } from "./platform";
import * as schema from "./schema";

type Handlers = Record<JobKind, (ctx: Ctx, args: unknown) => Promise<unknown>>;

export function createJobQueue(db: Db): JobQueue {
  return {
    async enqueue(kind, args, viewerId) {
      try {
        const id = crypto.randomUUID(); const now = new Date();
        await db.insert(schema.jobs).values({ id, kind, argsJson: JSON.stringify(args), viewerId, status: "queued", attempts: 0, createdAt: now, updatedAt: now });
        return { ok: true, id };
      } catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : "The job could not be queued." };
      }
    },
  };
}

export type Worker = { stop(): Promise<void>; drain(): Promise<void> };

/**
 * Runs queued jobs with limited concurrency. Jobs left "running" by a crash are put back in the queue once.
 * `makeCtx` builds the context for the job's owner, so owner-scoped reads behave as they did for the user.
 */
export function startWorker(opts: { db: Db; services: Services; queue: JobQueue; handlers: Handlers; concurrency: number; pollMs?: number; log?: (msg: string) => void; getMemory?: () => Memory }): Worker {
  const { db, handlers, concurrency } = opts;
  const pollMs = opts.pollMs ?? 500;
  const log = opts.log ?? ((m: string) => console.log(m));
  let active = 0; let stopped = false;
  const running = new Set<Promise<void>>();

  // Crash recovery: anything marked running when the process stopped goes back to the queue (at most one retry).
  db.update(schema.jobs).set({ status: "queued", updatedAt: new Date() }).where(and(eq(schema.jobs.status, "running"), lt(schema.jobs.attempts, 2))).run();
  db.update(schema.jobs).set({ status: "failed", error: "Stopped twice while running.", updatedAt: new Date() }).where(eq(schema.jobs.status, "running")).run();

  async function claim(): Promise<typeof schema.jobs.$inferSelect | null> {
    const next = db.select().from(schema.jobs).where(eq(schema.jobs.status, "queued")).orderBy(asc(schema.jobs.createdAt)).limit(1).get();
    if (!next) return null;
    // Only one worker wins the row (SQLite serialises writes).
    const won = db.update(schema.jobs).set({ status: "running", attempts: next.attempts + 1, updatedAt: new Date() }).where(and(eq(schema.jobs.id, next.id), eq(schema.jobs.status, "queued"))).returning({ id: schema.jobs.id }).all();
    return won.length === 1 ? { ...next, attempts: next.attempts + 1 } : null;
  }

  async function runJob(job: typeof schema.jobs.$inferSelect): Promise<void> {
    const ctx: Ctx = { db: () => db, viewer: { id: job.viewerId }, services: opts.services, jobs: opts.queue, memory: opts.getMemory?.() };
    try {
      await handlers[job.kind](ctx, JSON.parse(job.argsJson));
      db.update(schema.jobs).set({ status: "done", error: null, updatedAt: new Date() }).where(eq(schema.jobs.id, job.id)).run();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Job failed.";
      log(`[jobs] ${job.kind} ${job.id} failed: ${message}`);
      db.update(schema.jobs).set({ status: "failed", error: message.slice(0, 500), updatedAt: new Date() }).where(eq(schema.jobs.id, job.id)).run();
    }
  }

  const timer = setInterval(async () => {
    if (stopped) return;
    while (active < concurrency) {
      const job = await claim();
      if (!job) break;
      active += 1;
      const p = runJob(job).finally(() => { active -= 1; running.delete(p); });
      running.add(p);
    }
  }, pollMs);

  return {
    async stop() { stopped = true; clearInterval(timer); await Promise.allSettled([...running]); },
    /** Waits until the queue is empty and nothing is running (used by tests). */
    async drain() {
      for (;;) {
        const pending = db.select().from(schema.jobs).where(eq(schema.jobs.status, "queued")).limit(1).get();
        if (!pending && active === 0) return;
        await Bun.sleep(50);
      }
    },
  };
}
