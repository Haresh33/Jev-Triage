/**
 * SQLite database (a single file under DATA_DIR) with the app's SQL migrations from `drizzle/`.
 * Migrations run at startup, in file-name order, each exactly once.
 */

import { Database } from "bun:sqlite";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { drizzle } from "drizzle-orm/bun-sqlite";
import type { Db } from "./platform";
import * as schema from "./schema";

const MIGRATIONS_DIR = resolve(import.meta.dir, "../../drizzle");

export function openDatabase(path: string): { db: Db; sqlite: Database } {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const sqlite = new Database(path, { create: true, strict: true });
  sqlite.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  migrate(sqlite);
  return { db: drizzle(sqlite, { schema }), sqlite };
}

function migrate(sqlite: Database): void {
  sqlite.exec("CREATE TABLE IF NOT EXISTS __migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)");
  const applied = new Set(sqlite.query<{ name: string }, []>("SELECT name FROM __migrations").all().map((r) => r.name));
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    if (applied.has(file)) continue;
    const statements = readFileSync(join(MIGRATIONS_DIR, file), "utf8").split("--> statement-breakpoint").map((s) => s.trim()).filter(Boolean);
    sqlite.transaction(() => {
      for (const statement of statements) sqlite.exec(statement);
      sqlite.query("INSERT INTO __migrations (name, applied_at) VALUES (?, ?)").run(file, Date.now());
    })();
  }
}
