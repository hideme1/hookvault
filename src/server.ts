import { serve } from "@hono/node-server";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import * as schema from "./db/schema.js";
import { initDatabaseTables } from "./db/init.js";
import { createApp } from "./app.js";

const PORT = Number(
  process.env["PORT"] || (process.env["NODE_ENV"] === "production" ? 3000 : 3001)
);
const dataDir = path.resolve(process.cwd(), "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, "hookvault.db");
const sqlite = new Database(dbPath);
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

// Ensure all schema tables and indexes exist
initDatabaseTables(sqlite);

const db = drizzle(sqlite, { schema });
const app = createApp({ db });

console.log(`HookVault API running on http://localhost:${PORT}`);

serve({
  fetch: app.fetch,
  port: PORT,
});
