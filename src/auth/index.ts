/**
 * Better Auth configuration wired to Drizzle SQLite adapter.
 * Ref: AGENTS.md §1 & §2.4
 */

import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import * as schema from "../db/schema.js";

export function createAuth(db: any) {
  return betterAuth({
    database: drizzleAdapter(db, {
      provider: "sqlite",
      schema: {
        user: schema.user,
        session: schema.session,
        account: schema.account,
        verification: schema.verification,
      },
    }),
    emailAndPassword: {
      enabled: true,
    },
    secret:
      process.env["BETTER_AUTH_SECRET"] ??
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    baseURL: process.env["BETTER_AUTH_URL"] ?? "http://localhost:3000",
    trustedOrigins: [
      process.env["FRONTEND_ORIGIN"] || "http://localhost:5173",
      "http://localhost:3001",
      "http://localhost:3000",
    ],
  });
}

export type Auth = ReturnType<typeof createAuth>;
