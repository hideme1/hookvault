/**
 * Test Database Helper
 *
 * Creates an in-memory SQLite database with the full Drizzle schema applied,
 * plus helper factories to seed two isolated tenants (userA and userB)
 * with endpoints, sessions, and events.
 */

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import * as schema from "../../src/db/schema.js";
import { encrypt, generateSigningSecret } from "../../src/security/crypto.js";

// Stable test encryption key (64 hex chars = 32 bytes)
export const TEST_ENCRYPTION_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export type TestDb = BetterSQLite3Database<typeof schema>;

// Track active SQLite handles for zero-leak cleanup
const activeHandles = new Set<Database.Database>();

/**
 * Create a fresh in-memory SQLite database with all tables from src/db/schema.ts.
 */
export function createTestDb(): { db: TestDb; sqlite: Database.Database; close: () => void } {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  activeHandles.add(sqlite);

  // Create all tables from schema DDL
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS "user" (
      "id" text PRIMARY KEY NOT NULL,
      "name" text NOT NULL,
      "email" text NOT NULL,
      "emailVerified" integer DEFAULT false NOT NULL,
      "image" text,
      "createdAt" integer NOT NULL,
      "updatedAt" integer NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS "user_email_idx" ON "user" ("email");

    CREATE TABLE IF NOT EXISTS "session" (
      "id" text PRIMARY KEY NOT NULL,
      "expiresAt" integer NOT NULL,
      "token" text NOT NULL,
      "createdAt" integer NOT NULL,
      "updatedAt" integer NOT NULL,
      "ipAddress" text,
      "userAgent" text,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX IF NOT EXISTS "session_token_idx" ON "session" ("token");
    CREATE INDEX IF NOT EXISTS "session_userId_idx" ON "session" ("userId");

    CREATE TABLE IF NOT EXISTS "account" (
      "id" text PRIMARY KEY NOT NULL,
      "accountId" text NOT NULL,
      "providerId" text NOT NULL,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "accessToken" text,
      "refreshToken" text,
      "idToken" text,
      "accessTokenExpiresAt" integer,
      "refreshTokenExpiresAt" integer,
      "scope" text,
      "password" text,
      "createdAt" integer NOT NULL,
      "updatedAt" integer NOT NULL
    );
    CREATE INDEX IF NOT EXISTS "account_userId_idx" ON "account" ("userId");

    CREATE TABLE IF NOT EXISTS "verification" (
      "id" text PRIMARY KEY NOT NULL,
      "identifier" text NOT NULL,
      "value" text NOT NULL,
      "expiresAt" integer NOT NULL,
      "createdAt" integer,
      "updatedAt" integer
    );

    CREATE TABLE IF NOT EXISTS "endpoints" (
      "id" text PRIMARY KEY NOT NULL,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "name" text NOT NULL,
      "publicSlug" text NOT NULL,
      "targetUrl" text NOT NULL,
      "encryptedSecret" text NOT NULL,
      "isActive" integer DEFAULT true NOT NULL,
      "createdAt" integer NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS "endpoints_publicSlug_idx" ON "endpoints" ("publicSlug");
    CREATE INDEX IF NOT EXISTS "endpoints_userId_idx" ON "endpoints" ("userId");
    CREATE INDEX IF NOT EXISTS "endpoints_userId_id_idx" ON "endpoints" ("userId", "id");

    CREATE TABLE IF NOT EXISTS "webhookEvents" (
      "id" text PRIMARY KEY NOT NULL,
      "endpointId" text NOT NULL REFERENCES "endpoints"("id") ON DELETE CASCADE,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "idempotencyKey" text,
      "method" text NOT NULL,
      "headersJson" text NOT NULL,
      "bodyText" text,
      "signatureValid" integer,
      "receivedAt" integer NOT NULL
    );
    CREATE INDEX IF NOT EXISTS "webhookEvents_endpointId_idx" ON "webhookEvents" ("endpointId");
    CREATE INDEX IF NOT EXISTS "webhookEvents_userId_idx" ON "webhookEvents" ("userId");
    CREATE INDEX IF NOT EXISTS "webhookEvents_userId_id_idx" ON "webhookEvents" ("userId", "id");
    CREATE INDEX IF NOT EXISTS "webhookEvents_idempotencyKey_idx" ON "webhookEvents" ("endpointId", "idempotencyKey");

    CREATE TABLE IF NOT EXISTS "deliveryAttempts" (
      "id" text PRIMARY KEY NOT NULL,
      "eventId" text NOT NULL REFERENCES "webhookEvents"("id") ON DELETE CASCADE,
      "endpointId" text NOT NULL REFERENCES "endpoints"("id") ON DELETE CASCADE,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "attemptNumber" integer DEFAULT 1 NOT NULL,
      "statusCode" integer,
      "responseSnippet" text,
      "durationMs" integer,
      "errorCode" text,
      "createdAt" integer NOT NULL
    );
    CREATE INDEX IF NOT EXISTS "deliveryAttempts_eventId_idx" ON "deliveryAttempts" ("eventId");
    CREATE INDEX IF NOT EXISTS "deliveryAttempts_endpointId_idx" ON "deliveryAttempts" ("endpointId");
    CREATE INDEX IF NOT EXISTS "deliveryAttempts_userId_idx" ON "deliveryAttempts" ("userId");
    CREATE INDEX IF NOT EXISTS "deliveryAttempts_userId_id_idx" ON "deliveryAttempts" ("userId", "id");
  `);

  const db = drizzle(sqlite, { schema });
  const closeHandle = () => {
    if (sqlite.open) {
      sqlite.close();
    }
    activeHandles.delete(sqlite);
  };

  return { db, sqlite, close: closeHandle };
}

// ─── Auth Header / Cookie Helpers ─────────────────────────────────────────────

/**
 * Builds standard authenticated request headers with Bearer token & Better Auth cookie.
 */
export function buildAuthHeaders(
  token: string,
  extra?: Record<string, string>
): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Cookie: `better-auth.session_token=${token}`,
    ...extra,
  };
}

// ─── Seed Data Types ───────────────────────────────────────────────────────────

export interface TestTenant {
  user: {
    id: string;
    name: string;
    email: string;
  };
  session: {
    id: string;
    token: string;
  };
  endpoint: {
    id: string;
    publicSlug: string;
    name: string;
    targetUrl: string;
    signingSecret: string; // plaintext for HMAC test assertions
  };
  event?: {
    id: string;
  };
  headers: Record<string, string>;
  cookie: string;
  authHeaders: (extra?: Record<string, string>) => Record<string, string>;
}

export function authHeadersFor(
  tenant: TestTenant | { session?: { token: string }; token?: string } | string,
  extra?: Record<string, string>
): Record<string, string> {
  const token =
    typeof tenant === "string"
      ? tenant
      : "token" in tenant && typeof tenant.token === "string"
      ? tenant.token
      : tenant.session?.token ?? "";
  return buildAuthHeaders(token, extra);
}

export interface SeededTenants {
  userA: TestTenant & { event: { id: string } };
  userB: TestTenant;
}

/**
 * Seed two isolated tenants into an existing Drizzle DB instance.
 * Inserts two isolated users (userA, userB), their active sessions,
 * one endpoint each, and one webhook event for userA.
 */
export function seedTwoTenants(db: TestDb): SeededTenants {
  const now = Math.floor(Date.now() / 1000);
  const futureExpiry = now + 86400; // 24h from now

  // ─── Tenant A ──────────────────────────────────────────────────────
  const userAData = {
    id: "user-a-id",
    name: "Alice",
    email: "alice@example.com",
    emailVerified: false,
    createdAt: new Date(now * 1000),
    updatedAt: new Date(now * 1000),
  };

  const sessionAData = {
    id: "session-a-id",
    token: "token-a-secret",
    expiresAt: new Date(futureExpiry * 1000),
    createdAt: new Date(now * 1000),
    updatedAt: new Date(now * 1000),
    userId: "user-a-id",
  };

  const secretA = generateSigningSecret();
  const endpointAData = {
    id: "endpoint-a-id",
    userId: "user-a-id",
    name: "Alice Webhook",
    publicSlug: "slug-alice",
    targetUrl: "https://alice.example.com/hook",
    encryptedSecret: encrypt(secretA, TEST_ENCRYPTION_KEY),
    isActive: true,
    createdAt: new Date(now * 1000),
  };

  const eventAData = {
    id: "event-a-id",
    endpointId: "endpoint-a-id",
    userId: "user-a-id",
    method: "POST",
    headersJson: JSON.stringify({ "content-type": "application/json" }),
    bodyText: '{"test": "payload-a"}',
    signatureValid: true,
    receivedAt: new Date(now * 1000),
  };

  // ─── Tenant B ──────────────────────────────────────────────────────
  const userBData = {
    id: "user-b-id",
    name: "Bob",
    email: "bob@example.com",
    emailVerified: false,
    createdAt: new Date(now * 1000),
    updatedAt: new Date(now * 1000),
  };

  const sessionBData = {
    id: "session-b-id",
    token: "token-b-secret",
    expiresAt: new Date(futureExpiry * 1000),
    createdAt: new Date(now * 1000),
    updatedAt: new Date(now * 1000),
    userId: "user-b-id",
  };

  const secretB = generateSigningSecret();
  const endpointBData = {
    id: "endpoint-b-id",
    userId: "user-b-id",
    name: "Bob Webhook",
    publicSlug: "slug-bob",
    targetUrl: "https://bob.example.com/hook",
    encryptedSecret: encrypt(secretB, TEST_ENCRYPTION_KEY),
    isActive: true,
    createdAt: new Date(now * 1000),
  };

  // Insert seed rows
  db.insert(schema.user).values(userAData).run();
  db.insert(schema.user).values(userBData).run();
  db.insert(schema.session).values(sessionAData).run();
  db.insert(schema.session).values(sessionBData).run();
  db.insert(schema.endpoints).values(endpointAData).run();
  db.insert(schema.endpoints).values(endpointBData).run();
  db.insert(schema.webhookEvents).values(eventAData).run();

  const userA: TestTenant & { event: { id: string } } = {
    user: { id: userAData.id, name: userAData.name, email: userAData.email },
    session: { id: sessionAData.id, token: sessionAData.token },
    endpoint: {
      id: endpointAData.id,
      publicSlug: endpointAData.publicSlug,
      name: endpointAData.name,
      targetUrl: endpointAData.targetUrl,
      signingSecret: secretA,
    },
    event: { id: eventAData.id },
    headers: buildAuthHeaders(sessionAData.token),
    cookie: `better-auth.session_token=${sessionAData.token}`,
    authHeaders: (extra) => buildAuthHeaders(sessionAData.token, extra),
  };

  const userB: TestTenant = {
    user: { id: userBData.id, name: userBData.name, email: userBData.email },
    session: { id: sessionBData.id, token: sessionBData.token },
    endpoint: {
      id: endpointBData.id,
      publicSlug: endpointBData.publicSlug,
      name: endpointBData.name,
      targetUrl: endpointBData.targetUrl,
      signingSecret: secretB,
    },
    headers: buildAuthHeaders(sessionBData.token),
    cookie: `better-auth.session_token=${sessionBData.token}`,
    authHeaders: (extra) => buildAuthHeaders(sessionBData.token, extra),
  };

  return { userA, userB };
}

/**
 * Closes an SQLite database handle, or all active handles if no argument is passed.
 * Ensures zero open handles in afterEach / afterAll.
 */
export function close(
  target?: Database.Database | { sqlite?: Database.Database; close?: () => void }
): void {
  if (target) {
    if ("close" in target && typeof target.close === "function" && !("sqlite" in target)) {
      const db = target as Database.Database;
      if (db.open) db.close();
      activeHandles.delete(db);
    } else if ("sqlite" in target && target.sqlite) {
      if (target.sqlite.open) target.sqlite.close();
      activeHandles.delete(target.sqlite);
    }
  } else {
    for (const handle of activeHandles) {
      if (handle.open) {
        handle.close();
      }
    }
    activeHandles.clear();
  }
}

export interface SeededDb extends SeededTenants {
  db: TestDb;
  sqlite: Database.Database;
  close: () => void;
}

/**
 * Convenience helper combining createTestDb() and seedTwoTenants().
 */
export function seedTestDb(): SeededDb {
  const { db, sqlite, close: closeDb } = createTestDb();
  const tenants = seedTwoTenants(db);
  return {
    db,
    sqlite,
    close: closeDb,
    ...tenants,
  };
}
