import type Database from "better-sqlite3";

/**
 * Initializes all required tables and indexes if they do not exist.
 * Keeps schema in sync with src/db/schema.ts.
 */
export function initDatabaseTables(sqlite: Database.Database): void {
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
}
