import { sqliteTable, text, integer, index, uniqueIndex } from "drizzle-orm/sqlite-core";

// ─── Better Auth Core Tables ───────────────────────────────────────────────────
// These follow Better Auth's expected schema for SQLite.
// Ref: https://www.better-auth.com/docs/installation#database

export const user = sqliteTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  emailVerified: integer("emailVerified", { mode: "boolean" }).notNull().default(false),
  image: text("image"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull(),
}, (table) => [
  uniqueIndex("user_email_idx").on(table.email),
]);

export const session = sqliteTable("session", {
  id: text("id").primaryKey(),
  expiresAt: integer("expiresAt", { mode: "timestamp" }).notNull(),
  token: text("token").notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull(),
  ipAddress: text("ipAddress"),
  userAgent: text("userAgent"),
  userId: text("userId").notNull().references(() => user.id, { onDelete: "cascade" }),
}, (table) => [
  uniqueIndex("session_token_idx").on(table.token),
  index("session_userId_idx").on(table.userId),
]);

export const account = sqliteTable("account", {
  id: text("id").primaryKey(),
  accountId: text("accountId").notNull(),
  providerId: text("providerId").notNull(),
  userId: text("userId").notNull().references(() => user.id, { onDelete: "cascade" }),
  accessToken: text("accessToken"),
  refreshToken: text("refreshToken"),
  idToken: text("idToken"),
  accessTokenExpiresAt: integer("accessTokenExpiresAt", { mode: "timestamp" }),
  refreshTokenExpiresAt: integer("refreshTokenExpiresAt", { mode: "timestamp" }),
  scope: text("scope"),
  password: text("password"),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp" }).notNull(),
}, (table) => [
  index("account_userId_idx").on(table.userId),
]);

export const verification = sqliteTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: integer("expiresAt", { mode: "timestamp" }).notNull(),
  createdAt: integer("createdAt", { mode: "timestamp" }),
  updatedAt: integer("updatedAt", { mode: "timestamp" }),
});

// ─── HookVault Domain Tables ───────────────────────────────────────────────────

export const endpoints = sqliteTable("endpoints", {
  id: text("id").primaryKey(), // nanoid or uuid
  userId: text("userId").notNull().references(() => user.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  publicSlug: text("publicSlug").notNull(),
  targetUrl: text("targetUrl").notNull(),
  /** AES-256-GCM encrypted signing secret (base64: iv:ciphertext:authTag) */
  encryptedSecret: text("encryptedSecret").notNull(),
  isActive: integer("isActive", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
}, (table) => [
  uniqueIndex("endpoints_publicSlug_idx").on(table.publicSlug),
  index("endpoints_userId_idx").on(table.userId),
  index("endpoints_userId_id_idx").on(table.userId, table.id),
]);

export const webhookEvents = sqliteTable("webhookEvents", {
  id: text("id").primaryKey(),
  endpointId: text("endpointId").notNull().references(() => endpoints.id, { onDelete: "cascade" }),
  userId: text("userId").notNull().references(() => user.id, { onDelete: "cascade" }),
  idempotencyKey: text("idempotencyKey"), // optional, for dedup
  method: text("method").notNull(), // GET, POST, PUT, etc.
  headersJson: text("headersJson").notNull(), // JSON-serialized headers
  bodyText: text("bodyText"), // raw body (capped at 256 KB on ingestion)
  signatureValid: integer("signatureValid", { mode: "boolean" }),
  receivedAt: integer("receivedAt", { mode: "timestamp" }).notNull(),
}, (table) => [
  index("webhookEvents_endpointId_idx").on(table.endpointId),
  index("webhookEvents_userId_idx").on(table.userId),
  index("webhookEvents_userId_id_idx").on(table.userId, table.id),
  index("webhookEvents_idempotencyKey_idx").on(table.endpointId, table.idempotencyKey),
]);

export const deliveryAttempts = sqliteTable("deliveryAttempts", {
  id: text("id").primaryKey(),
  eventId: text("eventId").notNull().references(() => webhookEvents.id, { onDelete: "cascade" }),
  endpointId: text("endpointId").notNull().references(() => endpoints.id, { onDelete: "cascade" }),
  userId: text("userId").notNull().references(() => user.id, { onDelete: "cascade" }),
  attemptNumber: integer("attemptNumber").notNull().default(1),
  statusCode: integer("statusCode"), // null if network error
  responseSnippet: text("responseSnippet"), // first 512 chars of response body
  durationMs: integer("durationMs"),
  errorCode: text("errorCode"), // e.g., "TIMEOUT", "SSRF_BLOCKED", "DNS_FAILURE"
  createdAt: integer("createdAt", { mode: "timestamp" }).notNull(),
}, (table) => [
  index("deliveryAttempts_eventId_idx").on(table.eventId),
  index("deliveryAttempts_endpointId_idx").on(table.endpointId),
  index("deliveryAttempts_userId_idx").on(table.userId),
  index("deliveryAttempts_userId_id_idx").on(table.userId, table.id),
]);
