# HookVault — Security Audit Report

**Date:** November 2026  
**Auditor:** Automated Red-Team Security Suite & Static Analysis  
**Repository:** `hookvault`  
**Test Suite:** 115 passing tests across 8 suites (100% pass rate)  
**Target Invariants:** `AGENTS.md` & `THREAT_MODEL.md` (OWASP API Security Top 10 2023)

---

## 1. Executive Summary

HookVault was built under a **non-linear, security-first methodology**: the threat model and red-team exploit suite were written and verified to fail before any application routes or UI logic were implemented.

This audit report verifies that all 7 non-negotiable security invariants defined in `AGENTS.md` are actively enforced in source code, verified by 115 automated Vitest tests, and confirmed via static code hygiene scanning.

---

## 2. Invariant Verification Matrix

| # | Invariant | Implementation Location | Test Suite | Status |
|---|-----------|-------------------------|------------|:------:|
| 1 | **Deny-by-Default Multi-Tenancy (BOLA/IDOR)** | `src/routes/endpoints.ts`<br>`src/routes/events.ts`<br>`src/db/schema.ts` | `tests/security/idor.test.ts` (13 tests) | **PASSED** |
| 2 | **SSRF Defense on Outbound Requests** | `src/security/ssrf.ts` (`validateUrl`, `safeFetch`) | `tests/security/ssrf.test.ts` (37 tests) | **PASSED** |
| 3 | **Timing-Safe Cryptography & HMAC** | `src/security/crypto.ts` (`verifySignature`, `timingSafeEqual`) | `tests/security/hmac.test.ts` (24 tests)<br>`tests/security/replay.test.ts` (4 tests) | **PASSED** |
| 4 | **Anti-Mass Assignment & Strict Schemas** | `src/contracts/schemas.ts` (`.strict()`, serializers) | `tests/security/massAssignment.test.ts` (12 tests) | **PASSED** |
| 5 | **Payload Stream Caps & Ingestion DoS** | `src/routes/ingest.ts`<br>`src/security/rateLimiter.ts` | `tests/security/payload.test.ts` (4 tests)<br>`tests/security/rateLimit.test.ts` (11 tests) | **PASSED** |
| 6 | **Zero-Leakage Error Handling** | `src/app.ts` (`onError`, `notFound`) | `tests/security/headersAndErrors.test.ts` (10 tests) | **PASSED** |
| 7 | **Strict Security Headers & Ingestion Sanitization** | `src/app.ts` (`secureHeaders`)<br>`src/routes/ingest.ts` (`SENSITIVE_HEADERS`) | `tests/security/headersAndErrors.test.ts` (10 tests) | **PASSED** |

---

## 3. Deep-Dive Invariant Analysis

### Invariant 1: Deny-by-Default Multi-Tenancy (BOLA/IDOR)
- **Requirement:** Every database query on `endpoints`, `webhookEvents`, or `deliveryAttempts` must include `and(eq(table.id, id), eq(table.userId, session.user.id))`. Never query by resource `id` alone.
- **Verification:**
  - Audited `src/routes/endpoints.ts` and `src/routes/events.ts`. All `select`, `update`, and `delete` operations bind both `id` and `user.id`.
  - Database schema (`src/db/schema.ts`) enforces composite indexes on `(userId, id)` for efficient tenant-isolated index scans.
  - Foreign tenants attempting to read, update, delete, or replay resources receive `404 Not Found` (never `403 Forbidden`) to prevent resource enumeration.
- **Evidence:** 13/13 IDOR tests passing.

### Invariant 2: SSRF Defense Chain
- **Requirement:** Block non-`https:` protocols, loopback (`127.0.0.0/8`), RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`), IPv6 local/mapped (`::1`, `fc00::/7`, `fe80::/10`), DNS rebinding, manual redirect chasing, with a 5s hard timeout and 64 KB response body cap.
- **Verification:**
  - `src/security/ssrf.ts` parses hostname, performs DNS resolution (`dns.promises.lookup` with `all: true`), and validates all returned IPv4 and IPv6 addresses against exact CIDR bitmask algorithms before executing any HTTP request.
  - Inbound HTTP redirects are blocked via `redirect: "manual"` to prevent 301/302 hops into internal networks.
  - Response stream is terminated at 64 KB via custom chunk reader with `reader.cancel()`.
- **Evidence:** 37/37 SSRF tests passing across all IPv4/IPv6 edge cases, redirect scenarios, and timeout/size caps.

### Invariant 3: Timing-Safe Cryptography
- **Requirement:** All webhook HMAC-SHA256 signature comparisons must use `crypto.timingSafeEqual` on equal-length Buffers. Endpoint signing secrets must be generated with `crypto.randomBytes(32)` and encrypted at rest with AES-256-GCM.
- **Verification:**
  - `src/security/crypto.ts` checks buffer length equality prior to calling `timingSafeEqual` to avoid thrown exceptions.
  - AES-256-GCM uses a 12-byte IV and 16-byte authentication tag per encrypted payload.
  - Replay timestamps enforce a strict $\pm 5$ minute tolerance window.
- **Evidence:** 24/24 HMAC tests and 4/4 replay tests passing.

### Invariant 4: Anti-Mass Assignment & Output Serializers
- **Requirement:** All Zod input schemas must use `.strict()`. Responses must pass through explicit output DTO serializers.
- **Verification:**
  - `createEndpointSchema`, `updateEndpointSchema`, and `replayEventSchema` all invoke `.strict()`. Injected keys (`userId`, `role`, `encryptedSecret`, `createdAt`) are rejected with `400 Bad Request`.
  - `serializeEndpoint`, `serializeEvent`, and `serializeDelivery` allowlist only public-safe fields, completely omitting `encryptedSecret` and `userId`.
- **Evidence:** 12/12 mass assignment tests passing.

### Invariant 5: Inbound Stream Caps & Sensitive Header Sanitization
- **Requirement:** 256 KB hard limit on inbound webhook body stream before JSON parsing or DB writes. Strip sensitive headers before persistence or egress.
- **Verification:**
  - `src/routes/ingest.ts` inspects `Content-Length` and enforces an early stream abort if exceeded.
  - Inbound headers are sanitized against `SENSITIVE_HEADERS = new Set(["cookie", "authorization", "proxy-authorization", "set-cookie"])` case-insensitively before storing in `headersJson` and before forwarding outbound via `safeFetch()`.
- **Evidence:** 4/4 payload tests and 10/10 header/error tests passing.

### Invariant 6 & 7: Error Leakage & Security Headers
- **Requirement:** Structured `{ error: { code, message } }` JSON responses only. No stack traces, file paths, or raw SQLite messages. Global security headers.
- **Verification:**
  - Global `onError` in `src/app.ts` sanitizes all exceptions.
  - `secureHeaders` middleware applies `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and strict `Content-Security-Policy`.
- **Evidence:** 10/10 header and error tests passing.

---

## 4. Vitest Security Test Breakdown

```
Test Files  8 passed (8)
     Tests  115 passed (115)
  Duration  ~6.3s

Suite Breakdown:
  - tests/security/ssrf.test.ts              37 passed
  - tests/security/hmac.test.ts              24 passed
  - tests/security/idor.test.ts              13 passed
  - tests/security/massAssignment.test.ts    12 passed
  - tests/security/rateLimit.test.ts         11 passed
  - tests/security/headersAndErrors.test.ts  10 passed
  - tests/security/replay.test.ts             4 passed
  - tests/security/payload.test.ts            4 passed
```

---

## 5. Dependency & Static Code Hygiene Audit

### `npm audit` Summary
- **Frontend (`web/`):** 0 vulnerabilities (`found 0 vulnerabilities`).
- **Root Production Dependencies (`--omit=dev`):**
  - Production runtime dependencies (`hono`, `@hono/node-server`, `better-auth`, `better-sqlite3`, `drizzle-orm`) have **0 known vulnerabilities**.
  - Zod GHSA advisory (GHSA-mrhx-c7xc-m3w5 regarding unbounded collection memory exhaustion): **False Positive / Non-Applicable** to HookVault. All schemas validate strictly bounded scalar fields with `.strict()`, and an upstream 256 KB stream limit aborts large payloads before Zod parsing occurs.
  - Dev dependencies (`vitest`, `drizzle-kit` dev loaders): Vitest/esbuild dev-server advisories apply only to local test/migration runners and are never bundled or executed in production containers.

### Static Code Analysis
- **Hardcoded Secrets:** Zero instances in `src/` and `web/src/`. Key fallback defaults are restricted to test environments; production requires `ENCRYPTION_KEY`.
- **XSS & DOM Injection:** Zero occurrences of `dangerouslySetInnerHTML`.
- **SQL Injection:** Zero raw SQL string interpolation. All DDL statements in `src/db/init.ts` use static statements; all DML operations use Drizzle ORM parameterized query builders.
- **Information Leakage:** Zero `console.log` statements outputting signing secrets, session tokens, or raw request payloads.

---

## 6. Production Hardening Roadmap (Scale Readiness)

Before deploying HookVault to multi-instance cloud environments with high concurrency, the following architectural upgrades are recommended:

1. **Distributed Rate Limiting (Redis / Upstash):**
   - *Current:* High-performance in-memory sliding window rate limiter (`src/security/rateLimiter.ts`).
   - *Production Scale:* In multi-replica container clusters behind an ALB, replace in-memory timestamps with a distributed Redis sliding-window implementation using atomic Lua scripts.

2. **Durable Asynchronous Outbound Delivery Queue:**
   - *Current:* Synchronous outbound delivery via `safeFetch()` with a 5-second timeout during ingestion.
   - *Production Scale:* Ingest payloads immediately (returning `202 Accepted`), enqueue jobs to BullMQ or Cloudflare Queues, and process outbound deliveries via dedicated worker pools with exponential backoff and dead-letter queues.

3. **Cloud Database Replication (Cloudflare D1 / Turso):**
   - *Current:* Local embedded SQLite via `better-sqlite3` with WAL mode.
   - *Production Scale:* HookVault's Drizzle schema was architected to be 100% compatible with Cloudflare D1 and Turso/libSQL. Point the Drizzle client to a distributed edge database for global read/write replication.

4. **KMS / Hardware Security Module (HSM) Secret Storage:**
   - *Current:* Local AES-256-GCM symmetric encryption using an environment variable key.
   - *Production Scale:* Connect endpoint secret encryption to AWS KMS, Google Cloud KMS, or HashiCorp Vault for automated envelope encryption, audit logging, and zero-downtime key rotation.
