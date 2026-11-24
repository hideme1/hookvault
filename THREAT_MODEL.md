# HookVault — Threat Model

> Mapped against the **OWASP API Security Top 10 (2023)**, with HookVault-specific
> attack scenarios, mitigations, and the exact files/tests that enforce each control.

---

## 1. BOLA / IDOR (Broken Object-Level Authorization)

**OWASP:** API1:2023 — Broken Object-Level Authorization

**Threat:** An authenticated user crafts API requests to access or modify endpoints,
webhook events, or delivery attempts belonging to another user by guessing or
enumerating resource IDs.

**Attack Scenarios:**
- `GET /api/endpoints/:id` with another user's endpoint ID
- `POST /api/events/:id/replay` targeting another user's event
- `DELETE /api/endpoints/:id` on a resource the caller doesn't own

**Mitigation (Deny-by-Default Multi-Tenancy):**
Every database query on `endpoints`, `webhookEvents`, and `deliveryAttempts` MUST include
`AND userId = session.user.id` alongside the resource `id`. Queries by resource ID alone
are **forbidden**.

| File | Purpose |
|------|---------|
| `src/db/schema.ts` | Composite index `(userId, id)` on all domain tables to enforce & optimize scoped queries |
| `src/contracts/schemas.ts` | Output DTOs never expose `userId` to prevent enumeration |
| `tests/security/idor.test.ts` | *(Phase 2)* Cross-tenant access attempts return 404 (not 403, to prevent enumeration) |

---

## 2. SSRF via Webhook Target URLs

**OWASP:** API7:2023 — Server-Side Request Forgery

**Threat:** An attacker registers a webhook endpoint with a `targetUrl` pointing to
internal infrastructure (cloud metadata services, localhost, internal APIs).

**Attack Scenarios:**
- `targetUrl = "http://169.254.169.254/latest/meta-data/"` (AWS metadata)
- `targetUrl = "http://127.0.0.1:6379/"` (local Redis)
- `targetUrl = "https://evil.com"` that 301-redirects to `http://10.0.0.1/admin`
- DNS rebinding: hostname resolves to public IP first, then internal IP on delivery

**Mitigation (Full SSRF Defense Chain):**
1. **Protocol allowlist:** `https://` only (allow `http://` only if `ALLOW_LOCAL_TARGETS=true`)
2. **DNS resolution + IP validation:** Resolve hostname, block all private/reserved IPv4 & IPv6 ranges
3. **Redirect blocking:** `redirect: 'manual'` — never follow 301/302
4. **Resource caps:** 5s timeout, 64 KB response body limit

| File | Purpose |
|------|---------|
| `src/security/ssrf.ts` | `validateUrl()` — protocol check, DNS resolution, CIDR blocking |
| `src/security/ssrf.ts` | `safeFetch()` — `redirect: 'manual'`, 5s timeout, 64 KB cap |
| `src/security/ssrf.ts` | `isBlockedIPv4()`, `isBlockedIPv6()` — CIDR range checkers |
| `tests/security/ssrf.test.ts` | *(Phase 2)* Tests for each blocked range, redirect blocking, timeout, body cap |

---

## 3. Mass Assignment

**OWASP:** API6:2023 — Unrestricted Access to Sensitive Business Flows / API3:2023 — Broken Object Property Level Authorization

**Threat:** Attacker sends extra fields in API requests (`userId`, `role`, `plan`,
`encryptedSecret`, `createdAt`) to escalate privileges or corrupt data.

**Attack Scenarios:**
- `POST /api/endpoints` with `{ "name": "hook", "targetUrl": "...", "userId": "admin-id" }`
- `PATCH /api/endpoints/:id` with `{ "encryptedSecret": "attacker-controlled" }`
- Any request including `createdAt`, `id`, `publicSlug` in the body

**Mitigation (Strict Zod Schemas):**
Every input schema uses `.strict()` — unknown fields cause an immediate `400 Bad Request`.

| File | Purpose |
|------|---------|
| `src/contracts/schemas.ts` | `createEndpointSchema.strict()` — only `name`, `targetUrl` |
| `src/contracts/schemas.ts` | `updateEndpointSchema.strict()` — only `name`, `targetUrl`, `isActive` |
| `src/contracts/schemas.ts` | `replayEventSchema.strict()` — only `targetUrlOverride` |
| `src/contracts/schemas.ts` | Output DTO serializers strip `encryptedSecret`, `userId` |
| `tests/security/massAssignment.test.ts` | *(Phase 2)* Sends payloads with extra fields, asserts 400 |

---

## 4. Timing Attacks on HMAC Verification

**OWASP:** API2:2023 — Broken Authentication (crypto weakness variant)

**Threat:** Attacker measures response times to incrementally guess the correct
HMAC signature byte-by-byte, exploiting non-constant-time string comparison.

**Attack Scenarios:**
- Brute-force signature verification by timing `===` comparisons
- Partial signature matching leaking correct prefix bytes

**Mitigation (Timing-Safe Comparison):**
All HMAC-SHA256 comparisons use `crypto.timingSafeEqual()` on equal-length Buffers.
Buffer length is validated first; mismatched lengths return a fixed error.

| File | Purpose |
|------|---------|
| `src/security/crypto.ts` | `verifySignature()` — `timingSafeEqual` on hex-decoded Buffers |
| `src/security/crypto.ts` | Length check before `timingSafeEqual` to prevent thrown errors |
| `tests/security/hmac.test.ts` | *(Phase 2)* Valid/invalid/tampered signatures; timing analysis |

---

## 5. Replay Attacks

**OWASP:** API2:2023 — Broken Authentication (replay variant)

**Threat:** Attacker captures a valid webhook payload + signature and replays it
later to trigger duplicate processing.

**Attack Scenarios:**
- Replay a signed webhook delivery hours or days after the original
- Replay within the window but with manipulated payload

**Mitigation (Timestamp + Idempotency):**
1. **Timestamp in signed content:** Signatures include a Unix timestamp; verification
   enforces a ±5-minute replay window
2. **Idempotency-Key deduplication:** Optional `Idempotency-Key` header prevents
   duplicate event processing

| File | Purpose |
|------|---------|
| `src/security/crypto.ts` | `verifySignature()` — ±5 min replay window enforcement |
| `src/security/crypto.ts` | `signPayload()` — includes timestamp in signed content (`{ts}.{body}`) |
| `src/db/schema.ts` | `webhookEvents.idempotencyKey` column + composite index |
| `tests/security/replay.test.ts` | *(Phase 2)* Expired timestamps rejected; idempotency dedup |

---

## 6. Payload DoS (Denial of Service)

**OWASP:** API4:2023 — Unrestricted Resource Consumption

**Threat:** Attacker sends extremely large webhook payloads or floods endpoints
with high-volume requests to exhaust server resources.

**Attack Scenarios:**
- `POST /in/:slug` with a 100 MB body
- 10,000 requests/second to a single endpoint
- Slowloris-style attacks holding connections open

**Mitigation (Multi-Layer Defense):**
1. **256 KB body limit** on inbound webhook ingestion
2. **Per-endpoint sliding-window rate limiter**
3. **5s timeout** on outbound deliveries
4. **64 KB response cap** on outbound responses

| File | Purpose |
|------|---------|
| `src/security/rateLimiter.ts` | `RateLimiter` class — sliding-window, keyed by endpointId/userId |
| `src/security/ssrf.ts` | `safeFetch()` — 5s timeout + 64 KB body cap on outbound |
| `tests/security/rateLimit.test.ts` | *(Phase 2)* Burst test, window reset, per-key isolation |
| `tests/security/payload.test.ts` | *(Phase 2)* Oversized body rejection at 256 KB boundary |

---

## 7. Zero-Leakage Error Handling

**OWASP:** API8:2023 — Security Misconfiguration

**Threat:** Stack traces, SQL errors, or internal file paths leak in error responses,
giving attackers reconnaissance data.

**Mitigation:** All errors are caught and returned as structured
`{ error: { code, message } }` JSON. No raw exceptions escape to the client.

| File | Purpose |
|------|---------|
| *(Phase 3)* `src/middleware/errorHandler.ts` | Global Hono error handler |
| `src/contracts/schemas.ts` | Output DTOs ensure only allowlisted fields in success responses |

---

## 8. Security Headers

**OWASP:** API8:2023 — Security Misconfiguration

**Mitigation:** Hono `secureHeaders()` middleware applied globally.

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

| File | Purpose |
|------|---------|
| *(Phase 3)* `src/index.ts` | `app.use(secureHeaders())` |

---

## Threat ↔ File Matrix

| Threat | Primary Defense File | Test File (Phase 2) |
|--------|---------------------|---------------------|
| BOLA/IDOR | `src/db/schema.ts` (indexes + scoped queries) | `tests/security/idor.test.ts` |
| SSRF | `src/security/ssrf.ts` | `tests/security/ssrf.test.ts` |
| Mass Assignment | `src/contracts/schemas.ts` | `tests/security/massAssignment.test.ts` |
| Timing Attack | `src/security/crypto.ts` | `tests/security/hmac.test.ts` |
| Replay Attack | `src/security/crypto.ts` + `src/db/schema.ts` | `tests/security/replay.test.ts` |
| Payload DoS | `src/security/rateLimiter.ts` + `src/security/ssrf.ts` | `tests/security/rateLimit.test.ts` + `tests/security/payload.test.ts` |
| Error Leakage | `src/contracts/schemas.ts` (output DTOs) | *(Phase 3)* |
| Security Headers | *(Phase 3)* `secureHeaders()` middleware | *(Phase 3)* |
