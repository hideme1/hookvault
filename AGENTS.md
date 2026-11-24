# HookVault — Security-First Engineering Constitution (`AGENTS.md`)

## 1. Tech Stack (Zero Docker, Lightweight Local + Cloudflare Workers Ready)
- Runtime & API: TypeScript (strict mode), **Hono** (`hono`)
- Database & ORM: **Drizzle ORM** (`drizzle-orm`) + local SQLite (`better-sqlite3` for dev/tests, Cloudflare D1-compatible schema)
- Validation: **Zod** (`zod`) for ALL request inputs AND response output allowlists
- Authentication: **Better Auth** (`better-auth@^1.7.27` — MUST be >= 1.7.16 to include the Nov 3, 2026 security patches; NEVER write DIY auth, custom JWT signing, or custom password hashing)
- Testing: **Vitest** (`vitest`)
- Frontend (Phase 4 only): React + Vite + Tailwind CSS consuming typed API contracts

## 2. Non-Negotiable Security Invariants (NEVER VIOLATE)
1. **Deny-by-Default Multi-Tenancy:** Every database query on `endpoints`, `events`, or `deliveries` MUST include `and(eq(table.id, id), eq(table.userId, session.user.id))`. Never query by resource `id` alone.
2. **SSRF Defense on Outbound Webhooks:** Before ANY outbound HTTP request (relay or replay), resolve the target URL and REJECT:
   - Non-`https:` protocols (allow `http://` only if `ALLOW_LOCAL_TARGETS=true` in test mode)
   - Private/reserved IPv4 & IPv6 ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`, `0.0.0.0`)
   - HTTP redirects (`redirect: 'manual'` — never blindly follow 301/302 into internal IPs)
   - Hard timeout (`5000ms`) and max response body cap (`64 KB`).
3. **Timing-Safe Cryptography:** All webhook HMAC-SHA256 signature comparisons MUST use `crypto.timingSafeEqual` on equal-length Buffers. Signing secrets are generated with `crypto.randomBytes(32)` and stored encrypted at rest (AES-256-GCM) or masked on read.
4. **Anti-Mass Assignment & Strict Allowlists:** Every Zod input schema MUST use `.strict()` so unexpected fields (e.g., `userId`, `role`, `plan`, `createdAt`) return `400 Bad Request`. Every API response MUST pass through an explicit output DTO serializer so internal columns or secrets never leak.
5. **Payload & DoS Guards:** Inbound webhook ingestion (`/in/:publicSlug`) MUST enforce a hard `256 KB` body limit, per-endpoint rate limiting, and optional `Idempotency-Key` deduplication.
6. **Zero Leakage Error Handling:** Never return raw stack traces, SQL errors, or internal file paths in HTTP responses. Return structured `{ error: { code, message } }` JSON only.
7. **Security Headers:** Apply Hono `secureHeaders()` globally (`CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`).

## 3. Non-Linear Build Order (Strict Gatekeeping)
- Phase 1: Architecture, Threat Model, DB Schema, Zod Contracts, Security Primitives ONLY. No routes, no UI.
- Phase 2: Adversarial Red-Team Vitest Suite (IDOR, SSRF, Mass Assignment, HMAC tampering, Oversized payload, Rate limit). Tests MUST fail before Phase 3.
- Phase 3: Hono API + Better Auth implementation until 100% of Phase 2 tests pass.
- Phase 4: Minimalist high-contrast UI (Vite + Tailwind).
- Phase 5: Automated security audit, `npm audit`, README, and Cloudflare deployment config.