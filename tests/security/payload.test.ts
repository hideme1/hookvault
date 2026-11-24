/**
 * Layer B — Payload DoS Red-Team Tests
 *
 * Adversarial tests for body size limits on webhook ingestion.
 * These MUST FAIL until Phase 3 implements the actual ingestion route.
 *
 * Attack vectors:
 * - Oversized body (257 KB) → 413 Payload Too Large
 * - Valid body (10 KB) → 200/202 success
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../../src/app.js";
import { createTestDb, seedTwoTenants, close, type SeededTenants } from "../helpers/testDb.js";

describe("Payload DoS — Body Size Enforcement", () => {
  let testDb: ReturnType<typeof createTestDb>;
  let tenants: SeededTenants;
  let app: ReturnType<typeof createApp>;

  beforeAll(() => {
    testDb = createTestDb();
    tenants = seedTwoTenants(testDb.db);
    app = createApp({ db: testDb.db });
  });

  afterAll(() => {
    close(testDb.sqlite);
  });

  // ─── Oversized body rejection ─────────────────────────────────────────

  describe("oversized body rejection", () => {
    it("POST /in/:publicSlug with 257 KB body returns 413", async () => {
      // 257 KB = 263168 bytes, over the 256 KB (262144 byte) hard limit
      const oversizedBody = "x".repeat(257 * 1024);

      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: oversizedBody,
        }
      );

      expect(res.status).toBe(413);
    });

    it("POST /in/:publicSlug with exactly 256 KB body is accepted", async () => {
      // Exactly at the 256 KB limit
      const maxBody = "x".repeat(256 * 1024);

      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: maxBody,
        }
      );

      // Should be accepted (200 or 202), not rejected with 413
      expect([200, 202].includes(res.status)).toBe(true);
    });
  });

  // ─── Valid body acceptance ────────────────────────────────────────────

  describe("valid body acceptance", () => {
    it("POST /in/:publicSlug with 10 KB body succeeds", async () => {
      const validBody = JSON.stringify({
        event: "order.created",
        data: "x".repeat(10 * 1024 - 50), // ~10 KB total
      });

      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: validBody,
        }
      );

      // Should succeed with 200 or 202
      expect([200, 202].includes(res.status)).toBe(true);
    });

    it("POST /in/:publicSlug with tiny body succeeds", async () => {
      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: '{"event":"ping"}',
        }
      );

      expect([200, 202].includes(res.status)).toBe(true);
    });
  });
});
