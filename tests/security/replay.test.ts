/**
 * Layer B — Replay Attack Red-Team Tests
 *
 * Adversarial tests for HMAC replay and idempotency enforcement.
 * These MUST FAIL until Phase 3 implements the actual ingestion route.
 *
 * Attack vectors:
 * - Expired HMAC timestamp → signatureValid: false or rejection (401)
 * - Duplicate Idempotency-Key → deduplicated (store/deliver only once)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../../src/app.js";
import { createTestDb, seedTwoTenants, close, type SeededTenants } from "../helpers/testDb.js";
import { signPayload } from "../../src/security/crypto.js";

describe("Replay Attacks — Timestamp & Idempotency", () => {
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

  // ─── Expired HMAC timestamp ───────────────────────────────────────────

  describe("expired HMAC timestamp", () => {
    it("POST /in/:publicSlug with >5 min old timestamp flags signatureValid: false", async () => {
      const payload = JSON.stringify({ event: "order.created" });
      const expiredTimestamp = Math.floor(Date.now() / 1000) - 400; // ~6.5 min ago
      const sig = signPayload(
        payload,
        tenants.userA.endpoint.signingSecret,
        expiredTimestamp
      );

      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig,
            "X-Webhook-Timestamp": String(expiredTimestamp),
          },
          body: payload,
        }
      );

      // The route should accept the webhook but flag signatureValid as false,
      // OR reject it outright with 401. Either way, the signature should NOT be valid.
      const status = res.status;
      expect([200, 202, 401].includes(status)).toBe(true);

      if (status === 200 || status === 202) {
        const data = await res.json();
        // If accepted, the event should be flagged as invalid signature
        expect((data as any).signatureValid).toBe(false);
      }
    });

    it("POST /in/:publicSlug with fresh timestamp and valid sig succeeds", async () => {
      const payload = JSON.stringify({ event: "order.created" });
      const now = Math.floor(Date.now() / 1000);
      const sig = signPayload(
        payload,
        tenants.userA.endpoint.signingSecret,
        now
      );

      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig,
            "X-Webhook-Timestamp": String(now),
          },
          body: payload,
        }
      );

      expect([200, 202].includes(res.status)).toBe(true);
    });
  });

  // ─── Idempotency-Key deduplication ────────────────────────────────────

  describe("Idempotency-Key deduplication", () => {
    it("second POST with same Idempotency-Key is deduplicated", async () => {
      const payload = JSON.stringify({ event: "payment.completed", id: 42 });
      const now = Math.floor(Date.now() / 1000);
      const sig = signPayload(
        payload,
        tenants.userA.endpoint.signingSecret,
        now
      );
      const idempotencyKey = "unique-key-12345";

      const headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": sig,
        "X-Webhook-Timestamp": String(now),
        "Idempotency-Key": idempotencyKey,
      };

      // First request — should succeed and store the event
      const res1 = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        { method: "POST", headers, body: payload }
      );
      expect([200, 202].includes(res1.status)).toBe(true);

      // Second request with same Idempotency-Key — should be deduplicated
      const res2 = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        { method: "POST", headers, body: payload }
      );
      expect([200, 202].includes(res2.status)).toBe(true);

      // Both responses should reference the same event ID
      const data1 = await res1.json();
      const data2 = await res2.json();
      expect((data1 as any).id).toBe((data2 as any).id);
    });

    it("different Idempotency-Keys create separate events", async () => {
      const payload = JSON.stringify({ event: "order.shipped" });
      const now = Math.floor(Date.now() / 1000);
      const sig = signPayload(
        payload,
        tenants.userA.endpoint.signingSecret,
        now
      );

      const res1 = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig,
            "X-Webhook-Timestamp": String(now),
            "Idempotency-Key": "key-A",
          },
          body: payload,
        }
      );

      const res2 = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig,
            "X-Webhook-Timestamp": String(now),
            "Idempotency-Key": "key-B",
          },
          body: payload,
        }
      );

      expect([200, 202].includes(res1.status)).toBe(true);
      expect([200, 202].includes(res2.status)).toBe(true);

      const data1 = await res1.json();
      const data2 = await res2.json();
      expect((data1 as any).id).not.toBe((data2 as any).id);
    });
  });
});
