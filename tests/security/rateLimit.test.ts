/**
 * Layer A — Rate Limiter Unit Tests
 *
 * Tests the Phase 1 security primitive in src/security/rateLimiter.ts.
 * All tests in this file MUST PASS before Phase 3.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { RateLimiter } from "../../src/security/rateLimiter.js";

describe("RateLimiter", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1000000);
    limiter = new RateLimiter({ windowMs: 60_000, maxRequests: 5 });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ─── Burst up to limit & N+1 rejection with retryAfterMs ──────────────────

  describe("burst up to limit and N+1 rejection", () => {
    it("allows burst requests up to the max limit with retryAfterMs = 0", () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.check("endpoint-1");
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(4 - i);
        expect(result.limit).toBe(5);
        expect(result.retryAfterMs).toBe(0);
      }
    });

    it("rejects request N+1 with allowed: false and positive retryAfterMs", () => {
      // Exhaust the limit of 5 requests
      for (let i = 0; i < 5; i++) {
        limiter.check("endpoint-1");
      }

      // 6th request (N+1) should be rejected immediately
      const rejected = limiter.check("endpoint-1");
      expect(rejected.allowed).toBe(false);
      expect(rejected.remaining).toBe(0);
      expect(rejected.limit).toBe(5);
      expect(rejected.retryAfterMs).toBeGreaterThan(0);
      expect(rejected.retryAfterMs).toBeLessThanOrEqual(60_000);
    });

    it("reports accurate retryAfterMs decreasing as time advances", () => {
      // Exhaust limit at t = 1,000,000
      for (let i = 0; i < 5; i++) {
        limiter.check("endpoint-1");
      }

      const rej1 = limiter.check("endpoint-1");
      expect(rej1.retryAfterMs).toBe(60_000);

      // Advance by 20 seconds
      vi.advanceTimersByTime(20_000);

      const rej2 = limiter.check("endpoint-1");
      expect(rej2.allowed).toBe(false);
      expect(rej2.retryAfterMs).toBe(40_000);
    });
  });

  // ─── Sliding window reset using vi.useFakeTimers() ────────────────────────

  describe("sliding window reset using vi.useFakeTimers()", () => {
    it("resets cleanly after the full window expires", () => {
      // Consume all 5 slots at t = 1,000,000
      for (let i = 0; i < 5; i++) {
        limiter.check("endpoint-1");
      }

      // Verify blocked
      expect(limiter.check("endpoint-1").allowed).toBe(false);

      // Advance time beyond the 60s window (60,001 ms)
      vi.advanceTimersByTime(60_001);

      // Limiter should have cleanly reset
      const result = limiter.check("endpoint-1");
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
      expect(result.retryAfterMs).toBe(0);
    });

    it("partially recovers slots as individual timestamps roll out of the window", () => {
      // Request 1 at t = 1,000,000
      limiter.check("endpoint-1");

      // Advance 10s
      vi.advanceTimersByTime(10_000); // t = 1,010,000
      // Request 2, 3, 4, 5
      for (let i = 0; i < 4; i++) {
        limiter.check("endpoint-1");
      }

      // All 5 slots used -> rejected
      expect(limiter.check("endpoint-1").allowed).toBe(false);

      // Advance 50,001 ms (t = 1,060,001)
      // The 1st request at t = 1,000,000 has now expired (>60s ago)
      // The other 4 requests at t = 1,010,000 are still within the window (<60s ago)
      vi.advanceTimersByTime(50_001);

      // 1 slot should have freed up
      const res1 = limiter.check("endpoint-1");
      expect(res1.allowed).toBe(true);
      expect(res1.remaining).toBe(0); // Used the 1 freed slot

      // Immediately checking again should be blocked
      const res2 = limiter.check("endpoint-1");
      expect(res2.allowed).toBe(false);
    });
  });

  // ─── Per-key isolation ───────────────────────────────────────────────────

  describe("per-key isolation", () => {
    it("endpointA hitting its limit NEVER throttles endpointB", () => {
      // Exhaust endpointA's limit
      for (let i = 0; i < 5; i++) {
        limiter.check("endpointA");
      }

      // endpointA is throttled
      const resA = limiter.check("endpointA");
      expect(resA.allowed).toBe(false);
      expect(resA.retryAfterMs).toBeGreaterThan(0);

      // endpointB is completely unaffected and has full quota
      for (let i = 0; i < 5; i++) {
        const resB = limiter.check("endpointB");
        expect(resB.allowed).toBe(true);
        expect(resB.retryAfterMs).toBe(0);
      }

      // endpointB now exhausted as well
      expect(limiter.check("endpointB").allowed).toBe(false);
    });

    it("different users/IPs are isolated", () => {
      // Exhaust user-1
      for (let i = 0; i < 5; i++) {
        limiter.check("user:1");
      }
      expect(limiter.check("user:1").allowed).toBe(false);

      // user-2 has full quota
      const resUser2 = limiter.check("user:2");
      expect(resUser2.allowed).toBe(true);
      expect(resUser2.remaining).toBe(4);
    });
  });

  // ─── Peek (non-consuming) ────────────────────────────────────────────────

  describe("peek", () => {
    it("peek reports current quota without consuming slots", () => {
      // Consume 3 slots
      limiter.check("endpoint-1");
      limiter.check("endpoint-1");
      limiter.check("endpoint-1");

      // Peek shows 2 remaining
      const p1 = limiter.peek("endpoint-1");
      expect(p1.allowed).toBe(true);
      expect(p1.remaining).toBe(2);
      expect(p1.retryAfterMs).toBe(0);

      // Peek again — still 2 remaining
      const p2 = limiter.peek("endpoint-1");
      expect(p2.remaining).toBe(2);

      // Check consumes slot 4
      const c1 = limiter.check("endpoint-1");
      expect(c1.remaining).toBe(1);
    });

    it("peek on uninitialized key reports full quota", () => {
      const p = limiter.peek("new-endpoint");
      expect(p.allowed).toBe(true);
      expect(p.remaining).toBe(5);
      expect(p.retryAfterMs).toBe(0);
    });
  });

  // ─── Reset and Clear ─────────────────────────────────────────────────────

  describe("reset and clear", () => {
    it("reset clears a specific key", () => {
      for (let i = 0; i < 5; i++) {
        limiter.check("ep-1");
      }
      expect(limiter.check("ep-1").allowed).toBe(false);

      limiter.reset("ep-1");

      const res = limiter.check("ep-1");
      expect(res.allowed).toBe(true);
      expect(res.remaining).toBe(4);
    });

    it("clear resets all keys", () => {
      for (let i = 0; i < 5; i++) {
        limiter.check("ep-1");
        limiter.check("ep-2");
      }
      expect(limiter.check("ep-1").allowed).toBe(false);
      expect(limiter.check("ep-2").allowed).toBe(false);

      limiter.clear();

      expect(limiter.check("ep-1").allowed).toBe(true);
      expect(limiter.check("ep-2").allowed).toBe(true);
    });
  });
});
