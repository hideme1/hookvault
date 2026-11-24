/**
 * Layer B — Security Headers & Error Handling Red-Team Tests
 *
 * Adversarial tests for security headers and zero-leakage errors.
 * These MUST FAIL until Phase 3 implements the middleware.
 *
 * Requirements:
 * - Responses include security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
 * - Errors return structured { error: { code, message } } with ZERO stack traces
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../../src/app.js";
import { createTestDb, seedTwoTenants, close, type SeededTenants } from "../helpers/testDb.js";

describe("Security Headers & Error Handling", () => {
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

  // ─── Security Headers ─────────────────────────────────────────────────

  describe("security headers on all responses", () => {
    it("includes X-Content-Type-Options: nosniff", async () => {
      const res = await app.request("/api/endpoints");
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    });

    it("includes X-Frame-Options: DENY", async () => {
      const res = await app.request("/api/endpoints");
      expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    });

    it("includes Referrer-Policy: no-referrer", async () => {
      const res = await app.request("/api/endpoints");
      expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    });

    it("includes Content-Security-Policy", async () => {
      const res = await app.request("/api/endpoints");
      const csp = res.headers.get("Content-Security-Policy");
      expect(csp).toBeTruthy();
      expect(csp).toContain("default-src");
    });

    it("security headers present on /in/:publicSlug route too", async () => {
      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        { method: "POST", body: "{}" }
      );
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(res.headers.get("X-Frame-Options")).toBe("DENY");
    });

    it("security headers present on 404 responses", async () => {
      const res = await app.request("/nonexistent-route");
      expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    });
  });

  // ─── Structured Error Responses ───────────────────────────────────────

  describe("structured error responses with zero leakage", () => {
    it("malformed JSON body returns structured error, no stack trace", async () => {
      const res = await app.request("/api/endpoints", {
        method: "POST",
        headers: {
          ...tenants.userA.headers,
          "Content-Type": "application/json",
        },
        body: "{ invalid json !!!",
      });

      // Should return 400
      expect(res.status).toBe(400);

      let data: any = null;
      try {
        data = await res.json();
      } catch {
        // Response was not JSON
      }

      // Must have structured error format
      expect(data).toHaveProperty("error");
      expect(data?.error).toHaveProperty("code");
      expect(data?.error).toHaveProperty("message");

      // Must NOT contain stack traces, file paths, or internal errors
      const bodyText = JSON.stringify(data ?? {});
      expect(bodyText).not.toContain("at ");
      expect(bodyText).not.toContain("node_modules");
      expect(bodyText).not.toContain(".ts:");
      expect(bodyText).not.toContain(".js:");
      expect(bodyText).not.toContain("src/");
      expect(bodyText).not.toContain("SQLITE");
      expect(bodyText).not.toContain("Error:");
    });

    it("404 returns structured error JSON", async () => {
      const res = await app.request("/api/nonexistent");
      expect(res.status).toBe(404);

      let data: any = null;
      try {
        data = await res.json();
      } catch {
        // Response was not JSON
      }

      expect(data).not.toBeNull();
      expect(data).toHaveProperty("error");
      expect(data?.error).toHaveProperty("code");
      expect(data?.error).toHaveProperty("message");
    });

    it("validation error returns structured error without internal details", async () => {
      const res = await app.request("/api/endpoints", {
        method: "POST",
        headers: {
          ...tenants.userA.headers,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name: "", targetUrl: "not-a-url" }),
      });

      expect(res.status).toBe(400);

      let data: any = null;
      try {
        data = await res.json();
      } catch {
        // Response was not JSON
      }

      expect(data).toHaveProperty("error");
      const bodyText = JSON.stringify(data ?? {});
      expect(bodyText).not.toContain("at ");
      expect(bodyText).not.toContain("node_modules");
    });
  });

  // ─── Sensitive Header Sanitization ──────────────────────────────────

  describe("sensitive header sanitization on webhook ingestion", () => {
    it("never stores cookie, authorization, proxy-authorization, or set-cookie headers in headersJson", async () => {
      const res = await app.request(
        `/in/${tenants.userA.endpoint.publicSlug}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Cookie": "session_id=secret123; tracking=abc",
            "Authorization": "Bearer super-secret-token",
            "Proxy-Authorization": "Basic dXNlcjpwYXNz",
            "Set-Cookie": "id=hijack",
            "X-Custom-Header": "safe-value",
          },
          body: JSON.stringify({ event: "order.created" }),
        }
      );

      expect(res.status).toBe(200);
      const data: any = await res.json();
      expect(data).toHaveProperty("headersJson");

      const savedHeaders = JSON.parse(data.headersJson);
      expect(savedHeaders).not.toHaveProperty("cookie");
      expect(savedHeaders).not.toHaveProperty("authorization");
      expect(savedHeaders).not.toHaveProperty("proxy-authorization");
      expect(savedHeaders).not.toHaveProperty("set-cookie");
      expect(savedHeaders).toHaveProperty("x-custom-header", "safe-value");
      expect(savedHeaders).toHaveProperty("content-type", "application/json");

      // Verify raw serialized headersJson string contains no sensitive tokens
      expect(data.headersJson).not.toContain("secret123");
      expect(data.headersJson).not.toContain("super-secret-token");
      expect(data.headersJson).not.toContain("dXNlcjpwYXNz");
    });
  });
});
