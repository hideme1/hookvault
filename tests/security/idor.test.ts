/**
 * Layer B — IDOR / BOLA Red-Team Tests
 *
 * Adversarial tests for Broken Object-Level Authorization.
 * These MUST FAIL until Phase 3 implements the actual routes + auth.
 *
 * Attack vectors:
 * - Unauthenticated access to protected routes → 401
 * - Cross-tenant resource access → 404 (never 200, never 403)
 * - Listing returns only own resources, never includes encryptedSecret
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../../src/app.js";
import {
  createTestDb,
  seedTwoTenants,
  close,
  authHeadersFor,
  type SeededTenants,
} from "../helpers/testDb.js";

describe("IDOR / BOLA — Cross-Tenant Authorization", () => {
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

  // Helper to make an authenticated request using session token / auth headers
  function authRequest(
    method: string,
    path: string,
    tokenOrTenant: string | { session?: { token: string }; token?: string },
    body?: object
  ): Promise<Response> {
    const headers: Record<string, string> = {
      ...authHeadersFor(tokenOrTenant),
      "Content-Type": "application/json",
    };
    const init: RequestInit = {
      method,
      headers,
    };
    if (body) {
      init.body = JSON.stringify(body);
    }
    return app.request(path, init);
  }

  // ─── Unauthenticated access ───────────────────────────────────────────

  describe("unauthenticated requests", () => {
    it("GET /api/endpoints without auth returns 401", async () => {
      const res = await app.request("/api/endpoints");
      expect(res.status).toBe(401);
    });

    it("POST /api/endpoints without auth returns 401", async () => {
      const res = await app.request("/api/endpoints", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: "test", targetUrl: "https://example.com" }),
      });
      expect(res.status).toBe(401);
    });

    it("GET /api/endpoints/:id without auth returns 401", async () => {
      const res = await app.request(`/api/endpoints/${tenants.userA.endpoint.id}`);
      expect(res.status).toBe(401);
    });

    it("PATCH /api/endpoints/:id without auth returns 401", async () => {
      const res = await app.request(`/api/endpoints/${tenants.userA.endpoint.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: "hacked" }),
      });
      expect(res.status).toBe(401);
    });

    it("DELETE /api/endpoints/:id without auth returns 401", async () => {
      const res = await app.request(`/api/endpoints/${tenants.userA.endpoint.id}`, {
        method: "DELETE",
      });
      expect(res.status).toBe(401);
    });
  });

  // ─── Cross-tenant endpoint access ─────────────────────────────────────

  describe("cross-tenant endpoint access (userB → userA resources)", () => {
    it("GET /api/endpoints/:userAEndpointId as userB returns 404", async () => {
      const res = await authRequest(
        "GET",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userB
      );
      // Must be 404, never 200 (data leak) and never 403 (existence leak)
      expect(res.status).toBe(404);
      expect(res.status).not.toBe(200);
      expect(res.status).not.toBe(403);
    });

    it("PATCH /api/endpoints/:userAEndpointId as userB returns 404", async () => {
      const res = await authRequest(
        "PATCH",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userB,
        { name: "hacked" }
      );
      expect(res.status).toBe(404);
      expect(res.status).not.toBe(200);
      expect(res.status).not.toBe(403);
    });

    it("DELETE /api/endpoints/:userAEndpointId as userB returns 404", async () => {
      const res = await authRequest(
        "DELETE",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userB
      );
      expect(res.status).toBe(404);
      expect(res.status).not.toBe(200);
      expect(res.status).not.toBe(403);
    });
  });

  // ─── Cross-tenant event access ────────────────────────────────────────

  describe("cross-tenant event access (userB → userA events)", () => {
    it("GET /api/events/:userAEventId as userB returns 404", async () => {
      const res = await authRequest(
        "GET",
        `/api/events/${tenants.userA.event.id}`,
        tenants.userB
      );
      expect(res.status).toBe(404);
      expect(res.status).not.toBe(200);
      expect(res.status).not.toBe(403);
    });

    it("POST /api/events/:userAEventId/replay as userB returns 404", async () => {
      const res = await authRequest(
        "POST",
        `/api/events/${tenants.userA.event.id}/replay`,
        tenants.userB,
        {}
      );
      expect(res.status).toBe(404);
      expect(res.status).not.toBe(200);
      expect(res.status).not.toBe(403);
    });
  });

  // ─── Listing isolation + secret stripping ─────────────────────────────

  describe("listing isolation and secret stripping", () => {
    it("GET /api/endpoints as userB returns ONLY userB's endpoints", async () => {
      const res = await authRequest(
        "GET",
        "/api/endpoints",
        tenants.userB
      );
      expect(res.status).toBe(200);
      const data = await res.json();

      // Should be an array
      expect(Array.isArray(data)).toBe(true);

      // Every endpoint must belong to userB (never userA's endpoint)
      for (const ep of data as any[]) {
        expect(ep.id).not.toBe(tenants.userA.endpoint.id);
      }

      // Should contain userB's endpoint
      const bobEndpoint = (data as any[]).find(
        (ep: any) => ep.id === tenants.userB.endpoint.id
      );
      expect(bobEndpoint).toBeDefined();
    });

    it("GET /api/endpoints response NEVER includes encryptedSecret", async () => {
      const res = await authRequest(
        "GET",
        "/api/endpoints",
        tenants.userB
      );
      expect(res.status).toBe(200);
      const body = await res.text();

      // The raw response text must never contain encryptedSecret
      expect(body).not.toContain("encryptedSecret");
    });

    it("GET /api/endpoints/:id response NEVER includes encryptedSecret", async () => {
      const res = await authRequest(
        "GET",
        `/api/endpoints/${tenants.userB.endpoint.id}`,
        tenants.userB
      );
      expect(res.status).toBe(200);
      const body = await res.text();
      expect(body).not.toContain("encryptedSecret");
    });
  });
});
