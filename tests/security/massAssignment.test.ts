/**
 * Layer B — Mass Assignment Red-Team Tests
 *
 * Adversarial tests for Anti-Mass-Assignment via strict Zod schemas.
 * These MUST FAIL until Phase 3 implements the actual routes.
 *
 * Attack vectors:
 * - POST /api/endpoints with extra privileged fields → 400
 * - PATCH /api/endpoints/:id with forbidden override fields → 400
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

describe("Mass Assignment — Strict Schema Enforcement", () => {
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

  function authRequest(
    method: string,
    path: string,
    tokenOrTenant: string | { session?: { token: string }; token?: string },
    body?: object
  ): Promise<Response> {
    return app.request(path, {
      method,
      headers: {
        ...authHeadersFor(tokenOrTenant),
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  // ─── POST /api/endpoints — extra privileged fields ────────────────────

  describe("POST /api/endpoints — reject extra fields", () => {
    it("rejects userId injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          userId: tenants.userB.user.id, // ATTACK: impersonate another user
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects role injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          role: "admin", // ATTACK: privilege escalation
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects plan injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          plan: "enterprise", // ATTACK: bypass billing
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects custom id injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          id: "custom-id", // ATTACK: control resource ID
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects encryptedSecret injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          encryptedSecret: "attacker-controlled", // ATTACK: control signing secret
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects publicSlug injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          publicSlug: "my-chosen-slug", // ATTACK: control public slug
        }
      );
      expect(res.status).toBe(400);
    });

    it("rejects createdAt injection with 400", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "My Hook",
          targetUrl: "https://example.com/hook",
          createdAt: "2020-01-01T00:00:00Z", // ATTACK: backdate creation
        }
      );
      expect(res.status).toBe(400);
    });

    it("valid create with only name + targetUrl returns 201", async () => {
      const res = await authRequest(
        "POST",
        "/api/endpoints",
        tenants.userA,
        {
          name: "Legit Hook",
          targetUrl: "https://legit.example.com/hook",
        }
      );
      expect(res.status).toBe(201);
    });
  });

  // ─── PATCH /api/endpoints/:id — forbidden override fields ─────────────

  describe("PATCH /api/endpoints/:id — reject forbidden fields", () => {
    it("rejects userId override with 400", async () => {
      const res = await authRequest(
        "PATCH",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userA,
        { userId: tenants.userB.user.id } // ATTACK: transfer ownership
      );
      expect(res.status).toBe(400);
    });

    it("rejects publicSlug override with 400", async () => {
      const res = await authRequest(
        "PATCH",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userA,
        { publicSlug: "hijacked-slug" } // ATTACK: take over slug
      );
      expect(res.status).toBe(400);
    });

    it("rejects encryptedSecret override with 400", async () => {
      const res = await authRequest(
        "PATCH",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userA,
        { encryptedSecret: "attacker-secret" } // ATTACK: replace signing key
      );
      expect(res.status).toBe(400);
    });

    it("valid update with only name returns 200", async () => {
      const res = await authRequest(
        "PATCH",
        `/api/endpoints/${tenants.userA.endpoint.id}`,
        tenants.userA,
        { name: "Updated Name" }
      );
      expect(res.status).toBe(200);
    });
  });
});
