import { Hono } from "hono";
import { and, eq } from "drizzle-orm";
import { randomUUID, randomBytes } from "node:crypto";
import * as schema from "../db/schema.js";
import {
  createEndpointSchema,
  updateEndpointSchema,
  serializeEndpoint,
} from "../contracts/schemas.js";
import { validateUrl } from "../security/ssrf.js";
import { encrypt, generateSigningSecret } from "../security/crypto.js";
import { requireAuth } from "../middleware/auth.js";

export const endpointsRouter = new Hono();

endpointsRouter.use("*", requireAuth);

// GET /api/endpoints
endpointsRouter.get("/", async (c) => {
  const db = c.get("db");
  const user = c.get("user");

  const rows = await db
    .select()
    .from(schema.endpoints)
    .where(eq(schema.endpoints.userId, user.id))
    .all();

  return c.json(rows.map(serializeEndpoint), 200);
});

// POST /api/endpoints
endpointsRouter.post("/", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const encryptionKey = c.get("encryptionKey");

  const body = await c.req.json();
  const parsed = createEndpointSchema.parse(body);

  const urlCheck = await validateUrl(parsed.targetUrl);
  if (!urlCheck.safe && urlCheck.error !== "DNS_RESOLUTION_FAILED") {
    return c.json(
      {
        error: {
          code: "INVALID_TARGET_URL",
          message: urlCheck.error ?? "Invalid target URL",
        },
      },
      400
    );
  }

  const id = randomUUID();
  const publicSlug = "ep_" + randomBytes(8).toString("hex");
  const secret = generateSigningSecret();
  const encryptedSecret = encrypt(secret, encryptionKey);

  const newRow = {
    id,
    userId: user.id,
    name: parsed.name,
    publicSlug,
    targetUrl: parsed.targetUrl,
    encryptedSecret,
    isActive: true,
    createdAt: new Date(),
  };

  await db.insert(schema.endpoints).values(newRow).run();

  return c.json(serializeEndpoint(newRow), 201);
});

// GET /api/endpoints/:id
endpointsRouter.get("/:id", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const id = c.req.param("id");

  const row = await db
    .select()
    .from(schema.endpoints)
    .where(and(eq(schema.endpoints.id, id), eq(schema.endpoints.userId, user.id)))
    .get();

  if (!row) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Endpoint not found",
        },
      },
      404
    );
  }

  return c.json(serializeEndpoint(row), 200);
});

// PATCH /api/endpoints/:id
endpointsRouter.patch("/:id", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const id = c.req.param("id");

  const body = await c.req.json();
  const parsed = updateEndpointSchema.parse(body);

  if (parsed.targetUrl !== undefined) {
    const urlCheck = await validateUrl(parsed.targetUrl);
    if (!urlCheck.safe && urlCheck.error !== "DNS_RESOLUTION_FAILED") {
      return c.json(
        {
          error: {
            code: "INVALID_TARGET_URL",
            message: urlCheck.error ?? "Invalid target URL",
          },
        },
        400
      );
    }
  }

  const existing = await db
    .select()
    .from(schema.endpoints)
    .where(and(eq(schema.endpoints.id, id), eq(schema.endpoints.userId, user.id)))
    .get();

  if (!existing) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Endpoint not found",
        },
      },
      404
    );
  }

  const updates: Partial<typeof schema.endpoints.$inferInsert> = {};
  if (parsed.name !== undefined) updates.name = parsed.name;
  if (parsed.targetUrl !== undefined) updates.targetUrl = parsed.targetUrl;
  if (parsed.isActive !== undefined) updates.isActive = parsed.isActive;

  await db
    .update(schema.endpoints)
    .set(updates)
    .where(and(eq(schema.endpoints.id, id), eq(schema.endpoints.userId, user.id)))
    .run();

  const updated = { ...existing, ...updates };
  return c.json(serializeEndpoint(updated), 200);
});

// DELETE /api/endpoints/:id
endpointsRouter.delete("/:id", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const id = c.req.param("id");

  const existing = await db
    .select()
    .from(schema.endpoints)
    .where(and(eq(schema.endpoints.id, id), eq(schema.endpoints.userId, user.id)))
    .get();

  if (!existing) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Endpoint not found",
        },
      },
      404
    );
  }

  await db
    .delete(schema.endpoints)
    .where(and(eq(schema.endpoints.id, id), eq(schema.endpoints.userId, user.id)))
    .run();

  return c.json({ success: true }, 200);
});
