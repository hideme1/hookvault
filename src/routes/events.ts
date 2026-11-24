import { Hono } from "hono";
import { and, eq, desc } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import * as schema from "../db/schema.js";
import {
  replayEventSchema,
  serializeEvent,
  serializeDelivery,
} from "../contracts/schemas.js";
import { safeFetch } from "../security/ssrf.js";
import { requireAuth } from "../middleware/auth.js";

export const eventsRouter = new Hono();

eventsRouter.use("*", requireAuth);

// GET /api/events
eventsRouter.get("/", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const endpointId = c.req.query("endpointId");

  const conditions = [eq(schema.webhookEvents.userId, user.id)];
  if (endpointId) {
    conditions.push(eq(schema.webhookEvents.endpointId, endpointId));
  }

  const events = await db
    .select()
    .from(schema.webhookEvents)
    .where(and(...conditions))
    .orderBy(desc(schema.webhookEvents.receivedAt))
    .all();

  const deliveries = await db
    .select()
    .from(schema.deliveryAttempts)
    .where(eq(schema.deliveryAttempts.userId, user.id))
    .all();

  const latestDeliveryByEventId = new Map<string, typeof schema.deliveryAttempts.$inferSelect>();
  for (const d of deliveries) {
    const existing = latestDeliveryByEventId.get(d.eventId);
    if (!existing || d.attemptNumber > existing.attemptNumber) {
      latestDeliveryByEventId.set(d.eventId, d);
    }
  }

  const result = events.map((ev: typeof schema.webhookEvents.$inferSelect) => {
    const latest = latestDeliveryByEventId.get(ev.id);
    return serializeEvent(ev, undefined, latest?.statusCode ?? null);
  });

  return c.json(result, 200);
});

// GET /api/events/:id
eventsRouter.get("/:id", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const id = c.req.param("id");

  const event = await db
    .select()
    .from(schema.webhookEvents)
    .where(and(eq(schema.webhookEvents.id, id), eq(schema.webhookEvents.userId, user.id)))
    .get();

  if (!event) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Event not found",
        },
      },
      404
    );
  }

  const deliveries = await db
    .select()
    .from(schema.deliveryAttempts)
    .where(and(eq(schema.deliveryAttempts.eventId, event.id), eq(schema.deliveryAttempts.userId, user.id)))
    .orderBy(desc(schema.deliveryAttempts.attemptNumber))
    .all();

  const latestStatusCode = deliveries.length > 0 ? deliveries[0].statusCode : null;

  return c.json(serializeEvent(event, deliveries, latestStatusCode), 200);
});

// POST /api/events/:id/replay
eventsRouter.post("/:id/replay", async (c) => {
  const db = c.get("db");
  const user = c.get("user");
  const id = c.req.param("id");

  const event = await db
    .select()
    .from(schema.webhookEvents)
    .where(and(eq(schema.webhookEvents.id, id), eq(schema.webhookEvents.userId, user.id)))
    .get();

  if (!event) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Event not found",
        },
      },
      404
    );
  }

  const endpoint = await db
    .select()
    .from(schema.endpoints)
    .where(and(eq(schema.endpoints.id, event.endpointId), eq(schema.endpoints.userId, user.id)))
    .get();

  if (!endpoint) {
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

  let body: any = {};
  const text = await c.req.text();
  if (text && text.trim().length > 0) {
    body = JSON.parse(text);
  }

  const parsed = replayEventSchema.parse(body);

  const targetUrl = parsed.targetUrlOverride ?? endpoint.targetUrl;

  const priorAttempts = await db
    .select()
    .from(schema.deliveryAttempts)
    .where(and(eq(schema.deliveryAttempts.eventId, event.id), eq(schema.deliveryAttempts.userId, user.id)))
    .all();

  const attemptNumber = priorAttempts.length + 1;

  const deliveryHeaders: Record<string, string> = {
    "x-hookvault-replay": "true",
  };
  try {
    const origHeaders = JSON.parse(event.headersJson);
    if (origHeaders && typeof origHeaders === "object") {
      const contentType = origHeaders["content-type"];
      if (contentType) deliveryHeaders["content-type"] = contentType;
    }
  } catch {}

  const delivery = await safeFetch(targetUrl, {
    method: event.method || "POST",
    headers: deliveryHeaders,
    body: event.bodyText ?? undefined,
  });

  const deliveryRow = {
    id: randomUUID(),
    eventId: event.id,
    endpointId: endpoint.id,
    userId: user.id,
    attemptNumber,
    statusCode: delivery.status || null,
    responseSnippet: delivery.body ? delivery.body.slice(0, 512) : null,
    durationMs: delivery.durationMs,
    errorCode: delivery.error || null,
    createdAt: new Date(),
  };

  await db.insert(schema.deliveryAttempts).values(deliveryRow).run();

  return c.json(serializeDelivery(deliveryRow), 200);
});
