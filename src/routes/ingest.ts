import { Hono } from "hono";
import { and, eq } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import * as schema from "../db/schema.js";
import { serializeEvent } from "../contracts/schemas.js";
import { decrypt, verifySignature } from "../security/crypto.js";
import { safeFetch } from "../security/ssrf.js";

export const ingestRouter = new Hono();

const MAX_BODY_BYTES = 256 * 1024; // 256 KB

const SENSITIVE_HEADERS = new Set([
  "cookie",
  "authorization",
  "proxy-authorization",
  "set-cookie",
]);

ingestRouter.post("/:publicSlug", async (c) => {
  const db = c.get("db");
  const encryptionKey = c.get("encryptionKey");
  const rateLimiter = c.get("rateLimiter");

  // 1. Enforce hard 256 KB body limit BEFORE JSON parsing/DB writes
  const contentLength = c.req.header("content-length");
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    return c.json(
      {
        error: {
          code: "PAYLOAD_TOO_LARGE",
          message: "Payload exceeds 256 KB limit",
        },
      },
      413
    );
  }

  const rawReq = c.req.raw;
  let rawBody = "";
  if (rawReq.body) {
    const reader = rawReq.body.getReader();
    let totalBytes = 0;
    const chunks: Uint8Array[] = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel();
        return c.json(
          {
            error: {
              code: "PAYLOAD_TOO_LARGE",
              message: "Payload exceeds 256 KB limit",
            },
          },
          413
        );
      }
      chunks.push(value);
    }

    const decoder = new TextDecoder();
    rawBody =
      chunks.map((chunk) => decoder.decode(chunk, { stream: true })).join("") +
      decoder.decode();
  }

  // 2. Lookup endpoint by publicSlug
  const publicSlug = c.req.param("publicSlug");
  const endpoint = await db
    .select()
    .from(schema.endpoints)
    .where(eq(schema.endpoints.publicSlug, publicSlug))
    .get();

  if (!endpoint || !endpoint.isActive) {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Endpoint not found or inactive",
        },
      },
      404
    );
  }

  // 3. Sliding-window rate limiting per endpoint
  if (rateLimiter) {
    const limitResult = rateLimiter.check(endpoint.id);
    if (!limitResult.allowed) {
      const retryAfterSec = Math.max(1, Math.ceil(limitResult.retryAfterMs / 1000));
      return c.json(
        {
          error: {
            code: "RATE_LIMIT_EXCEEDED",
            message: "Rate limit exceeded for endpoint",
          },
        },
        429,
        {
          "Retry-After": String(retryAfterSec),
        }
      );
    }
  }

  // 4. Idempotency-Key deduplication
  const idempotencyKey =
    c.req.header("Idempotency-Key") || c.req.header("idempotency-key");

  if (idempotencyKey) {
    const existing = await db
      .select()
      .from(schema.webhookEvents)
      .where(
        and(
          eq(schema.webhookEvents.endpointId, endpoint.id),
          eq(schema.webhookEvents.idempotencyKey, idempotencyKey)
        )
      )
      .get();

    if (existing) {
      return c.json(serializeEvent(existing), 200);
    }
  }

  // 5. HMAC signature verification
  const signature =
    c.req.header("X-Webhook-Signature") || c.req.header("x-webhook-signature");
  const timestampHeader =
    c.req.header("X-Webhook-Timestamp") || c.req.header("x-webhook-timestamp");

  let signatureValid: boolean | null = null;
  if (signature && timestampHeader) {
    const timestamp = parseInt(timestampHeader, 10);
    if (!isNaN(timestamp)) {
      try {
        const decryptedSecret = decrypt(endpoint.encryptedSecret, encryptionKey);
        const verifyRes = verifySignature(rawBody, signature, decryptedSecret, timestamp);
        signatureValid = verifyRes.valid;
      } catch {
        signatureValid = false;
      }
    } else {
      signatureValid = false;
    }
  }

  // 6. Persist webhookEvents row (strip sensitive headers case-insensitively)
  const headersObj: Record<string, string> = {};
  for (const [k, v] of Object.entries(c.req.header())) {
    const lowerKey = k.toLowerCase();
    if (v !== undefined && !SENSITIVE_HEADERS.has(lowerKey)) {
      headersObj[lowerKey] = v;
    }
  }

  const eventRow = {
    id: randomUUID(),
    endpointId: endpoint.id,
    userId: endpoint.userId,
    idempotencyKey: idempotencyKey || null,
    method: c.req.method,
    headersJson: JSON.stringify(headersObj),
    bodyText: rawBody || null,
    signatureValid,
    receivedAt: new Date(),
  };

  await db.insert(schema.webhookEvents).values(eventRow).run();

  // 7. Dispatch outbound delivery via safeFetch()
  const deliveryHeaders: Record<string, string> = {};
  const contentType = c.req.header("content-type");
  if (contentType) deliveryHeaders["content-type"] = contentType;
  if (signature) deliveryHeaders["x-webhook-signature"] = signature;
  if (timestampHeader) deliveryHeaders["x-webhook-timestamp"] = timestampHeader;

  // Filter out any sensitive headers case-insensitively
  for (const key of Object.keys(deliveryHeaders)) {
    if (SENSITIVE_HEADERS.has(key.toLowerCase())) {
      delete deliveryHeaders[key];
    }
  }

  const delivery = await safeFetch(endpoint.targetUrl, {
    method: "POST",
    headers: deliveryHeaders,
    body: rawBody || undefined,
  });

  const deliveryRow = {
    id: randomUUID(),
    eventId: eventRow.id,
    endpointId: endpoint.id,
    userId: endpoint.userId,
    attemptNumber: 1,
    statusCode: delivery.status || null,
    responseSnippet: delivery.body ? delivery.body.slice(0, 512) : null,
    durationMs: delivery.durationMs,
    errorCode: delivery.error || null,
    createdAt: new Date(),
  };

  await db.insert(schema.deliveryAttempts).values(deliveryRow).run();

  // 8. Return response
  return c.json(serializeEvent(eventRow), 200);
});
