import { z } from "zod";

// ─── Shared Validators ─────────────────────────────────────────────────────────

const urlSchema = z.string().url().max(2048);
const nameSchema = z.string().min(1).max(255).trim();
const idSchema = z.string().min(1).max(64);

// ─── Input Schemas (.strict() — rejects unknown fields) ────────────────────────

/**
 * POST /api/endpoints — create a new webhook endpoint.
 * Accepts only name and targetUrl. All other fields (id, userId,
 * publicSlug, encryptedSecret, isActive, createdAt) are server-generated.
 */
export const createEndpointSchema = z
  .object({
    name: nameSchema,
    targetUrl: urlSchema,
  })
  .strict();

export type CreateEndpointInput = z.infer<typeof createEndpointSchema>;

/**
 * PATCH /api/endpoints/:id — update mutable endpoint fields.
 * Every field is optional, but at least one must be present.
 * Fields like id, userId, publicSlug, encryptedSecret, createdAt are NEVER accepted.
 */
export const updateEndpointSchema = z
  .object({
    name: nameSchema.optional(),
    targetUrl: urlSchema.optional(),
    isActive: z.boolean().optional(),
  })
  .strict()
  .refine(
    (data) => data.name !== undefined || data.targetUrl !== undefined || data.isActive !== undefined,
    { message: "At least one field must be provided for update" }
  );

export type UpdateEndpointInput = z.infer<typeof updateEndpointSchema>;

/**
 * POST /api/events/:id/replay — replay a previously-received webhook event.
 * Only allows an optional override target URL.
 */
export const replayEventSchema = z
  .object({
    targetUrlOverride: urlSchema.optional(),
  })
  .strict();

export type ReplayEventInput = z.infer<typeof replayEventSchema>;

// ─── Output DTO Schemas (explicit allowlists — NEVER expose secrets) ───────────

/**
 * Endpoint response — encryptedSecret is NEVER included.
 * Only these exact fields appear in API responses.
 */
export const endpointResponseSchema = z.object({
  id: idSchema,
  name: z.string(),
  publicSlug: z.string(),
  targetUrl: z.string(),
  isActive: z.boolean(),
  createdAt: z.string().datetime(),
});

export type EndpointResponse = z.infer<typeof endpointResponseSchema>;

/**
 * Serializer: transforms a raw DB row into a safe EndpointResponse.
 * Strips encryptedSecret and userId, formats timestamp.
 */
export function serializeEndpoint(row: {
  id: string;
  name: string;
  publicSlug: string;
  targetUrl: string;
  isActive: boolean;
  createdAt: Date;
}): EndpointResponse {
  return endpointResponseSchema.parse({
    id: row.id,
    name: row.name,
    publicSlug: row.publicSlug,
    targetUrl: row.targetUrl,
    isActive: row.isActive,
    createdAt: row.createdAt.toISOString(),
  });
}

/**
 * DeliveryAttempt response DTO.
 */
export const deliveryResponseSchema = z.object({
  id: idSchema,
  eventId: z.string(),
  endpointId: z.string(),
  attemptNumber: z.number().int(),
  statusCode: z.number().int().nullable(),
  responseSnippet: z.string().nullable(),
  durationMs: z.number().int().nullable(),
  errorCode: z.string().nullable(),
  createdAt: z.string().datetime(),
});

export type DeliveryResponse = z.infer<typeof deliveryResponseSchema>;

export function serializeDelivery(row: {
  id: string;
  eventId: string;
  endpointId: string;
  attemptNumber: number;
  statusCode: number | null;
  responseSnippet: string | null;
  durationMs: number | null;
  errorCode: string | null;
  createdAt: Date;
}): DeliveryResponse {
  return deliveryResponseSchema.parse({
    id: row.id,
    eventId: row.eventId,
    endpointId: row.endpointId,
    attemptNumber: row.attemptNumber,
    statusCode: row.statusCode,
    responseSnippet: row.responseSnippet,
    durationMs: row.durationMs,
    errorCode: row.errorCode,
    createdAt: row.createdAt.toISOString(),
  });
}

/**
 * WebhookEvent response DTO.
 */
export const eventResponseSchema = z.object({
  id: idSchema,
  endpointId: z.string(),
  method: z.string(),
  headersJson: z.string(),
  bodyText: z.string().nullable(),
  signatureValid: z.boolean().nullable(),
  receivedAt: z.string().datetime(),
  latestStatusCode: z.number().int().nullable().optional(),
  deliveryAttempts: z.array(deliveryResponseSchema).optional(),
});

export type EventResponse = z.infer<typeof eventResponseSchema>;

export function serializeEvent(
  row: {
    id: string;
    endpointId: string;
    method: string;
    headersJson: string;
    bodyText: string | null;
    signatureValid: boolean | null;
    receivedAt: Date;
  },
  deliveries?: Array<{
    id: string;
    eventId: string;
    endpointId: string;
    attemptNumber: number;
    statusCode: number | null;
    responseSnippet: string | null;
    durationMs: number | null;
    errorCode: string | null;
    createdAt: Date;
  }>,
  latestStatusCode?: number | null
): EventResponse {
  return eventResponseSchema.parse({
    id: row.id,
    endpointId: row.endpointId,
    method: row.method,
    headersJson: row.headersJson,
    bodyText: row.bodyText,
    signatureValid: row.signatureValid,
    receivedAt: row.receivedAt.toISOString(),
    ...(deliveries !== undefined ? { deliveryAttempts: deliveries.map(serializeDelivery) } : {}),
    ...(latestStatusCode !== undefined ? { latestStatusCode } : {}),
  });
}

export const eventDetailResponseSchema = eventResponseSchema.extend({
  deliveryAttempts: z.array(deliveryResponseSchema),
});

export type EventDetailResponse = z.infer<typeof eventDetailResponseSchema>;

export function serializeEventDetail(
  row: {
    id: string;
    endpointId: string;
    method: string;
    headersJson: string;
    bodyText: string | null;
    signatureValid: boolean | null;
    receivedAt: Date;
  },
  deliveries: Array<{
    id: string;
    eventId: string;
    endpointId: string;
    attemptNumber: number;
    statusCode: number | null;
    responseSnippet: string | null;
    durationMs: number | null;
    errorCode: string | null;
    createdAt: Date;
  }>,
  latestStatusCode?: number | null
): EventDetailResponse {
  return eventDetailResponseSchema.parse({
    id: row.id,
    endpointId: row.endpointId,
    method: row.method,
    headersJson: row.headersJson,
    bodyText: row.bodyText,
    signatureValid: row.signatureValid,
    receivedAt: row.receivedAt.toISOString(),
    deliveryAttempts: deliveries.map(serializeDelivery),
    ...(latestStatusCode !== undefined ? { latestStatusCode } : {}),
  });
}
