/**
 * HookVault API Application
 *
 * Implements security headers, error handling with zero leakage,
 * Better Auth mounting, and tenant + public webhook routes.
 */

import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { cors } from "hono/cors";
import { HTTPException } from "hono/http-exception";
import { z } from "zod";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import path from "node:path";
import fs from "node:fs";
import { serveStatic } from "@hono/node-server/serve-static";
import * as schema from "./db/schema.js";
import { RateLimiter } from "./security/rateLimiter.js";
import { createAuth } from "./auth/index.js";
import { endpointsRouter } from "./routes/endpoints.js";
import { eventsRouter } from "./routes/events.js";
import { ingestRouter } from "./routes/ingest.js";

// Stable fallback encryption key matching testDb.ts
export const DEFAULT_ENCRYPTION_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

declare module "hono" {
  interface ContextVariableMap {
    user: typeof schema.user.$inferSelect;
    session: typeof schema.session.$inferSelect;
    db: any;
    auth: any;
    encryptionKey: string;
    rateLimiter: RateLimiter;
  }
}

export interface AppDeps {
  db?: any;
  auth?: any;
  encryptionKey?: string;
  rateLimiter?: RateLimiter;
}

export function createApp(deps?: AppDeps): Hono {
  const app = new Hono();

  // Resolve dependencies
  const db =
    deps?.db ??
    drizzle(new Database(process.env["DATABASE_URL"] ?? ":memory:"), { schema });

  const auth = deps?.auth ?? createAuth(db);

  const encryptionKey =
    deps?.encryptionKey ?? process.env["ENCRYPTION_KEY"] ?? DEFAULT_ENCRYPTION_KEY;

  const rateLimiter =
    deps?.rateLimiter ??
    new RateLimiter({
      windowMs: Number(process.env["RATE_LIMIT_WINDOW_MS"] ?? 60_000),
      maxRequests: Number(process.env["RATE_LIMIT_MAX_REQUESTS"] ?? 100),
    });

  // 1. Global Security Headers
  app.use(
    "*",
    secureHeaders({
      xContentTypeOptions: "nosniff",
      xFrameOptions: "DENY",
      referrerPolicy: "no-referrer",
      contentSecurityPolicy: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
      },
    })
  );

  // Strict CORS middleware (never wildcard on authenticated routes)
  const frontendOrigin = process.env["FRONTEND_ORIGIN"] || "http://localhost:5173";
  app.use(
    "*",
    cors({
      origin: frontendOrigin,
      credentials: true,
      allowHeaders: [
        "Content-Type",
        "Authorization",
        "Cookie",
        "x-hookvault-signature",
        "idempotency-key",
      ],
      allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    })
  );

  // 2. Attach dependencies to Hono context
  app.use("*", async (c, next) => {
    c.set("db", db);
    c.set("auth", auth);
    c.set("encryptionKey", encryptionKey);
    c.set("rateLimiter", rateLimiter);
    return next();
  });

  // 3. Global Error Handler (Zero leakage)
  app.onError((err, c) => {
    // Malformed JSON parsing errors
    if (
      err instanceof SyntaxError ||
      err.name === "SyntaxError" ||
      err.message?.toLowerCase().includes("json")
    ) {
      return c.json(
        {
          error: {
            code: "BAD_REQUEST",
            message: "Malformed JSON in request body",
          },
        },
        400
      );
    }

    // Zod validation errors
    if (err instanceof z.ZodError || err.name === "ZodError" || "issues" in (err as any)) {
      const zodErr = err as z.ZodError;
      const msg =
        zodErr.issues
          ?.map((i) => `${i.path.join(".") || "field"}: Invalid value`)
          .join("; ") || "Validation failed";

      return c.json(
        {
          error: {
            code: "VALIDATION_FAILED",
            message: msg,
          },
        },
        400
      );
    }

    // HTTPException
    if (err instanceof HTTPException) {
      return c.json(
        {
          error: {
            code: "HTTP_EXCEPTION",
            message: err.message || "Request failed",
          },
        },
        err.status
      );
    }

    // Unexpected internal error: no stack trace, no file paths, no SQL errors
    return c.json(
      {
        error: {
          code: "INTERNAL_SERVER_ERROR",
          message: "An internal server error occurred",
        },
      },
      500
    );
  });

  // 4. Structured 404 handler
  app.notFound((c) => {
    return c.json(
      {
        error: {
          code: "NOT_FOUND",
          message: "Resource not found",
        },
      },
      404
    );
  });

  // 5. Better Auth routes
  app.all("/api/auth/*", (c) => auth.handler(c.req.raw));

  // 6. Tenant API routes
  app.route("/api/endpoints", endpointsRouter);
  app.route("/api/events", eventsRouter);

  // 7. Public Webhook Ingestion & Relay route
  app.route("/in", ingestRouter);

  // 8. Serve compiled frontend static files in production mode
  if (process.env["NODE_ENV"] === "production") {
    const webDistPath = path.resolve(process.cwd(), "web/dist");
    if (fs.existsSync(webDistPath)) {
      app.use("/*", serveStatic({ root: "web/dist" }));
      app.get("*", async (c, next) => {
        if (c.req.path.startsWith("/api/") || c.req.path.startsWith("/in/")) {
          return next();
        }
        return serveStatic({ path: "web/dist/index.html" })(c, next);
      });
    }
  }

  return app;
}
