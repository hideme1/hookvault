import type { Context, Next } from "hono";
import { eq } from "drizzle-orm";
import * as schema from "../db/schema.js";

/**
 * Authentication middleware for tenant API routes.
 *
 * Resolves active session from Bearer token or Better Auth session cookie,
 * queries the session table (supporting seeded test DBs and live sessions),
 * attaches the active `user` and `session` to Hono context,
 * and returns 401 on missing or expired sessions.
 */
export async function requireAuth(c: Context, next: Next) {
  const db = c.get("db");
  const auth = c.get("auth");

  // 1. Resolve token from Authorization header or cookies
  let token: string | undefined;

  const authHeader = c.req.header("Authorization") || c.req.header("authorization");
  if (authHeader?.startsWith("Bearer ")) {
    token = authHeader.slice(7).trim();
  }

  if (!token) {
    const cookieHeader = c.req.header("Cookie") || c.req.header("cookie");
    if (cookieHeader) {
      const match = cookieHeader.match(/(?:^|;\s*)better-auth\.session_token=([^;]+)/);
      if (match && match[1]) {
        token = decodeURIComponent(match[1]);
      }
    }
  }

  let userRecord: typeof schema.user.$inferSelect | null = null;
  let sessionRecord: typeof schema.session.$inferSelect | null = null;

  if (token) {
    const rawToken = token.includes(".") ? token.split(".")[0] : token;
    const tokensToTry = [token];
    if (rawToken && rawToken !== token) {
      tokensToTry.push(rawToken);
    }

    for (const t of tokensToTry) {
      try {
        const res = await db
          .select({
            session: schema.session,
            user: schema.user,
          })
          .from(schema.session)
          .innerJoin(schema.user, eq(schema.session.userId, schema.user.id))
          .where(eq(schema.session.token, t))
          .get();

        if (res) {
          sessionRecord = res.session;
          userRecord = res.user;
          break;
        }
      } catch {
        // Continue to fallback
      }
    }
  }

  // 2. Fallback to Better Auth session resolver
  if (!userRecord && auth?.api?.getSession) {
    try {
      const betterSession = await auth.api.getSession({
        headers: c.req.raw.headers,
      });
      if (betterSession?.session && betterSession?.user) {
        sessionRecord = betterSession.session;
        userRecord = betterSession.user;
      }
    } catch {
      // Continue to 401
    }
  }

  // 3. Reject if unauthenticated
  if (!sessionRecord || !userRecord) {
    return c.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "Authentication required",
        },
      },
      401
    );
  }

  // 4. Reject if expired
  const expiresAt = new Date(sessionRecord.expiresAt);
  if (expiresAt.getTime() <= Date.now()) {
    return c.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "Session expired",
        },
      },
      401
    );
  }

  // 5. Attach to Hono context
  c.set("user", userRecord);
  c.set("session", sessionRecord);

  return next();
}
