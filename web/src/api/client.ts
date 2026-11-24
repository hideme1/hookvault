import type {
  User,
  Session,
  Endpoint,
  WebhookEvent,
  DeliveryAttempt,
  ApiError,
} from "../types";

export class RequestError extends Error {
  code: string;
  status: number;

  constructor(message: string, code: string, status: number) {
    super(message);
    this.name = "RequestError";
    this.code = code;
    this.status = status;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  const text = await res.text();
  let json: any = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      // Not JSON
    }
  }

  if (!res.ok) {
    if (json?.error) {
      const err = json as ApiError;
      throw new RequestError(err.error.message, err.error.code, res.status);
    }
    throw new RequestError(
      json?.message || text || `Request failed with status ${res.status}`,
      "UNKNOWN_ERROR",
      res.status
    );
  }

  return json as T;
}

export const api = {
  // Better Auth endpoints
  auth: {
    async getSession(): Promise<{ user: User; session: Session } | null> {
      try {
        const res = await fetch("/api/auth/get-session", {
          method: "GET",
          credentials: "include",
          headers: { Accept: "application/json" },
        });
        if (!res.ok) return null;
        const data = await res.json();
        if (data?.user && data?.session) {
          return data;
        }
        return null;
      } catch {
        return null;
      }
    },

    async signIn(email: string, password: string): Promise<{ user: User; session: Session }> {
      const res = await fetch("/api/auth/sign-in/email", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ email, password }),
      });
      return handleResponse<{ user: User; session: Session }>(res);
    },

    async signUp(name: string, email: string, password: string): Promise<{ user: User; session: Session }> {
      const res = await fetch("/api/auth/sign-up/email", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ name, email, password }),
      });
      return handleResponse<{ user: User; session: Session }>(res);
    },

    async signOut(): Promise<void> {
      await fetch("/api/auth/sign-out", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });
    },
  },

  // Endpoints Manager
  endpoints: {
    async list(): Promise<Endpoint[]> {
      const res = await fetch("/api/endpoints", {
        method: "GET",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      return handleResponse<Endpoint[]>(res);
    },

    async create(data: { name: string; targetUrl: string }): Promise<Endpoint> {
      const res = await fetch("/api/endpoints", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(data),
      });
      return handleResponse<Endpoint>(res);
    },

    async delete(id: string): Promise<{ success: boolean }> {
      const res = await fetch(`/api/endpoints/${id}`, {
        method: "DELETE",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      return handleResponse<{ success: boolean }>(res);
    },
  },

  // Events & Replay
  events: {
    async list(endpointId?: string): Promise<WebhookEvent[]> {
      const url = endpointId
        ? `/api/events?endpointId=${encodeURIComponent(endpointId)}`
        : "/api/events";
      const res = await fetch(url, {
        method: "GET",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      return handleResponse<WebhookEvent[]>(res);
    },

    async get(id: string): Promise<WebhookEvent> {
      const res = await fetch(`/api/events/${id}`, {
        method: "GET",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      return handleResponse<WebhookEvent>(res);
    },

    async replay(id: string, targetUrlOverride?: string): Promise<DeliveryAttempt> {
      const body = targetUrlOverride ? { targetUrlOverride } : {};
      const res = await fetch(`/api/events/${id}/replay`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      });
      return handleResponse<DeliveryAttempt>(res);
    },
  },

  // Public Webhook Ingestion (for test drawer)
  ingest: {
    async sendTest(
      publicSlug: string,
      payload: string,
      headers: Record<string, string> = {}
    ): Promise<{ status: number; body: string }> {
      const res = await fetch(`/in/${publicSlug}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
        body: payload,
      });
      const body = await res.text();
      return { status: res.status, body };
    },
  },
};
