export interface User {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  image?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Session {
  id: string;
  expiresAt: string;
  token: string;
  userId: string;
}

export interface AuthState {
  user: User | null;
  session: Session | null;
  loading: boolean;
}

export interface Endpoint {
  id: string;
  name: string;
  publicSlug: string;
  targetUrl: string;
  isActive: boolean;
  createdAt: string;
}

export interface DeliveryAttempt {
  id: string;
  eventId: string;
  endpointId: string;
  attemptNumber: number;
  statusCode: number | null;
  responseSnippet: string | null;
  durationMs: number | null;
  errorCode: string | null;
  createdAt: string;
}

export interface WebhookEvent {
  id: string;
  endpointId: string;
  method: string;
  headersJson: string;
  bodyText: string | null;
  signatureValid: boolean | null;
  receivedAt: string;
  latestStatusCode?: number | null;
  deliveryAttempts?: DeliveryAttempt[];
}

export interface ApiError {
  error: {
    code: string;
    message: string;
  };
}
