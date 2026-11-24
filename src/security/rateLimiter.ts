/**
 * Sliding-Window Rate Limiter
 *
 * In-memory rate limiter keyed by arbitrary string (endpointId, userId, IP, etc.).
 * Uses a sliding window algorithm for smooth rate limiting.
 *
 * Referenced by: AGENTS.md §2.5
 */

interface WindowEntry {
  /** Timestamps of requests within the current window */
  timestamps: number[];
  /** Start of the oldest tracked window */
  windowStart: number;
}

export interface RateLimitResult {
  allowed: boolean;
  /** Remaining requests in the current window */
  remaining: number;
  /** Unix ms when the window resets */
  resetAt: number;
  /** Milliseconds to wait before retrying (0 if allowed) */
  retryAfterMs: number;
  /** Total limit for the window */
  limit: number;
}

export interface RateLimiterOptions {
  /** Window size in milliseconds (default: 60_000 = 1 minute) */
  windowMs?: number;
  /** Maximum requests per window (default: 100) */
  maxRequests?: number;
}

export class RateLimiter {
  private readonly store = new Map<string, WindowEntry>();
  private readonly windowMs: number;
  private readonly maxRequests: number;

  constructor(options: RateLimiterOptions = {}) {
    this.windowMs = options.windowMs ?? 60_000;
    this.maxRequests = options.maxRequests ?? 100;
  }

  /**
   * Check if a request is allowed for the given key, and record it if so.
   *
   * @param key - Rate limit key (e.g., endpointId, userId, IP)
   * @param now - Current timestamp in ms (defaults to Date.now(), injectable for testing)
   */
  check(key: string, now: number = Date.now()): RateLimitResult {
    const windowStart = now - this.windowMs;
    let entry = this.store.get(key);

    if (!entry) {
      entry = { timestamps: [], windowStart };
      this.store.set(key, entry);
    }

    // Prune timestamps outside the current window
    entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
    entry.windowStart = windowStart;

    if (entry.timestamps.length >= this.maxRequests) {
      const oldest = entry.timestamps[0]!;
      const retryAfterMs = Math.max(1, oldest + this.windowMs - now);
      return {
        allowed: false,
        remaining: 0,
        resetAt: oldest + this.windowMs,
        retryAfterMs,
        limit: this.maxRequests,
      };
    }

    // Record this request
    entry.timestamps.push(now);

    return {
      allowed: true,
      remaining: this.maxRequests - entry.timestamps.length,
      resetAt: now + this.windowMs,
      retryAfterMs: 0,
      limit: this.maxRequests,
    };
  }

  /**
   * Reset the rate limit for a specific key.
   */
  reset(key: string): void {
    this.store.delete(key);
  }

  /**
   * Clear all rate limit entries. Useful for tests.
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Get the current count for a key without consuming a request.
   */
  peek(key: string, now: number = Date.now()): RateLimitResult {
    const windowStart = now - this.windowMs;
    const entry = this.store.get(key);

    if (!entry) {
      return {
        allowed: true,
        remaining: this.maxRequests,
        resetAt: now + this.windowMs,
        retryAfterMs: 0,
        limit: this.maxRequests,
      };
    }

    const activeTimestamps = entry.timestamps.filter((t) => t > windowStart);
    const remaining = Math.max(0, this.maxRequests - activeTimestamps.length);
    const allowed = remaining > 0;
    const oldest = activeTimestamps[0];
    const retryAfterMs = allowed || oldest === undefined ? 0 : Math.max(1, oldest + this.windowMs - now);

    return {
      allowed,
      remaining,
      resetAt: oldest !== undefined ? oldest + this.windowMs : now + this.windowMs,
      retryAfterMs,
      limit: this.maxRequests,
    };
  }
}
