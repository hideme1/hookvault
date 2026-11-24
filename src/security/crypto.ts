/**
 * Cryptographic Primitives
 *
 * - AES-256-GCM encrypt/decrypt for endpoint signing secrets
 * - HMAC-SHA256 sign/verify with timing-safe comparison
 * - Timestamp replay-window check (±5 minutes)
 *
 * Referenced by: AGENTS.md §2.3
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

// ─── AES-256-GCM Encryption ───────────────────────────────────────────────────

/** IV length for AES-256-GCM (96 bits = 12 bytes, NIST recommended) */
const IV_LENGTH = 12;

/** GCM auth tag length in bytes */
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Returns a combined string: base64(iv):base64(ciphertext):base64(authTag)
 *
 * @param plaintext - The secret to encrypt (e.g., a webhook signing secret)
 * @param encryptionKey - 32-byte key as a hex string (64 hex chars)
 */
export function encrypt(plaintext: string, encryptionKey: string): string {
  const key = Buffer.from(encryptionKey, "hex");
  if (key.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)");
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    encrypted.toString("base64"),
    authTag.toString("base64"),
  ].join(":");
}

/**
 * Decrypt a string encrypted with `encrypt()`.
 *
 * @param encryptedValue - The iv:ciphertext:authTag string
 * @param encryptionKey - 32-byte key as a hex string (64 hex chars)
 */
export function decrypt(encryptedValue: string, encryptionKey: string): string {
  const key = Buffer.from(encryptionKey, "hex");
  if (key.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)");
  }

  const parts = encryptedValue.split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted value format (expected iv:ciphertext:authTag)");
  }

  const iv = Buffer.from(parts[0]!, "base64");
  const ciphertext = Buffer.from(parts[1]!, "base64");
  const authTag = Buffer.from(parts[2]!, "base64");

  const decipher = createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

// ─── Signing Secret Generation ─────────────────────────────────────────────────

/**
 * Generate a cryptographically secure 32-byte signing secret (hex-encoded).
 */
export function generateSigningSecret(): string {
  return randomBytes(32).toString("hex");
}

// ─── HMAC-SHA256 Signing & Verification ────────────────────────────────────────

/**
 * Sign a payload using HMAC-SHA256.
 *
 * @param payload - The raw body string to sign
 * @param secret - The signing secret (hex string)
 * @param timestamp - Unix timestamp (seconds) to include in the signed content
 * @returns The hex-encoded HMAC signature
 */
export function signPayload(
  payload: string,
  secret: string,
  timestamp: number
): string {
  const signedContent = `${timestamp}.${payload}`;
  return createHmac("sha256", secret).update(signedContent).digest("hex");
}

/**
 * Default replay window: ±5 minutes (300 seconds).
 */
const DEFAULT_REPLAY_WINDOW_SECONDS = 300;

export interface VerifyResult {
  valid: boolean;
  error?: "INVALID_SIGNATURE" | "TIMESTAMP_EXPIRED" | "INVALID_FORMAT";
}

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 * Also enforces a timestamp replay window (±5 minutes by default).
 *
 * @param payload - The raw body string
 * @param signature - The hex-encoded signature to verify
 * @param secret - The signing secret (hex string)
 * @param timestamp - The claimed timestamp (seconds since epoch)
 * @param options.replayWindowSeconds - Custom replay window (default: 300s)
 * @param options.nowSeconds - Override current time for testing
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string,
  timestamp: number,
  options: {
    replayWindowSeconds?: number;
    nowSeconds?: number;
  } = {}
): VerifyResult {
  const replayWindow = options.replayWindowSeconds ?? DEFAULT_REPLAY_WINDOW_SECONDS;
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);

  // 1. Replay window check
  const diff = Math.abs(now - timestamp);
  if (diff > replayWindow) {
    return { valid: false, error: "TIMESTAMP_EXPIRED" };
  }

  // 2. Compute expected signature
  const expected = signPayload(payload, secret, timestamp);

  // 3. Timing-safe comparison on equal-length buffers
  const sigBuf = Buffer.from(signature, "hex");
  const expectedBuf = Buffer.from(expected, "hex");

  if (sigBuf.length !== expectedBuf.length) {
    return { valid: false, error: "INVALID_FORMAT" };
  }

  const isValid = timingSafeEqual(sigBuf, expectedBuf);
  if (!isValid) {
    return { valid: false, error: "INVALID_SIGNATURE" };
  }

  return { valid: true };
}
