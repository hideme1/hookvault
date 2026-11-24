/**
 * Layer A — HMAC & Encryption Unit Tests
 *
 * Tests the Phase 1 security primitives in src/security/crypto.ts.
 * All tests in this file MUST PASS before Phase 3.
 */

import { describe, it, expect } from "vitest";
import {
  encrypt,
  decrypt,
  generateSigningSecret,
  signPayload,
  verifySignature,
} from "../../src/security/crypto.js";

// Stable 32-byte test key (64 hex chars)
const TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// ─── AES-256-GCM Encryption ───────────────────────────────────────────────────

describe("AES-256-GCM encrypt/decrypt", () => {
  it("round-trips a secret successfully", () => {
    const secret = "my-webhook-signing-secret-12345";
    const encrypted = encrypt(secret, TEST_KEY);
    const decrypted = decrypt(encrypted, TEST_KEY);
    expect(decrypted).toBe(secret);
  });

  it("produces different ciphertexts for the same plaintext (random IV)", () => {
    const secret = "same-secret";
    const enc1 = encrypt(secret, TEST_KEY);
    const enc2 = encrypt(secret, TEST_KEY);
    expect(enc1).not.toBe(enc2); // IVs differ
  });

  it("produces iv:ciphertext:authTag format", () => {
    const encrypted = encrypt("test", TEST_KEY);
    const parts = encrypted.split(":");
    expect(parts.length).toBe(3);
    // Each part should be valid base64
    for (const part of parts) {
      expect(() => Buffer.from(part!, "base64")).not.toThrow();
    }
  });

  it("throws on tampered ciphertext", () => {
    const encrypted = encrypt("secret-data", TEST_KEY);
    const parts = encrypted.split(":");
    // Tamper with the ciphertext portion
    const tamperedCiphertext = Buffer.from(parts[1]!, "base64");
    tamperedCiphertext[0] = (tamperedCiphertext[0]! ^ 0xff);
    parts[1] = tamperedCiphertext.toString("base64");
    const tampered = parts.join(":");

    expect(() => decrypt(tampered, TEST_KEY)).toThrow();
  });

  it("throws on tampered auth tag", () => {
    const encrypted = encrypt("secret-data", TEST_KEY);
    const parts = encrypted.split(":");
    // Tamper with the auth tag
    const tamperedTag = Buffer.from(parts[2]!, "base64");
    tamperedTag[0] = (tamperedTag[0]! ^ 0xff);
    parts[2] = tamperedTag.toString("base64");
    const tampered = parts.join(":");

    expect(() => decrypt(tampered, TEST_KEY)).toThrow();
  });

  it("throws on wrong decryption key", () => {
    const encrypted = encrypt("secret-data", TEST_KEY);
    const wrongKey = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it("throws on invalid key length (too short)", () => {
    expect(() => encrypt("test", "deadbeef")).toThrow(
      /ENCRYPTION_KEY must be exactly 32 bytes/
    );
  });

  it("throws on invalid encrypted format (missing parts)", () => {
    expect(() => decrypt("onlyonepart", TEST_KEY)).toThrow(
      /Invalid encrypted value format/
    );
  });

  it("handles empty string plaintext", () => {
    const encrypted = encrypt("", TEST_KEY);
    const decrypted = decrypt(encrypted, TEST_KEY);
    expect(decrypted).toBe("");
  });

  it("handles unicode plaintext", () => {
    const secret = "🔑 ключ 密钥 مفتاح";
    const encrypted = encrypt(secret, TEST_KEY);
    const decrypted = decrypt(encrypted, TEST_KEY);
    expect(decrypted).toBe(secret);
  });
});

// ─── Signing Secret Generation ─────────────────────────────────────────────────

describe("generateSigningSecret", () => {
  it("produces a 64-char hex string (32 bytes)", () => {
    const secret = generateSigningSecret();
    expect(secret).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(secret)).toBe(true);
  });

  it("generates unique secrets each call", () => {
    const s1 = generateSigningSecret();
    const s2 = generateSigningSecret();
    expect(s1).not.toBe(s2);
  });
});

// ─── HMAC-SHA256 Sign & Verify ─────────────────────────────────────────────────

describe("HMAC-SHA256 signPayload / verifySignature", () => {
  const secret = generateSigningSecret();
  const payload = '{"event":"order.created","id":123}';
  const now = Math.floor(Date.now() / 1000);

  it("valid signature with fresh timestamp returns valid: true", () => {
    const sig = signPayload(payload, secret, now);
    const result = verifySignature(payload, sig, secret, now, { nowSeconds: now });
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("tampered body returns valid: false (INVALID_SIGNATURE)", () => {
    const sig = signPayload(payload, secret, now);
    const result = verifySignature(
      payload + "TAMPERED",
      sig,
      secret,
      now,
      { nowSeconds: now }
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe("INVALID_SIGNATURE");
  });

  it("wrong secret returns valid: false (INVALID_SIGNATURE)", () => {
    const sig = signPayload(payload, secret, now);
    const wrongSecret = generateSigningSecret();
    const result = verifySignature(payload, sig, wrongSecret, now, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe("INVALID_SIGNATURE");
  });

  it("mismatched signature length returns INVALID_FORMAT without throwing", () => {
    // Short signature (not 64 hex chars)
    const result = verifySignature(payload, "deadbeef", secret, now, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe("INVALID_FORMAT");
  });

  it("empty signature returns INVALID_FORMAT without throwing", () => {
    const result = verifySignature(payload, "", secret, now, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe("INVALID_FORMAT");
  });

  it("expired timestamp (>5 min old) returns TIMESTAMP_EXPIRED", () => {
    const oldTimestamp = now - 301; // 5 min + 1 second ago
    const sig = signPayload(payload, secret, oldTimestamp);
    const result = verifySignature(payload, sig, secret, oldTimestamp, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe("TIMESTAMP_EXPIRED");
  });

  it("future timestamp (>5 min ahead) returns TIMESTAMP_EXPIRED", () => {
    const futureTimestamp = now + 301; // 5 min + 1 second in future
    const sig = signPayload(payload, secret, futureTimestamp);
    const result = verifySignature(payload, sig, secret, futureTimestamp, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(false);
    expect(result.error).toBe("TIMESTAMP_EXPIRED");
  });

  it("timestamp exactly at 5 min boundary is still valid", () => {
    const boundaryTimestamp = now - 300; // Exactly 5 min ago
    const sig = signPayload(payload, secret, boundaryTimestamp);
    const result = verifySignature(payload, sig, secret, boundaryTimestamp, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(true);
  });

  it("timestamp exactly at future 5 min boundary is still valid", () => {
    const boundaryTimestamp = now + 300; // Exactly 5 min in future
    const sig = signPayload(payload, secret, boundaryTimestamp);
    const result = verifySignature(payload, sig, secret, boundaryTimestamp, {
      nowSeconds: now,
    });
    expect(result.valid).toBe(true);
  });

  it("produces consistent signatures for same input", () => {
    const sig1 = signPayload(payload, secret, now);
    const sig2 = signPayload(payload, secret, now);
    expect(sig1).toBe(sig2);
  });

  it("produces different signatures for different timestamps", () => {
    const sig1 = signPayload(payload, secret, now);
    const sig2 = signPayload(payload, secret, now + 1);
    expect(sig1).not.toBe(sig2);
  });

  it("signature is a 64-char hex string (SHA-256 output)", () => {
    const sig = signPayload(payload, secret, now);
    expect(sig).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(sig)).toBe(true);
  });
});
