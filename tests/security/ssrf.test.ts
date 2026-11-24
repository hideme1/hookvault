/**
 * Layer A — SSRF Defense Unit Tests
 *
 * Tests the Phase 1 security primitives in src/security/ssrf.ts.
 * All tests in this file MUST PASS before Phase 3.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validateUrl,
  safeFetch,
  isBlockedIPv4,
  isBlockedIPv6,
} from "../../src/security/ssrf.js";
import type { DnsLookupResult } from "../../src/security/ssrf.js";

function mockDns(address: string, family: 4 | 6): (hostname: string) => Promise<DnsLookupResult> {
  return async () => ({ address, family });
}

function failingDns(): (hostname: string) => Promise<DnsLookupResult> {
  return async () => {
    throw new Error("ENOTFOUND");
  };
}

describe("SSRF Defense Unit Tests", () => {
  const publicDns = mockDns("93.184.216.34", 4);

  beforeEach(() => {
    delete process.env["ALLOW_LOCAL_TARGETS"];
  });

  afterEach(() => {
    delete process.env["ALLOW_LOCAL_TARGETS"];
    vi.restoreAllMocks();
  });

  // ─── 1. Protocol allowlist & bypasses ──────────────────────────────────────

  describe("Protocol allowlist", () => {
    it("blocks http:// when ALLOW_LOCAL_TARGETS is not set", async () => {
      const res = await validateUrl("http://example.com/webhook", { resolveDns: publicDns });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("PROTOCOL_NOT_ALLOWED");
    });

    it("allows http:// when options.allowLocalTargets is true", async () => {
      const res = await validateUrl("http://example.com/webhook", {
        allowLocalTargets: true,
        resolveDns: publicDns,
      });
      expect(res.safe).toBe(true);
    });

    it("allows http:// when process.env.ALLOW_LOCAL_TARGETS is 'true'", async () => {
      process.env["ALLOW_LOCAL_TARGETS"] = "true";
      const res = await validateUrl("http://example.com/webhook", { resolveDns: publicDns });
      expect(res.safe).toBe(true);
    });

    it("blocks file:// protocol", async () => {
      const res = await validateUrl("file:///etc/passwd");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("PROTOCOL_NOT_ALLOWED");
    });

    it("blocks ftp:// protocol", async () => {
      const res = await validateUrl("ftp://files.example.com/data");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("PROTOCOL_NOT_ALLOWED");
    });

    it("blocks gopher:// protocol", async () => {
      const res = await validateUrl("gopher://old.example.com/1");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("PROTOCOL_NOT_ALLOWED");
    });

    it("blocks invalid URL strings", async () => {
      const res = await validateUrl("not-a-valid-url");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("INVALID_URL");
    });
  });

  // ─── 2. Direct IP literals in targetUrl ────────────────────────────────────

  describe("Direct IP literals in targetUrl", () => {
    it("blocks 127.0.0.1 (loopback)", async () => {
      const res = await validateUrl("https://127.0.0.1/admin");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks 10.0.0.1 (RFC 1918 Class A)", async () => {
      const res = await validateUrl("https://10.0.0.1/internal");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks 172.16.0.1 (RFC 1918 Class B)", async () => {
      const res = await validateUrl("https://172.16.0.1/api");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks 192.168.1.1 (RFC 1918 Class C)", async () => {
      const res = await validateUrl("https://192.168.1.1/router");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks 169.254.169.254 (cloud metadata)", async () => {
      const res = await validateUrl("https://169.254.169.254/latest/meta-data");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks 0.0.0.0", async () => {
      const res = await validateUrl("https://0.0.0.0/test");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks [::1] (IPv6 loopback)", async () => {
      const res = await validateUrl("https://[::1]/secret");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks [::ffff:127.0.0.1] (IPv6-mapped IPv4 loopback)", async () => {
      const res = await validateUrl("https://[::ffff:127.0.0.1]/secret");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks [::ffff:169.254.169.254] (IPv6-mapped cloud metadata)", async () => {
      const res = await validateUrl("https://[::ffff:169.254.169.254]/meta-data");
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("allows public IPv4 literal", async () => {
      const res = await validateUrl("https://93.184.216.34/webhook");
      expect(res.safe).toBe(true);
      expect(res.resolvedIp).toBe("93.184.216.34");
    });
  });

  // ─── 3. DNS resolution to private IPs ─────────────────────────────────────

  describe("DNS resolution to private IPs (DNS rebinding / evasion)", () => {
    it("blocks hostname resolving to 127.0.0.1", async () => {
      const res = await validateUrl("https://evil.example.com", {
        resolveDns: mockDns("127.0.0.1", 4),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to 10.0.0.1", async () => {
      const res = await validateUrl("https://internal.example.com", {
        resolveDns: mockDns("10.0.0.1", 4),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to 172.16.0.1", async () => {
      const res = await validateUrl("https://corp.example.com", {
        resolveDns: mockDns("172.16.0.1", 4),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to 192.168.1.1", async () => {
      const res = await validateUrl("https://lan.example.com", {
        resolveDns: mockDns("192.168.1.1", 4),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to 169.254.169.254", async () => {
      const res = await validateUrl("https://metadata.example.com", {
        resolveDns: mockDns("169.254.169.254", 4),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to ::1", async () => {
      const res = await validateUrl("https://ipv6-loopback.example.com", {
        resolveDns: mockDns("::1", 6),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to fc00::1 (IPv6 unique local)", async () => {
      const res = await validateUrl("https://ipv6-ula.example.com", {
        resolveDns: mockDns("fc00::1", 6),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to fe80::1 (IPv6 link-local)", async () => {
      const res = await validateUrl("https://ipv6-linklocal.example.com", {
        resolveDns: mockDns("fe80::1", 6),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("blocks hostname resolving to ::ffff:127.0.0.1", async () => {
      const res = await validateUrl("https://ipv6-mapped.example.com", {
        resolveDns: mockDns("::ffff:127.0.0.1", 6),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
    });

    it("returns DNS_RESOLUTION_FAILED when domain cannot be resolved", async () => {
      const res = await validateUrl("https://unresolvable-domain.invalid", {
        resolveDns: failingDns(),
      });
      expect(res.safe).toBe(false);
      expect(res.error).toBe("DNS_RESOLUTION_FAILED");
    });

    it("allows hostname resolving to public IP", async () => {
      const res = await validateUrl("https://api.stripe.com/webhook", {
        resolveDns: publicDns,
      });
      expect(res.safe).toBe(true);
      expect(res.resolvedIp).toBe("93.184.216.34");
    });
  });

  // ─── 4. safeFetch() protections ───────────────────────────────────────────

  describe("safeFetch() protections", () => {
    it("rejects 301 redirects with REDIRECT_BLOCKED", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(null, {
          status: 301,
          headers: { Location: "http://127.0.0.1/admin" },
        })
      );

      const res = await safeFetch("https://api.example.com/endpoint", {
        resolveDns: publicDns,
      });
      expect(res.ok).toBe(false);
      expect(res.status).toBe(301);
      expect(res.error).toBe("REDIRECT_BLOCKED");
    });

    it("rejects 302 redirects with REDIRECT_BLOCKED", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(null, {
          status: 302,
          headers: { Location: "http://169.254.169.254/latest" },
        })
      );

      const res = await safeFetch("https://api.example.com/endpoint", {
        resolveDns: publicDns,
      });
      expect(res.ok).toBe(false);
      expect(res.status).toBe(302);
      expect(res.error).toBe("REDIRECT_BLOCKED");
    });

    it("enforces 5-second timeout and returns TIMEOUT error", async () => {
      vi.spyOn(globalThis, "fetch").mockImplementation(
        () =>
          new Promise((_, reject) => {
            setTimeout(() => {
              reject(new DOMException("The operation was aborted.", "AbortError"));
            }, 50);
          })
      );

      const res = await safeFetch("https://slow-api.example.com", {
        resolveDns: publicDns,
      });
      expect(res.ok).toBe(false);
      expect(res.error).toBe("TIMEOUT");
    });

    it("truncates response bodies over 64 KB", async () => {
      const oversizedBody = "A".repeat(128 * 1024); // 128 KB
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(oversizedBody, { status: 200 })
      );

      const res = await safeFetch("https://large-api.example.com", {
        resolveDns: publicDns,
      });
      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      expect(res.body.length).toBeLessThanOrEqual(64 * 1024);
    });

    it("returns normal body when within 64 KB cap", async () => {
      const normalBody = JSON.stringify({ success: true, count: 42 });
      vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(normalBody, { status: 200 })
      );

      const res = await safeFetch("https://normal-api.example.com", {
        resolveDns: publicDns,
      });
      expect(res.ok).toBe(true);
      expect(res.status).toBe(200);
      expect(res.body).toBe(normalBody);
    });

    it("pre-emptively rejects safeFetch to private IP targetUrl without fetching", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch");

      const res = await safeFetch("https://127.0.0.1:8080/hook");
      expect(res.ok).toBe(false);
      expect(res.error).toBe("SSRF_BLOCKED_IP");
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("pre-emptively rejects safeFetch with http:// protocol unless allowed", async () => {
      const fetchSpy = vi.spyOn(globalThis, "fetch");

      const res = await safeFetch("http://example.com/hook");
      expect(res.ok).toBe(false);
      expect(res.error).toBe("PROTOCOL_NOT_ALLOWED");
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  // ─── 5. Raw helper functions ──────────────────────────────────────────────

  describe("isBlockedIPv4 & isBlockedIPv6 helpers", () => {
    it("isBlockedIPv4 checks expected ranges", () => {
      expect(isBlockedIPv4("127.0.0.1")).toBe(true);
      expect(isBlockedIPv4("10.0.0.1")).toBe(true);
      expect(isBlockedIPv4("172.16.0.1")).toBe(true);
      expect(isBlockedIPv4("192.168.1.1")).toBe(true);
      expect(isBlockedIPv4("169.254.169.254")).toBe(true);
      expect(isBlockedIPv4("0.0.0.0")).toBe(true);
      expect(isBlockedIPv4("8.8.8.8")).toBe(false);
      expect(isBlockedIPv4("1.1.1.1")).toBe(false);
    });

    it("isBlockedIPv6 checks expected ranges", () => {
      expect(isBlockedIPv6("::1")).toBe(true);
      expect(isBlockedIPv6("[::1]")).toBe(true);
      expect(isBlockedIPv6("fc00::1")).toBe(true);
      expect(isBlockedIPv6("fe80::1")).toBe(true);
      expect(isBlockedIPv6("::ffff:127.0.0.1")).toBe(true);
      expect(isBlockedIPv6("[::ffff:127.0.0.1]")).toBe(true);
      expect(isBlockedIPv6("::ffff:169.254.169.254")).toBe(true);
      expect(isBlockedIPv6("2001:db8::1")).toBe(false);
    });
  });
});
