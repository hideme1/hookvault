/**
 * SSRF Defense Module
 *
 * Validates target URLs before outbound webhook delivery:
 * 1. Protocol allowlist (https only; http only if ALLOW_LOCAL_TARGETS=true)
 * 2. DNS resolution + IPv4/IPv6 private range blocking
 * 3. Safe fetch wrapper with redirect:'manual', 5s timeout, 64KB cap
 *
 * Referenced by: AGENTS.md §2.2
 */

import { lookup } from "node:dns/promises";

// ─── Private/Reserved IP Ranges ────────────────────────────────────────────────

interface CidrRange {
  readonly network: bigint;
  readonly mask: bigint;
}

/**
 * Parse a CIDR notation string into network + mask as bigints (for IPv4, treated as 32-bit).
 */
function parseCidrV4(cidr: string): CidrRange {
  const [ip, bits] = cidr.split("/") as [string, string];
  const parts = ip.split(".").map(Number);
  const addr =
    BigInt(parts[0]!) << 24n |
    BigInt(parts[1]!) << 16n |
    BigInt(parts[2]!) << 8n |
    BigInt(parts[3]!);
  const prefixLen = parseInt(bits, 10);
  const mask = prefixLen === 0 ? 0n : ((1n << 32n) - 1n) << BigInt(32 - prefixLen);
  return { network: addr & mask, mask };
}

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".").map(Number);
  return (
    BigInt(parts[0]!) << 24n |
    BigInt(parts[1]!) << 16n |
    BigInt(parts[2]!) << 8n |
    BigInt(parts[3]!)
  );
}

/**
 * Normalizes an IPv6 address string, expanding embedded IPv4 dotted-decimal
 * representations (e.g., ::ffff:127.0.0.1 -> ::ffff:7f00:1) and stripping brackets.
 */
function normalizeIpv6(ip: string): string {
  let clean = ip.replace(/^\[|\]$/g, "");
  const lastColon = clean.lastIndexOf(":");
  if (lastColon !== -1) {
    const maybeV4 = clean.slice(lastColon + 1);
    if (maybeV4.includes(".")) {
      const parts = maybeV4.split(".").map(Number);
      if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
        const hex1 = (((parts[0]! << 8) | parts[1]!) >>> 0).toString(16);
        const hex2 = (((parts[2]! << 8) | parts[3]!) >>> 0).toString(16);
        clean = clean.slice(0, lastColon) + ":" + hex1 + ":" + hex2;
      }
    }
  }
  return clean;
}

function ipv6ToBigInt(ip: string): bigint {
  const clean = normalizeIpv6(ip);
  // Expand :: notation
  const halves = clean.split("::");
  let groups: string[];

  if (halves.length === 2) {
    const left = halves[0] === "" ? [] : halves[0]!.split(":");
    const right = halves[1] === "" ? [] : halves[1]!.split(":");
    const fill = 8 - left.length - right.length;
    groups = [...left, ...Array<string>(fill).fill("0"), ...right];
  } else {
    groups = clean.split(":");
  }

  let result = 0n;
  for (const g of groups) {
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
}

interface CidrRangeV6 {
  readonly network: bigint;
  readonly mask: bigint;
}

function parseCidrV6(cidr: string): CidrRangeV6 {
  const slashIdx = cidr.lastIndexOf("/");
  const ip = cidr.slice(0, slashIdx);
  const prefixLen = parseInt(cidr.slice(slashIdx + 1), 10);
  const addr = ipv6ToBigInt(ip);
  const mask = prefixLen === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefixLen);
  return { network: addr & mask, mask };
}

/** Blocked IPv4 CIDR ranges per AGENTS.md §2.2 */
const BLOCKED_IPV4_CIDRS: readonly CidrRange[] = [
  parseCidrV4("0.0.0.0/8"),       // "this" network
  parseCidrV4("10.0.0.0/8"),      // RFC 1918
  parseCidrV4("127.0.0.0/8"),     // loopback
  parseCidrV4("169.254.0.0/16"),  // link-local
  parseCidrV4("172.16.0.0/12"),   // RFC 1918
  parseCidrV4("192.168.0.0/16"),  // RFC 1918
];

/** Blocked IPv6 ranges */
const BLOCKED_IPV6_CIDRS: readonly CidrRangeV6[] = [
  parseCidrV6("::1/128"),         // loopback
  parseCidrV6("fc00::/7"),        // unique local
  parseCidrV6("fe80::/10"),       // link-local
];

// Also block IPv4-mapped IPv6 addresses (::ffff:0:0/96)
const IPV4_MAPPED_PREFIX = ipv6ToBigInt("::ffff:0:0");
const IPV4_MAPPED_MASK = ((1n << 128n) - 1n) << 32n; // top 96 bits

function isBlockedIPv4(ip: string): boolean {
  try {
    const addr = ipv4ToBigInt(ip);
    return BLOCKED_IPV4_CIDRS.some((r) => (addr & r.mask) === r.network);
  } catch {
    return true; // fail-closed
  }
}

function isBlockedIPv6(ip: string): boolean {
  try {
    const addr = ipv6ToBigInt(ip);

    // Check if it's an IPv4-mapped IPv6 (::ffff:x.x.x.x) — apply v4 rules
    if ((addr & IPV4_MAPPED_MASK) === IPV4_MAPPED_PREFIX) {
      const v4Part = addr & 0xFFFFFFFFn;
      const v4Str = [
        Number((v4Part >> 24n) & 0xFFn),
        Number((v4Part >> 16n) & 0xFFn),
        Number((v4Part >> 8n) & 0xFFn),
        Number(v4Part & 0xFFn),
      ].join(".");
      return isBlockedIPv4(v4Str);
    }

    return BLOCKED_IPV6_CIDRS.some((r) => (addr & r.mask) === r.network);
  } catch {
    return true; // fail-closed
  }
}

// ─── Public API ────────────────────────────────────────────────────────────────

export interface SsrfValidationResult {
  safe: boolean;
  error?: string;
  resolvedIp?: string;
}

/** DNS lookup result shape (matches node:dns/promises lookup) */
export interface DnsLookupResult {
  address: string;
  family: 4 | 6;
}

/** Default DNS resolver using node:dns/promises */
async function defaultResolveDns(hostname: string): Promise<DnsLookupResult> {
  const result = await lookup(hostname, { all: false });
  return { address: result.address, family: result.family as 4 | 6 };
}

export interface ValidateUrlOptions {
  allowLocalTargets?: boolean;
  /** Injectable DNS resolver for testing */
  resolveDns?: (hostname: string) => Promise<DnsLookupResult>;
}

/**
 * Validate a URL for SSRF safety:
 * - Protocol check (https required; http only in test mode or with ALLOW_LOCAL_TARGETS=true)
 * - Raw IP literal check (blocks private/reserved IPv4 & IPv6 immediately)
 * - DNS resolution + private IP blocking
 */
export async function validateUrl(
  targetUrl: string,
  options: ValidateUrlOptions = {}
): Promise<SsrfValidationResult> {
  const resolveDns = options.resolveDns ?? defaultResolveDns;

  // 1. Parse URL
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { safe: false, error: "INVALID_URL" };
  }

  // 2. Protocol check
  const allowHttp =
    options.allowLocalTargets === true || process.env["ALLOW_LOCAL_TARGETS"] === "true";
  if (parsed.protocol === "http:" && !allowHttp) {
    return { safe: false, error: "PROTOCOL_NOT_ALLOWED" };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { safe: false, error: "PROTOCOL_NOT_ALLOWED" };
  }

  // 3. Raw IP literal check
  const rawHostname = parsed.hostname;
  const cleanHost = rawHostname.replace(/^\[|\]$/g, "");

  // IPv4 literal
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleanHost)) {
    if (isBlockedIPv4(cleanHost)) {
      return { safe: false, error: "SSRF_BLOCKED_IP", resolvedIp: cleanHost };
    }
    return { safe: true, resolvedIp: cleanHost };
  }

  // IPv6 literal
  if (cleanHost.includes(":")) {
    if (isBlockedIPv6(cleanHost)) {
      return { safe: false, error: "SSRF_BLOCKED_IP", resolvedIp: cleanHost };
    }
    return { safe: true, resolvedIp: cleanHost };
  }

  // 4. DNS resolution — resolve hostname to IP, then check ranges
  try {
    const result = await resolveDns(cleanHost);
    const ip = result.address;
    const cleanIp = ip.replace(/^\[|\]$/g, "");

    if (cleanIp.includes(":") || result.family === 6) {
      if (isBlockedIPv6(cleanIp)) {
        return { safe: false, error: "SSRF_BLOCKED_IP", resolvedIp: cleanIp };
      }
    } else {
      if (isBlockedIPv4(cleanIp)) {
        return { safe: false, error: "SSRF_BLOCKED_IP", resolvedIp: cleanIp };
      }
    }

    return { safe: true, resolvedIp: cleanIp };
  } catch {
    return { safe: false, error: "DNS_RESOLUTION_FAILED" };
  }
}

/** Maximum response body size: 64 KB */
const MAX_RESPONSE_BYTES = 64 * 1024;

/** Request timeout: 5 seconds */
const FETCH_TIMEOUT_MS = 5000;

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  body: string;
  durationMs: number;
  error?: string;
}

/**
 * Perform a safe outbound HTTP request with SSRF protections:
 * - Validates URL against SSRF rules
 * - redirect: 'manual' (never follows redirects into internal IPs)
 * - 5s hard timeout via AbortController
 * - 64 KB response body cap
 */
export async function safeFetch(
  targetUrl: string,
  init: RequestInit & {
    allowLocalTargets?: boolean;
    resolveDns?: (hostname: string) => Promise<DnsLookupResult>;
  } = {}
): Promise<SafeFetchResult> {
  const { allowLocalTargets, resolveDns, ...fetchInit } = init;
  const start = Date.now();

  // 1. SSRF validation
  const validation = await validateUrl(targetUrl, { allowLocalTargets, resolveDns });
  if (!validation.safe) {
    return {
      ok: false,
      status: 0,
      body: "",
      durationMs: Date.now() - start,
      error: validation.error,
    };
  }

  // 2. Fetch with timeout + redirect: manual
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(targetUrl, {
      ...fetchInit,
      redirect: "manual",
      signal: controller.signal,
    });

    // 3. If the response is a redirect, block it (don't follow)
    if (response.status >= 300 && response.status < 400) {
      return {
        ok: false,
        status: response.status,
        body: "",
        durationMs: Date.now() - start,
        error: "REDIRECT_BLOCKED",
      };
    }

    // 4. Read body with 64 KB cap
    let body = "";
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      let totalBytes = 0;
      const chunks: Uint8Array[] = [];

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          reader.cancel().catch(() => { /* ignore */ });
          const truncated = value.slice(
            0,
            value.byteLength - (totalBytes - MAX_RESPONSE_BYTES)
          );
          chunks.push(truncated);
          break;
        }
        chunks.push(value);
      }

      const decoder = new TextDecoder();
      body =
        chunks.map((c) => decoder.decode(c, { stream: true })).join("") +
        decoder.decode();
    } else if (response.text) {
      const text = await response.text();
      body = text.slice(0, MAX_RESPONSE_BYTES);
    }

    return {
      ok: response.ok,
      status: response.status,
      body: body.slice(0, MAX_RESPONSE_BYTES), // extra safety
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const errorCode =
      err instanceof DOMException && err.name === "AbortError"
        ? "TIMEOUT"
        : "NETWORK_ERROR";
    return {
      ok: false,
      status: 0,
      body: "",
      durationMs: Date.now() - start,
      error: errorCode,
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ─── Exports for testing ───────────────────────────────────────────────────────

export { isBlockedIPv4, isBlockedIPv6, normalizeIpv6 };
