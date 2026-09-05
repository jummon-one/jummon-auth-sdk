/**
 * Dependency-free base64/base64url codec — deliberately NOT using
 * `atob`/`btoa` (absent on Hermes, RN's default JS engine, with no
 * guaranteed global polyfill) or Node's `Buffer` (same absence risk on a
 * bare RN runtime without a bundler-level shim). Pure bit manipulation, so
 * it works identically on Hermes, JSC, or any other engine `react-native`
 * ships on. `@jummon/auth`'s own `src/internal/base64url.ts` assumes
 * `atob`/`btoa`/`Buffer` — safe on web/Node, not guaranteed on RN, which is
 * why this package doesn't reuse it.
 */

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array): string {
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const hasB1 = i + 1 < bytes.length;
    const hasB2 = i + 2 < bytes.length;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const triplet = (b0 << 16) | (b1 << 8) | b2;
    result += BASE64_CHARS[(triplet >> 18) & 0x3f];
    result += BASE64_CHARS[(triplet >> 12) & 0x3f];
    result += hasB1 ? BASE64_CHARS[(triplet >> 6) & 0x3f] : "=";
    result += hasB2 ? BASE64_CHARS[triplet & 0x3f] : "=";
  }
  return result;
}

export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/=+$/, "");
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    const value = BASE64_CHARS.indexOf(char);
    if (value === -1) {
      continue; // tolerate whitespace/newlines defensively
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(value: string): Uint8Array {
  return base64ToBytes(value.replace(/-/g, "+").replace(/_/g, "/"));
}
