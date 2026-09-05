/**
 * THE canonical base64 / base64url codec for this SDK — web AND React
 * Native. Deliberately dependency-free (pure bit manipulation): no
 * `atob`/`btoa` (absent on Hermes, RN's default JS engine, with no
 * guaranteed global polyfill) and no Node `Buffer` fallback (same absence
 * risk on a bare RN runtime without a bundler-level shim).
 *
 * This replaces a PRE-EXISTING BUG (B1, RN launch blocker): the previous
 * `./base64url.ts` used `atob`/`btoa` with a `Buffer.from(...)` fallback —
 * neither is an RN/Hermes global. That path was reached on EVERY RN
 * operation via `../core/platform/pkce.ts` (every `start()`), `../flow/
 * webauthn.ts` (passkey), and `../jwt.ts` (`mapSession()` on every
 * `getUser()`), so on stock Expo it threw `ReferenceError: Buffer is not
 * defined` and left the flow stuck in a permanent `status: "error"`. This
 * file is the fix: ONE codec, imported by every consumer (web and RN
 * alike, the latter via the `@jummon/auth/core` re-export in
 * `../core/index.ts`) — no separate "browser-first, Node/RN fallback"
 * branch anywhere, so there is nothing left to silently break on an engine
 * that has neither `atob` nor `Buffer`.
 *
 * Used directly by `./jwt.ts` (JWT payload decode, standard-alphabet-
 * agnostic), `../core/platform/pkce.ts` (PKCE `code_verifier`/opaque-id
 * generation), and `../flow/webauthn.ts` (WebAuthn options/response
 * encoding, which mixes both alphabets — see that file's own doc comment).
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

export function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
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

export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return bytesToBase64(arr).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  return base64ToBytes(value.replace(/-/g, "+").replace(/_/g, "/"));
}
