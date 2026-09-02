/**
 * Binary-safe base64 / base64url helpers, browser-first with a Node fallback
 * for build tooling and tests (mirrors the pattern already used by
 * `../jwt.ts`). Shared by `jwt.ts` (JWT payload decode, standard-alphabet-
 * agnostic) and `../flow/webauthn.ts` (WebAuthn options/response encoding,
 * which mixes both alphabets — see that file's doc comment).
 */

export function base64UrlToBytes(segment: string): Uint8Array<ArrayBuffer> {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
}

export function base64ToBytes(segment: string): Uint8Array<ArrayBuffer> {
  if (typeof atob === "function") {
    const binary = atob(segment);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Non-browser fallback (SSR build tooling, tests).
  return new Uint8Array(Buffer.from(segment, "base64"));
}

export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of arr) {
      binary += String.fromCharCode(byte);
    }
    return toBase64Url(btoa(binary));
  }
  return toBase64Url(Buffer.from(arr).toString("base64"));
}

function toBase64Url(base64: string): string {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
