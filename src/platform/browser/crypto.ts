import { JummonAuthError } from "../../errors";
import type { PlatformCrypto } from "../../core/platform/types";

/**
 * Browser `PlatformCrypto` — the Web Crypto API
 * (`crypto.getRandomValues`/`crypto.subtle.digest`), the exact primitives
 * `oidc-client-ts`'s `CryptoUtils` used under the hood pre-refactor. Requires
 * a secure context (HTTPS or localhost) for `crypto.subtle` — same
 * requirement `oidc-client-ts` had, just surfaced as a clear
 * `JummonAuthError` instead of `crypto.subtle` being `undefined` and the
 * call throwing an opaque `TypeError` deep inside PKCE generation.
 */
export const browserCrypto: PlatformCrypto = {
  randomBytes(length: number): Uint8Array {
    if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
      throw new JummonAuthError(
        "ssr_unsupported",
        "crypto.getRandomValues is not available in this environment — createJummonAuth() must run in a browser context.",
      );
    }
    return crypto.getRandomValues(new Uint8Array(length));
  },
  async sha256(data: Uint8Array): Promise<Uint8Array> {
    if (typeof crypto === "undefined" || !crypto.subtle) {
      throw new JummonAuthError(
        "ssr_unsupported",
        "crypto.subtle is not available in this environment — PKCE requires a secure context (HTTPS or localhost).",
      );
    }
    const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
    return new Uint8Array(digest);
  },
};
