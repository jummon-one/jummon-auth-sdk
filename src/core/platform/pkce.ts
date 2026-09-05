import { bytesToBase64Url } from "../../internal/base64url";
import type { PlatformCrypto } from "./types";

/**
 * PKCE (RFC 7636) pair generation, platform-agnostic via the injected
 * `PlatformCrypto`. Replaces `oidc-client-ts`'s `SigninState.create()` (the
 * one place the pre-refactor headless flow depended on that browser-oriented
 * library for something not actually browser-specific) so the core never
 * imports `oidc-client-ts` at all.
 *
 * `code_verifier`: 32 cryptographically-secure random bytes, base64url-encoded
 * → 43 characters, comfortably inside RFC 7636 §4.1's required 43-128
 * char range, and every base64url character (`A-Za-z0-9-_`) is in the
 * spec's `unreserved` set. Same approach `oidc-client-ts` and most other
 * spec-compliant PKCE implementations use (they concatenate UUIDs instead of
 * reading raw random bytes, but the resulting entropy/charset guarantee is
 * the same shape).
 *
 * `code_challenge` (S256): `BASE64URL(SHA256(ASCII(code_verifier)))` — RFC
 * 7636 §4.2, computed here exactly as `oidc-client-ts`'s
 * `CryptoUtils.generateCodeChallenge` did via `crypto.subtle.digest`, just
 * through the injected adapter instead of the global.
 */
export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

const CODE_VERIFIER_BYTES = 32;

export async function generatePkcePair(crypto: PlatformCrypto): Promise<PkcePair> {
  const codeVerifier = bytesToBase64Url(await crypto.randomBytes(CODE_VERIFIER_BYTES));
  const digest = await crypto.sha256(new TextEncoder().encode(codeVerifier));
  const codeChallenge = bytesToBase64Url(digest);
  return { codeVerifier, codeChallenge };
}

/**
 * An opaque, unguessable string for round-tripped values that carry no
 * format requirement of their own — the OIDC `state` param (CSRF-checked
 * back against the stored value in `resume()`) and the `nonce` param.
 * Previously `SigninState.id` (a UUIDv4) for `state` and a
 * `crypto.randomUUID()`-or-`Math.random()` fallback for `nonce`
 * (`headlessAuthFlow.ts`'s old free-standing `generateNonce()`); neither
 * consumer (this SDK's own CSRF check, the auth-engine's nonce echo)
 * requires UUID formatting specifically, only sufficient entropy and
 * uniqueness — base64url(16 random bytes) satisfies both without depending
 * on `crypto.randomUUID` being present.
 */
export async function generateOpaqueId(crypto: PlatformCrypto, byteLength = 16): Promise<string> {
  return bytesToBase64Url(await crypto.randomBytes(byteLength));
}
