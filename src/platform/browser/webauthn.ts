import type { PlatformWebAuthn } from "../../core/platform/types";

/**
 * Browser `PlatformWebAuthn` — `navigator.credentials`. Same feature
 * detection `../../internal/passkeyEnrollment.ts`'s `isPasskeySupported()`
 * already performed pre-refactor (secure context + `PublicKeyCredential` +
 * `navigator.credentials.create` present); that function now delegates to
 * `isSupported()` here so there is exactly one implementation of the check.
 */
export const browserWebAuthn: PlatformWebAuthn = {
  isSupported(): boolean {
    return (
      typeof window !== "undefined" &&
      typeof navigator !== "undefined" &&
      typeof navigator.credentials?.create === "function" &&
      typeof (window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential === "function"
    );
  },
  create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null> {
    return navigator.credentials.create({ publicKey: options }) as Promise<PublicKeyCredential | null>;
  },
  get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential | null> {
    return navigator.credentials.get({ publicKey: options }) as Promise<PublicKeyCredential | null>;
  },
};
