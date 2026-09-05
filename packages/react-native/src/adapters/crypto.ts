import type { PlatformCrypto } from "@jummon/auth/core";

/**
 * Structural shape of `expo-crypto`'s module — defined locally (never
 * imported from the real package, same reasoning as `storage.ts`'s
 * `AsyncStorageLike`). `getRandomBytesAsync` is `expo-crypto`'s CSPRNG
 * (there is no RN-runtime `crypto.getRandomValues` — Hermes doesn't ship
 * one); `digest` is the newer `Crypto.digest(algorithm, data)` API
 * (`CryptoDigestAlgorithm.SHA256` === the string `"SHA-256"` used below),
 * chosen over the string-based `digestStringAsync` because
 * `PlatformCrypto.sha256` is byte-in/byte-out (RFC 7636 §4.2 operates on the
 * `code_verifier`'s raw ASCII bytes, not a pre-encoded string).
 */
export interface ExpoCryptoLike {
  getRandomBytesAsync(byteCount: number): Promise<Uint8Array>;
  digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
}

/**
 * `PlatformCrypto.randomBytes` is `Uint8Array | Promise<Uint8Array>`
 * specifically so this adapter can return the native bridge's async result
 * directly — see that interface's doc comment (`@jummon/auth/core`) for why
 * the union exists instead of forcing RN's genuinely-async CSPRNG into a
 * fake-sync shape.
 */
export function createReactNativeCrypto(expoCrypto: ExpoCryptoLike): PlatformCrypto {
  return {
    randomBytes(length: number): Promise<Uint8Array> {
      return expoCrypto.getRandomBytesAsync(length);
    },
    async sha256(data: Uint8Array): Promise<Uint8Array> {
      const digest = await expoCrypto.digest("SHA-256", data);
      return new Uint8Array(digest);
    },
  };
}
