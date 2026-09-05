import { describe, expect, it, vi } from "vitest";
import { createReactNativeCrypto, type ExpoCryptoLike } from "./crypto";

function mockExpoCrypto(): ExpoCryptoLike {
  return {
    getRandomBytesAsync: vi.fn(async (length: number) => new Uint8Array(length).fill(7)),
    digest: vi.fn(async (_algorithm, data: Uint8Array) => {
      // Deterministic fake digest for assertions — not a real SHA-256.
      const out = new Uint8Array(32);
      out.set(data.slice(0, 32));
      return out.buffer;
    }),
  };
}

describe("createReactNativeCrypto", () => {
  it("randomBytes() delegates to expo-crypto's getRandomBytesAsync and resolves (async, per the PlatformCrypto union)", async () => {
    const expoCrypto = mockExpoCrypto();
    const crypto = createReactNativeCrypto(expoCrypto);

    const result = await crypto.randomBytes(32);

    expect(expoCrypto.getRandomBytesAsync).toHaveBeenCalledWith(32);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("sha256() calls expo-crypto's digest with \"SHA-256\" and returns a Uint8Array (ArrayBuffer normalized to bytes)", async () => {
    const expoCrypto = mockExpoCrypto();
    const crypto = createReactNativeCrypto(expoCrypto);
    const input = new TextEncoder().encode("hello");

    const digest = await crypto.sha256(input);

    expect(expoCrypto.digest).toHaveBeenCalledWith("SHA-256", input);
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(digest.length).toBe(32);
  });
});
