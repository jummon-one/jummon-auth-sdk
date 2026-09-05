import { describe, expect, it } from "vitest";
import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from "./base64";

describe("base64/base64url codec (dependency-free — no atob/btoa/Buffer, see this module's doc comment / B1)", () => {
  it("round-trips arbitrary byte lengths through base64 (0, 1, 2, 3, and non-multiple-of-3 lengths)", () => {
    for (const length of [0, 1, 2, 3, 4, 5, 16, 32, 100]) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 7 + 3) % 256);
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    }
  });

  it("round-trips arbitrary bytes through bytesToBase64Url -> base64UrlToBytes (url-safe alphabet, no padding)", () => {
    const original = new Uint8Array([0, 1, 2, 253, 254, 255, 16, 32, 64, 128]);
    const encoded = bytesToBase64Url(original);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(Array.from(base64UrlToBytes(encoded))).toEqual(Array.from(original));
  });

  it("bytesToBase64Url accepts a plain ArrayBuffer too (DOM WebAuthn fields like credential.rawId)", () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    expect(bytesToBase64Url(bytes.buffer)).toBe(bytesToBase64Url(bytes));
  });

  it("matches known base64 test vectors ('hello' / 'hello world')", () => {
    expect(bytesToBase64(new TextEncoder().encode("hello"))).toBe("aGVsbG8=");
    expect(bytesToBase64(new TextEncoder().encode("hello world"))).toBe("aGVsbG8gd29ybGQ=");
  });

  it("base64UrlToBytes tolerates missing padding, per RFC 4648 §5 ('hi' -> 'aGk', length 3 mod 4 == 3)", () => {
    const decoded = base64UrlToBytes("aGk");
    expect(new TextDecoder().decode(decoded)).toBe("hi");
  });

  it("decodes a standard-alphabet base64 string carrying UTF-8 JSON text (the fido_login_options outer-envelope shape)", () => {
    const json = JSON.stringify({ challenge: "abc", rpId: "example.com" });
    // Built with the browser's btoa() here only to construct an
    // independent test fixture — the SUT (base64ToBytes) never calls it.
    const standardBase64 = btoa(json);
    const decoded = new TextDecoder().decode(base64ToBytes(standardBase64));
    expect(JSON.parse(decoded)).toEqual({ challenge: "abc", rpId: "example.com" });
  });

  it("decodes a base64url string produced with the +/- and /-_ alphabet swap symmetrically", () => {
    const bytes = new Uint8Array([0xfb, 0xef]);
    const standard = bytesToBase64(bytes);
    expect(standard).toContain("+");
    const url = bytesToBase64Url(bytes);
    expect(url).toBe("--8");
    expect(base64UrlToBytes(url)).toEqual(bytes);
  });

  it("works with atob/btoa/Buffer all deleted from the global scope (B1 regression — see base64.regression.test.ts for the full flow-level version)", () => {
    const originalAtob = (globalThis as { atob?: unknown }).atob;
    const originalBtoa = (globalThis as { btoa?: unknown }).btoa;
    const originalBuffer = (globalThis as { Buffer?: unknown }).Buffer;
    // @ts-expect-error -- deliberately simulating a Hermes/RN global scope for this assertion
    delete globalThis.atob;
    // @ts-expect-error -- see above
    delete globalThis.btoa;
    // @ts-expect-error -- see above
    delete globalThis.Buffer;
    try {
      const bytes = new Uint8Array([9, 8, 7, 6, 5]);
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
      expect(base64UrlToBytes(bytesToBase64Url(bytes))).toEqual(bytes);
    } finally {
      (globalThis as { atob?: unknown }).atob = originalAtob;
      (globalThis as { btoa?: unknown }).btoa = originalBtoa;
      (globalThis as { Buffer?: unknown }).Buffer = originalBuffer;
    }
  });
});
