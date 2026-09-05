import { describe, expect, it } from "vitest";
import { base64ToBytes, base64UrlToBytes, bytesToBase64, bytesToBase64Url } from "./base64";

describe("dependency-free base64/base64url codec", () => {
  it("round-trips arbitrary byte lengths through base64 (0, 1, 2, 3, and non-multiple-of-3 lengths)", () => {
    for (const length of [0, 1, 2, 3, 4, 5, 16, 32, 100]) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 7 + 3) % 256);
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    }
  });

  it("round-trips through base64url (no padding, - and _ instead of + and /)", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0x00, 0x10]);
    const url = bytesToBase64Url(bytes);
    expect(url).not.toMatch(/[+/=]/);
    expect(base64UrlToBytes(url)).toEqual(bytes);
  });

  it("matches known base64 test vectors ('hello' / 'hello world')", () => {
    expect(bytesToBase64(new TextEncoder().encode("hello"))).toBe("aGVsbG8=");
    expect(bytesToBase64(new TextEncoder().encode("hello world"))).toBe("aGVsbG8gd29ybGQ=");
  });

  it("decodes a base64url string produced by the browser package's alphabet swap identically", () => {
    // Same bytes, standard-alphabet base64 has a '+' and a '/' — confirms
    // the -/_ substitution round-trips correctly through this codec too.
    const bytes = new Uint8Array([0xfb, 0xef]);
    const standard = bytesToBase64(bytes); // "++8=" — 0xFB=11111011, 0xEF=11101111 -> base64 "++8="
    expect(standard).toContain("+");
    const url = bytesToBase64Url(bytes);
    expect(url).toBe("--8");
    expect(base64UrlToBytes(url)).toEqual(bytes);
  });
});
