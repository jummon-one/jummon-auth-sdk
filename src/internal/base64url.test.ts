import { describe, expect, it } from "vitest";
import { base64ToBytes, base64UrlToBytes, bytesToBase64Url } from "./base64url";

describe("base64url roundtrip", () => {
  it("round-trips arbitrary bytes through bytesToBase64Url -> base64UrlToBytes", () => {
    const original = new Uint8Array([0, 1, 2, 253, 254, 255, 16, 32, 64, 128]);
    const encoded = bytesToBase64Url(original);
    expect(encoded).not.toMatch(/[+/=]/); // url-safe alphabet, no padding
    const decoded = base64UrlToBytes(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it("decodes a standard-alphabet base64 string carrying UTF-8 JSON text (the fido_login_options envelope shape)", () => {
    const json = JSON.stringify({ challenge: "abc", rpId: "example.com" });
    const standardBase64 = btoa(json);
    const decoded = new TextDecoder().decode(base64ToBytes(standardBase64));
    expect(JSON.parse(decoded)).toEqual({ challenge: "abc", rpId: "example.com" });
  });

  it("base64UrlToBytes tolerates missing padding, per RFC 4648 §5", () => {
    // "hi" -> base64url "aGk" (no padding, length 3 mod 4 == 3)
    const decoded = base64UrlToBytes("aGk");
    expect(new TextDecoder().decode(decoded)).toBe("hi");
  });
});
