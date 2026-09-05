import { describe, expect, it, vi } from "vitest";
import { base64UrlToBytes, bytesToBase64Url } from "@jummon/auth/core";
import {
  createReactNativeWebAuthn,
  type PasskeyCreateResult,
  type PasskeyGetResult,
  type ReactNativePasskeyLike,
} from "./webauthn";

function bytes(...values: number[]): Uint8Array<ArrayBuffer> {
  return new Uint8Array(values);
}

describe("createReactNativeWebAuthn", () => {
  it("isSupported() delegates straight to react-native-passkey", () => {
    const passkey: ReactNativePasskeyLike = {
      isSupported: vi.fn().mockReturnValue(true),
      create: vi.fn(),
      get: vi.fn(),
    };
    const webauthn = createReactNativeWebAuthn(passkey);

    expect(webauthn.isSupported()).toBe(true);
    expect(passkey.isSupported).toHaveBeenCalledTimes(1);
  });

  it("create(): base64url-encodes DOM binary fields into the JSON request, and decodes the JSON result back into DOM-shaped binary fields", async () => {
    const challenge = bytes(1, 2, 3, 4);
    const userId = bytes(9, 9, 9);
    const fakeResult: PasskeyCreateResult = {
      id: "cred-1",
      rawId: bytesToBase64Url(bytes(5, 6, 7)),
      response: {
        clientDataJSON: bytesToBase64Url(bytes(10, 11)),
        attestationObject: bytesToBase64Url(bytes(12, 13, 14)),
      },
    };
    const create = vi.fn().mockResolvedValue(fakeResult);
    const passkey: ReactNativePasskeyLike = { isSupported: vi.fn(), create, get: vi.fn() };
    const webauthn = createReactNativeWebAuthn(passkey);

    const credential = await webauthn.create({
      rp: { id: "acme.com", name: "Acme" },
      user: { id: userId, name: "jane", displayName: "Jane" },
      challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    });

    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        challenge: bytesToBase64Url(challenge),
        user: expect.objectContaining({ id: bytesToBase64Url(userId), name: "jane", displayName: "Jane" }),
      }),
    );
    expect(credential?.id).toBe("cred-1");
    expect(credential?.rawId).toEqual(bytes(5, 6, 7));
    const response = credential?.response as unknown as { clientDataJSON: Uint8Array; attestationObject: Uint8Array };
    expect(response.clientDataJSON).toEqual(bytes(10, 11));
    expect(response.attestationObject).toEqual(bytes(12, 13, 14));
    expect(credential?.getClientExtensionResults()).toEqual({});
  });

  it("create() returns null when react-native-passkey resolves null (user cancelled)", async () => {
    const passkey: ReactNativePasskeyLike = {
      isSupported: vi.fn(),
      create: vi.fn().mockResolvedValue(null),
      get: vi.fn(),
    };
    const webauthn = createReactNativeWebAuthn(passkey);

    const result = await webauthn.create({
      rp: { name: "Acme" },
      user: { id: bytes(1), name: "jane", displayName: "Jane" },
      challenge: bytes(1),
      pubKeyCredParams: [],
    });

    expect(result).toBeNull();
  });

  it("get(): base64url round-trips the assertion, including a null userHandle", async () => {
    const challenge = bytes(1, 2);
    const fakeResult: PasskeyGetResult = {
      id: "cred-1",
      rawId: bytesToBase64Url(bytes(5)),
      response: {
        clientDataJSON: bytesToBase64Url(bytes(1)),
        authenticatorData: bytesToBase64Url(bytes(2)),
        signature: bytesToBase64Url(bytes(3)),
        userHandle: null,
      },
    };
    const get = vi.fn().mockResolvedValue(fakeResult);
    const passkey: ReactNativePasskeyLike = { isSupported: vi.fn(), create: vi.fn(), get };
    const webauthn = createReactNativeWebAuthn(passkey);

    const credential = await webauthn.get({ challenge, rpId: "acme.com" });

    expect(get).toHaveBeenCalledWith(expect.objectContaining({ challenge: bytesToBase64Url(challenge), rpId: "acme.com" }));
    const response = credential?.response as unknown as { userHandle: Uint8Array | null };
    expect(response.userHandle).toBeNull();
  });

  it("get(): decodes a non-null userHandle back to bytes", async () => {
    const fakeResult: PasskeyGetResult = {
      id: "cred-1",
      rawId: bytesToBase64Url(bytes(5)),
      response: {
        clientDataJSON: bytesToBase64Url(bytes(1)),
        authenticatorData: bytesToBase64Url(bytes(2)),
        signature: bytesToBase64Url(bytes(3)),
        userHandle: bytesToBase64Url(bytes(42)),
      },
    };
    const passkey: ReactNativePasskeyLike = {
      isSupported: vi.fn(),
      create: vi.fn(),
      get: vi.fn().mockResolvedValue(fakeResult),
    };
    const webauthn = createReactNativeWebAuthn(passkey);

    const credential = await webauthn.get({ challenge: bytes(1) });

    const response = credential?.response as unknown as { userHandle: Uint8Array | null };
    expect(response.userHandle).toEqual(base64UrlToBytes(bytesToBase64Url(bytes(42))));
  });
});
