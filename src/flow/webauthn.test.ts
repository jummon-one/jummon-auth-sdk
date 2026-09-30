import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64Url } from "../internal/base64";
import {
  decodeCredentialCreationOptions,
  decodeCredentialRequestOptions,
  encodeAssertionForWire,
  encodeAttestationForWire,
} from "./webauthn";

/** Encodes a wire-shaped WebAuthn options object the way auth-engine's `fido_login_options`/`fido_registration_options` do: standard base64 over JSON, with base64url-encoded inner byte fields. */
function toOuterEnvelope(obj: unknown): string {
  return btoa(JSON.stringify(obj));
}

describe("decodeCredentialRequestOptions", () => {
  it("decodes the outer standard-base64 envelope and the inner base64url challenge/allowCredentials fields", () => {
    const challengeBytes = new Uint8Array([1, 2, 3, 4]);
    const credIdBytes = new Uint8Array([9, 9, 9]);
    const wire = toOuterEnvelope({
      challenge: bytesToBase64Url(challengeBytes),
      rpId: "example.com",
      userVerification: "preferred",
      allowCredentials: [{ id: bytesToBase64Url(credIdBytes), type: "public-key", transports: ["internal"] }],
    });

    const decoded = decodeCredentialRequestOptions(wire);

    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(challengeBytes);
    expect(decoded.rpId).toBe("example.com");
    expect(decoded.userVerification).toBe("preferred");
    expect(decoded.allowCredentials).toHaveLength(1);
    expect(new Uint8Array(decoded.allowCredentials?.[0]?.id as ArrayBuffer)).toEqual(credIdBytes);
  });
});

describe("decodeCredentialCreationOptions", () => {
  it("decodes rp/user/challenge, base64url-decoding user.id and challenge", () => {
    const challengeBytes = new Uint8Array([5, 6, 7]);
    const userIdBytes = new Uint8Array([42]);
    const wire = toOuterEnvelope({
      rp: { id: "example.com", name: "Acme" },
      user: { id: bytesToBase64Url(userIdBytes), name: "jane", displayName: "Jane" },
      challenge: bytesToBase64Url(challengeBytes),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    });

    const decoded = decodeCredentialCreationOptions(wire);

    expect(decoded.rp).toEqual({ id: "example.com", name: "Acme" });
    expect(decoded.user.name).toBe("jane");
    expect(new Uint8Array(decoded.user.id as ArrayBuffer)).toEqual(userIdBytes);
    expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(challengeBytes);
  });
});

describe("encodeAssertionForWire", () => {
  it("produces the standard WebAuthn-JSON assertion shape the go-webauthn server expects (fido_validator.go)", () => {
    const fakeCredential = {
      id: "cred-id",
      rawId: new Uint8Array([1, 2]).buffer,
      type: "public-key",
      response: {
        clientDataJSON: new Uint8Array([3, 4]).buffer,
        authenticatorData: new Uint8Array([5, 6]).buffer,
        signature: new Uint8Array([7, 8]).buffer,
        userHandle: new Uint8Array([9]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;

    const wire = encodeAssertionForWire(fakeCredential);

    expect(wire.id).toBe("cred-id");
    expect(wire.type).toBe("public-key");
    expect(wire).toHaveProperty("response");
    const response = wire.response as Record<string, unknown>;
    expect(typeof response.clientDataJSON).toBe("string");
    expect(typeof response.authenticatorData).toBe("string");
    expect(typeof response.signature).toBe("string");
    expect(typeof response.userHandle).toBe("string");
  });

  it("encodes a null userHandle as null, not a string", () => {
    const fakeCredential = {
      id: "cred-id",
      rawId: new Uint8Array([1]).buffer,
      type: "public-key",
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([1]).buffer,
        signature: new Uint8Array([1]).buffer,
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;

    const wire = encodeAssertionForWire(fakeCredential);
    expect((wire.response as Record<string, unknown>).userHandle).toBeNull();
  });
});

describe("encodeAttestationForWire", () => {
  it("returns a base64 STRING (not an object) wrapping the standard WebAuthn-JSON attestation shape — matches the Go `string` fields (catalog-api's RegisterPasskeyFinishRequest.Attestation, auth-engine's SubmitStepData.FidoRegistationResponse, dynamic-flows' step_enroll_passkey.go Attestation) that bind this value; an object here breaks all three at decode time", () => {
    const fakeCredential = {
      id: "cred-id",
      rawId: new Uint8Array([1, 2]).buffer,
      type: "public-key",
      response: {
        clientDataJSON: new Uint8Array([3]).buffer,
        attestationObject: new Uint8Array([4]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;

    const wire = encodeAttestationForWire(fakeCredential);

    expect(typeof wire).toBe("string");
    // Round-trip exactly like `fido.FinishRegistration`'s
    // `base64.StdEncoding.DecodeString` does server-side.
    const decoded = JSON.parse(new TextDecoder().decode(base64ToBytes(wire))) as Record<string, unknown>;
    expect(decoded.id).toBe("cred-id");
    expect(decoded.type).toBe("public-key");
    const response = decoded.response as Record<string, unknown>;
    expect(typeof response.clientDataJSON).toBe("string");
    expect(typeof response.attestationObject).toBe("string");
  });
});
