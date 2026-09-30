import { afterEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { runRecoveryPasskeyCeremony, type RecoveryPasskeyChallenge } from "./recoveryPasskeyEnrollment";

function toOuterEnvelope(obj: unknown): string {
  return btoa(JSON.stringify(obj));
}

function challenge(overrides: Partial<RecoveryPasskeyChallenge> = {}): RecoveryPasskeyChallenge {
  return {
    ceremonyId: "ceremony-1",
    options: toOuterEnvelope({
      rp: { id: "example.com", name: "Acme" },
      user: { id: "dXNlci0x", name: "jane", displayName: "Jane" },
      challenge: "Y2hhbGxlbmdl",
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    }),
    ...overrides,
  };
}

function fakeCredential(): PublicKeyCredential {
  return {
    id: "cred-id",
    rawId: new Uint8Array([1, 2]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([3]).buffer,
      attestationObject: new Uint8Array([4]).buffer,
    },
    getClientExtensionResults: () => ({}),
  } as unknown as PublicKeyCredential;
}

describe("runRecoveryPasskeyCeremony", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("never touches navigator.credentials when webauthn.isSupported() is false", async () => {
    const webauthn = { isSupported: () => false, create: vi.fn(), get: vi.fn() };

    await expect(runRecoveryPasskeyCeremony(challenge(), undefined, webauthn)).rejects.toMatchObject({
      code: "passkey_origin_unsupported",
    });
    expect(webauthn.create).not.toHaveBeenCalled();
  });

  it("happy path: decodes the challenge, calls create(), returns the wire-ready ceremony_id/attestation/name — makes NO network call itself", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const create = vi.fn().mockResolvedValue(fakeCredential());
    const webauthn = { isSupported: () => true, create, get: vi.fn() };

    const result = await runRecoveryPasskeyCeremony(challenge(), "My phone", webauthn);

    expect(result.ceremony_id).toBe("ceremony-1");
    expect(result.name).toBe("My phone");
    // Wire-format regression guard: `attestation` MUST be a base64 STRING —
    // `dynamic-flows/internal/executionflow/steps/step_enroll_passkey.go`'s
    // `Attestation` is a plain Go `string`; an object here fails the bind
    // the same way it did for the standalone enrollment ceremony.
    expect(typeof result.attestation).toBe("string");
    const decodedAttestation = JSON.parse(
      new TextDecoder().decode(Uint8Array.from(atob(result.attestation), (c) => c.charCodeAt(0))),
    ) as Record<string, unknown>;
    expect(decodedAttestation.id).toBe("cred-id");
    expect(decodedAttestation).toHaveProperty("response");
    expect(create).toHaveBeenCalledOnce();
    // The Recovery Grant is never on this path — this module has no HTTP
    // transport of its own (design §3.2: the grant never crosses the wire
    // to the client, and this ceremony runner is not where the client
    // would even have it).
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps the user cancelling/dismissing the platform UI to passkey_failed", async () => {
    const create = vi.fn().mockRejectedValue(new Error("NotAllowedError"));
    const webauthn = { isSupported: () => true, create, get: vi.fn() };

    await expect(runRecoveryPasskeyCeremony(challenge(), undefined, webauthn)).rejects.toMatchObject({
      code: "passkey_failed",
    });
  });

  it("maps a null credential from create() to passkey_failed", async () => {
    const create = vi.fn().mockResolvedValue(null);
    const webauthn = { isSupported: () => true, create, get: vi.fn() };

    const err = await runRecoveryPasskeyCeremony(challenge(), undefined, webauthn).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("passkey_failed");
  });
});
