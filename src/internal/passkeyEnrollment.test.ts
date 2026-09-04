import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { DEFAULT_API_HOST, enrollPasskey, isPasskeySupported } from "./passkeyEnrollment";

/** Same outer-envelope encoding `catalog-api`'s `RegisterPasskeyBeginResponse.options` uses — standard base64 over JSON, matching `webauthn.test.ts`'s `toOuterEnvelope()`. */
function toOuterEnvelope(obj: unknown): string {
  return btoa(JSON.stringify(obj));
}

function beginBody(overrides: Partial<{ ceremony_id: string; options: string }> = {}) {
  return {
    ceremony_id: "ceremony-1",
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

/** Stubs `window.PublicKeyCredential` + `navigator.credentials.create` so `isPasskeySupported()` reports true and `enrollPasskey()` can resolve a ceremony. Pass a rejecting/null-resolving mock to simulate a cancelled/failed ceremony. */
function stubWebAuthnSupport(create: ReturnType<typeof vi.fn>): void {
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  vi.stubGlobal("navigator", { credentials: { create } });
}

describe("isPasskeySupported", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is false when navigator.credentials.create isn't a function (no WebAuthn in this browser/origin)", () => {
    vi.stubGlobal("navigator", {});
    expect(isPasskeySupported()).toBe(false);
  });

  it("is true once PublicKeyCredential + navigator.credentials.create are both present", () => {
    stubWebAuthnSupport(vi.fn());
    expect(isPasskeySupported()).toBe(true);
  });
});

describe("enrollPasskey", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("never calls the network when the origin doesn't support WebAuthn — throws passkey_origin_unsupported", async () => {
    vi.stubGlobal("navigator", {});

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "passkey_origin_unsupported",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("happy path: begin -> navigator.credentials.create -> finish, Bearer auth, apiHost (not issuerHost) as base", async () => {
    const create = vi.fn().mockResolvedValue(fakeCredential());
    stubWebAuthnSupport(create);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify(beginBody()), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ credential_id: "cred-1", name: "My phone" }), { status: 200 }),
      );

    const result = await enrollPasskey("token-1", "My phone", { apiHost: "api.jummon.dev" });

    expect(result).toEqual({ credentialId: "cred-1", name: "My phone" });

    const [beginUrl, beginInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(beginUrl).toBe("https://api.jummon.dev/catalog/me/credentials/passkeys/begin");
    expect((beginInit.headers as Record<string, string>).Authorization).toBe("Bearer token-1");

    const [finishUrl, finishInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(finishUrl).toBe("https://api.jummon.dev/catalog/me/credentials/passkeys/finish");
    const finishBody = JSON.parse(finishInit.body as string) as Record<string, unknown>;
    expect(finishBody.ceremony_id).toBe("ceremony-1");
    expect(finishBody.name).toBe("My phone");
    expect(finishBody).toHaveProperty("attestation");

    expect(create).toHaveBeenCalledOnce();
  });

  it("maps the user cancelling/dismissing the platform WebAuthn UI to passkey_failed", async () => {
    const create = vi.fn().mockRejectedValue(new Error("NotAllowedError"));
    stubWebAuthnSupport(create);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(beginBody()), { status: 200 }));

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "passkey_failed",
    });
    // finish() must never be called after create() failed.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("maps a null credential from navigator.credentials.create() to passkey_failed", async () => {
    const create = vi.fn().mockResolvedValue(null);
    stubWebAuthnSupport(create);
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(beginBody()), { status: 200 }));

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "passkey_failed",
    });
  });

  it("maps a 401 on begin() to not_authenticated (expired/invalid access_token)", async () => {
    stubWebAuthnSupport(vi.fn());
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "invalid token" }), { status: 401 }),
    );

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "not_authenticated",
    });
  });

  it("maps catalog-api's UPSTREAM_NOT_FOUND (expired/unknown ceremony) on finish() to passkey_failed, not a bare unknown", async () => {
    const create = vi.fn().mockResolvedValue(fakeCredential());
    stubWebAuthnSupport(create);
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify(beginBody()), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ code: "UPSTREAM_NOT_FOUND", error: "not_exist", message: "ceremony not found" }),
          { status: 404 },
        ),
      );

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "passkey_failed",
    });
  });

  it("maps a 403 to access_denied", async () => {
    stubWebAuthnSupport(vi.fn());
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "FORBIDDEN", message: "not allowed" }), { status: 403 }),
    );

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "access_denied",
    });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    stubWebAuthnSupport(vi.fn());
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST })).rejects.toMatchObject({
      code: "network_unreachable",
    });
  });

  it("classifies a malformed (non-JSON) response as unknown", async () => {
    stubWebAuthnSupport(vi.fn());
    fetchMock.mockResolvedValueOnce(new Response("not json", { status: 200 }));

    const err = await enrollPasskey("token-1", undefined, { apiHost: DEFAULT_API_HOST }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("unknown");
  });
});
