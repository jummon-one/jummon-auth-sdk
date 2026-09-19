import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { HeadlessRecoveryFlowCore } from "./headlessRecoveryFlowCore";

function stepEnvelope(overrides: Record<string, unknown> = {}) {
  return {
    next_token: "token-2",
    current_step: { step: { ref: "how-to-recover-form" } },
    data: { channels: ["sms", "email"] },
    ...overrides,
  };
}

describe("HeadlessRecoveryFlowCore", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let core: HeadlessRecoveryFlowCore;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    core = new HeadlessRecoveryFlowCore({ baseHost: "dynamic.jummon.dev", flowRef: "recover-account-credential-aware" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("init(): POSTs /dynamic/executionflows with flow_ref, then GETs the current step with the rotated x-flow-token", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "validate-user-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ current_step: { step: { ref: "validate-user-form" } }, data: {} })),
          { status: 200 },
        ),
      );

    const snapshot = await core.init();

    expect(snapshot.status).toBe("in_progress");
    expect(snapshot.stepRef).toBe("validate-user-form");

    const [initUrl, initInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(initUrl).toBe("https://dynamic.jummon.dev/dynamic/executionflows");
    const initBody = JSON.parse(initInit.body as string) as Record<string, unknown>;
    expect(initBody.flow_ref).toBe("recover-account-credential-aware");
    // No token exists yet at init — the first call must never send a stale
    // or undefined x-flow-token header.
    expect((initInit.headers as Record<string, string>)["x-flow-token"]).toBeUndefined();

    const [currentUrl, currentInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(currentUrl).toBe("https://dynamic.jummon.dev/dynamic/executionflows/steps");
    expect((currentInit.headers as Record<string, string>)["x-flow-token"]).toBe("token-1");
  });

  it("submit(): POSTs the step body with the rotated token and advances stepRef", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "validate-user-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ current_step: { step: { ref: "validate-user-form" } }, data: {} })),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "how-to-recover-form" } } })),
          { status: 200 },
        ),
      );

    await core.init();
    const snapshot = await core.submit({ email: "user@example.com" });

    expect(snapshot.stepRef).toBe("how-to-recover-form");
    const [, submitInit] = fetchMock.mock.calls[2] as [string, RequestInit];
    // current()'s response already rotated the token to "token-2" (its own
    // next_token) before submit() runs — the header must reflect the LATEST
    // rotation, never a stale value from init().
    expect((submitInit.headers as Record<string, string>)["x-flow-token"]).toBe("token-2");
    expect(JSON.parse(submitInit.body as string)).toEqual({ email: "user@example.com" });
  });

  it("a done envelope reports status='done' and a null stepRef", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "success-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ done: true, next_token: "", data: {} }), { status: 200 }));

    const snapshot = await core.init();
    expect(snapshot.status).toBe("done");
    expect(snapshot.stepRef).toBeNull();
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(core.init()).rejects.toMatchObject({ code: "network_unreachable" });
  });

  describe("enrollPasskey", () => {
    it("refuses to run when the current step isn't enroll-passkey-form", async () => {
      const snapshot = { status: "in_progress" as const, stepRef: "how-to-recover-form", data: {}, error: null };

      await expect(core.enrollPasskey(snapshot)).rejects.toBeInstanceOf(JummonAuthError);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("refuses to run when the step data is missing ceremony_id/options", async () => {
      const snapshot = { status: "in_progress" as const, stepRef: "enroll-passkey-form", data: {}, error: null };

      await expect(core.enrollPasskey(snapshot)).rejects.toBeInstanceOf(JummonAuthError);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("happy path: runs the WebAuthn ceremony then submits the attestation through the generic step endpoint", async () => {
      const create = vi.fn().mockResolvedValue({
        id: "cred-id",
        rawId: new Uint8Array([1]).buffer,
        type: "public-key",
        response: {
          clientDataJSON: new Uint8Array([2]).buffer,
          attestationObject: new Uint8Array([3]).buffer,
        },
        getClientExtensionResults: () => ({}),
      });
      const webauthnCore = new HeadlessRecoveryFlowCore(
        { baseHost: "dynamic.jummon.dev", flowRef: "recover-account-credential-aware" },
        { isSupported: () => true, create, get: vi.fn() },
      );
      // Manually seed the token as if init()/current() had already run —
      // avoids re-mocking the init round trip for this focused assertion.
      fetchMock.mockResolvedValueOnce(
        new Response(JSON.stringify(stepEnvelope({ current_step: { step: { ref: "success-form" } } })), {
          status: 200,
        }),
      );

      const snapshot = {
        status: "in_progress" as const,
        stepRef: "enroll-passkey-form",
        data: {
          ceremony_id: "ceremony-1",
          options: btoa(
            JSON.stringify({
              rp: { id: "example.com", name: "Acme" },
              user: { id: "dXNlci0x", name: "jane", displayName: "Jane" },
              challenge: "Y2hhbGxlbmdl",
              pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            }),
          ),
        },
        error: null,
      };

      await webauthnCore.enrollPasskey(snapshot, "My phone");

      expect(create).toHaveBeenCalledOnce();
      const [submitUrl, submitInit] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(submitUrl).toBe("https://dynamic.jummon.dev/dynamic/executionflows/steps");
      const body = JSON.parse(submitInit.body as string) as Record<string, unknown>;
      expect(body.ceremony_id).toBe("ceremony-1");
      expect(body.name).toBe("My phone");
      expect(body).toHaveProperty("attestation");
    });
  });
});
