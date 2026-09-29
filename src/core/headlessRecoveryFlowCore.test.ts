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
    // threat model §3.5 R13 — init() mints and sends the PKCE CHALLENGE
    // only, never the verifier.
    expect(initBody.code_challenge).toEqual(expect.any(String));
    expect(initBody.code_challenge_method).toBe("S256");
    expect(initBody.code_verifier).toBeUndefined();
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
    // threat model §3.5 R13 — every step submit carries the PKCE verifier
    // minted at init(), transparently, alongside the caller's own body.
    const submitBody = JSON.parse(submitInit.body as string) as Record<string, unknown>;
    expect(submitBody.email).toBe("user@example.com");
    expect(submitBody.code_verifier).toEqual(expect.any(String));
    expect((submitBody.code_verifier as string).length).toBeGreaterThanOrEqual(43);
  });

  // issue #163/#165 Wave 3
  it("redeemRecoveryCode(): submits {code} through the generic step endpoint", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "validate-user-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ current_step: { step: { ref: "recovery-codes-form" } }, data: { mode: "redeem" } })),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "select-credential-form" } } })),
          { status: 200 },
        ),
      );

    await core.init();
    const snapshot = await core.redeemRecoveryCode("ABCD-1234");

    expect(snapshot.stepRef).toBe("select-credential-form");
    const [, submitInit] = fetchMock.mock.calls[2] as [string, RequestInit];
    const body = JSON.parse(submitInit.body as string) as Record<string, unknown>;
    expect(body.code).toBe("ABCD-1234");
    expect(body.code_verifier).toEqual(expect.any(String));
  });

  // account-recovery masked-hints/confirm-partial build
  it("confirmPartial(): submits {partial} through the generic step endpoint", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "validate-user-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ current_step: { step: { ref: "confirm-contact-form" } }, data: { channel: "sms" } })),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "validate-recovery-form" } } })),
          { status: 200 },
        ),
      );

    await core.init();
    const snapshot = await core.confirmPartial("4821");

    expect(snapshot.stepRef).toBe("validate-recovery-form");
    const [, submitInit] = fetchMock.mock.calls[2] as [string, RequestInit];
    const body = JSON.parse(submitInit.body as string) as Record<string, unknown>;
    expect(body.partial).toBe("4821");
    expect(body.code_verifier).toEqual(expect.any(String));
  });

  it("confirmPartial(): a mismatch resolves IDENTICALLY to a match — no error, same advance", async () => {
    // The server never signals match/mismatch (design §5.3) — from the
    // SDK's perspective both paths are just "the network call succeeded
    // and the flow advanced." This test documents that there is no
    // branch to assert on beyond that.
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "token-1", current_step: "validate-user-form" }), { status: 201 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ current_step: { step: { ref: "confirm-contact-form" } }, data: { channel: "email" } })),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "validate-recovery-form" } } })),
          { status: 200 },
        ),
      );

    await core.init();
    const snapshot = await core.confirmPartial("not-the-real-email@example.com");

    expect(snapshot.status).toBe("in_progress");
    expect(snapshot.stepRef).toBe("validate-recovery-form");
    expect(snapshot.error).toBeNull();
  });

  describe("auto_proceed", () => {
    it("init(): a single-channel how-to-recover-form is resolved transparently — the caller never sees that stepRef", async () => {
      fetchMock
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ token: "token-1", current_step: "how-to-recover-form" }), { status: 201 }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              next_token: "token-2",
              auto_proceed: true,
              current_step: { step: { ref: "how-to-recover-form" } },
              data: { options: ["whatsapp"] },
            }),
            { status: 200 },
          ),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "confirm-contact-form" } } })),
            { status: 200 },
          ),
        );

      const snapshot = await core.init();

      expect(snapshot.stepRef).toBe("confirm-contact-form");
      // Exactly 3 calls: init POST, the auto-proceed-flagged GET, and the
      // transparently-issued auto-submit POST — never a 4th call the
      // caller would have had to trigger itself.
      expect(fetchMock).toHaveBeenCalledTimes(3);
      const [, autoSubmitInit] = fetchMock.mock.calls[2] as [string, RequestInit];
      const body = JSON.parse(autoSubmitInit.body as string) as Record<string, unknown>;
      expect(body.option).toBe("whatsapp");
      // Even the transparently-issued auto-proceed submit carries the
      // verifier — it goes through the same request() path as every other
      // step submission (R13's "every step submit", not a hand-picked one).
      expect(body.code_verifier).toEqual(expect.any(String));
    });

    it("2+ channels never auto-proceeds — the picker step is returned as-is", async () => {
      fetchMock
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ token: "token-1", current_step: "how-to-recover-form" }), { status: 201 }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              next_token: "token-2",
              auto_proceed: false,
              current_step: { step: { ref: "how-to-recover-form" } },
              data: { options: ["sms", "whatsapp"] },
            }),
            { status: 200 },
          ),
        );

      const snapshot = await core.init();

      expect(snapshot.stepRef).toBe("how-to-recover-form");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("auto_proceed=true with no options[] fails loudly instead of hanging", async () => {
      fetchMock
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ token: "token-1", current_step: "how-to-recover-form" }), { status: 201 }),
        )
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({
              next_token: "token-2",
              auto_proceed: true,
              current_step: { step: { ref: "how-to-recover-form" } },
              data: { options: [] },
            }),
            { status: 200 },
          ),
        );

      await expect(core.init()).rejects.toBeInstanceOf(JummonAuthError);
    });
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

  // threat model §3.5 R13/R17 — PKCE device-binding
  describe("PKCE device-binding (R13/R17)", () => {
    it("each init() mints a FRESH verifier/challenge pair — never reused across flow instances", async () => {
      const coreA = new HeadlessRecoveryFlowCore({ baseHost: "dynamic.jummon.dev", flowRef: "recover" });
      const coreB = new HeadlessRecoveryFlowCore({ baseHost: "dynamic.jummon.dev", flowRef: "recover" });

      fetchMock
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "t1", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ data: {} })), { status: 200 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "t2", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ data: {} })), { status: 200 }));

      await coreA.init();
      await coreB.init();

      const challengeA = (JSON.parse((fetchMock.mock.calls[0] as [string, RequestInit])[1].body as string) as Record<string, unknown>)
        .code_challenge;
      const challengeB = (JSON.parse((fetchMock.mock.calls[2] as [string, RequestInit])[1].body as string) as Record<string, unknown>)
        .code_challenge;
      expect(challengeA).not.toBe(challengeB);
    });

    it("submit() attaches the SAME verifier init() minted, unchanged across the whole flow", async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "token-1", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ current_step: { step: { ref: "step-a" } } })), { status: 200 }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify(stepEnvelope({ next_token: "token-3", current_step: { step: { ref: "step-b" } } })), {
            status: 200,
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify(stepEnvelope({ next_token: "token-4", current_step: { step: { ref: "step-c" } } })), {
            status: 200,
          }),
        );

      await core.init();
      await core.submit({ a: 1 });
      await core.submit({ b: 2 });

      const verifier1 = (JSON.parse((fetchMock.mock.calls[2] as [string, RequestInit])[1].body as string) as Record<string, unknown>)
        .code_verifier;
      const verifier2 = (JSON.parse((fetchMock.mock.calls[3] as [string, RequestInit])[1].body as string) as Record<string, unknown>)
        .code_verifier;
      expect(verifier1).toBe(verifier2);
      expect(verifier1).toEqual(expect.any(String));
    });

    it("current() (GET, no body) never sends a code_verifier field at all", async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "token-1", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ data: {} })), { status: 200 }));

      await core.init();

      const [, currentInit] = fetchMock.mock.calls[1] as [string, RequestInit];
      expect(currentInit.body).toBeUndefined();
      expect(currentInit.method).toBe("GET");
    });
  });

  // threat model §3.5 R15/R16 — in-memory only, never persisted
  describe("in-memory only (R15/R16)", () => {
    it("the flow token and PKCE verifier are TRUE private (#) fields — never own enumerable properties, unlike opts/adapters", async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "super-secret-token", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ data: {} })), { status: 200 }));

      await core.init();

      // A naive integrator who accidentally JSON.stringify()s / spreads /
      // AsyncStorage.setItem()s the whole flow instance (instead of just
      // its public HeadlessRecoveryFlowSnapshot) must NEVER leak the
      // bearer token or the PKCE verifier this way — `#`-private fields are
      // not own enumerable properties, unlike the constructor-injected
      // `opts`/`webauthn`/`crypto` (non-secret config/adapters, TS
      // `private` — still enumerable at runtime, which is fine, they never
      // held a token or verifier value in the first place).
      expect(Object.keys(core)).not.toContain("token");
      expect(Object.keys(core)).not.toContain("codeVerifier");
      const serialized = JSON.stringify(core);
      expect(serialized).not.toContain("super-secret-token");
      const codeVerifierUsed = (
        JSON.parse(
          (fetchMock.mock.calls[0] as [string, RequestInit])[1].body as string,
        ) as { code_challenge: string }
      ).code_challenge;
      expect(serialized).not.toContain(codeVerifierUsed); // sanity: challenge itself isn't the verifier either
    });

    it('a completed ("done") flow drops its PKCE verifier from memory — the NEXT submit (if any) would carry none', async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "token-1", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(new Response(JSON.stringify({ done: true, next_token: "", data: {} }), { status: 200 }))
        .mockResolvedValueOnce(new Response(JSON.stringify(stepEnvelope({ data: {} })), { status: 200 }));

      const snapshot = await core.init();
      expect(snapshot.status).toBe("done");

      // Calling submit() after "done" is a caller misuse the class doesn't
      // forbid outright (no flow_token invalidation check here — dynamic-
      // flows itself rejects a consumed token), but the hygiene contract
      // still holds: no verifier value is left to attach.
      await core.submit({ whatever: true });
      const [, submitInit] = fetchMock.mock.calls[2] as [string, RequestInit];
      const body = JSON.parse(submitInit.body as string) as Record<string, unknown>;
      expect(body.code_verifier).toBeUndefined();
    });
  });
});
