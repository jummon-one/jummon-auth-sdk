/**
 * Payload fixtures here are copy-typed from the ACTUAL runtime object
 * literals `jummon-login-interface` sends over the wire — NOT from this
 * SDK's own `HeadlessAuthEnvelope`/`HeadlessErrorEnvelope` types (those are
 * exercised elsewhere, e.g. `headlessAuthFlow.test.ts`/`transport.test.ts`).
 * The point of this file is to catch drift between the SDK's TYPE and the
 * backend's actual JSON.stringify output — a bug the other suites can't see
 * because they cast fixtures *through* the same types being tested.
 *
 * Sources (read 2026-09-02, jummon-login-interface):
 *  - `src/server/services/headless/response.ts`
 *    (`respondCurrentStep`/`respondNeedsRedirect`/`respondTerminal`)
 *  - `src/server/handlers/headlessAuthHandler.ts` (pre-mint 400/404/500s)
 *  - `src/server/services/headless/flowToken.ts` (`headlessFlowTokenBroker`
 *    401s, incl. `flow_client_mismatch` — NOT in either SDK error-code
 *    whitelist, must resolve through the §4.3 `type` fallback)
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../internal/tokenExchange", () => ({ exchangeAuthorizationCode: vi.fn() }));

import { exchangeAuthorizationCode } from "../internal/tokenExchange";
import { createHeadlessAuthFlow, type HeadlessSessionSink } from "./headlessAuthFlow";
import { HeadlessTransport } from "./transport";

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  issuerHost: "idm.jummon.dev",
};

function jsonResponse(literal: unknown, status: number): Response {
  // Round-trip through JSON.stringify/parse, exactly like the real
  // Express->fetch boundary — this also drops any `undefined`-valued keys,
  // matching `response.ts`'s actual output (e.g. `theme: raw?.theme` when
  // `raw.theme` is undefined never appears in the wire JSON at all).
  return new Response(JSON.stringify(literal), { status });
}

describe("real jummon-login-interface wire payloads (raw literals, not SDK types)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const transport = () => new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

  // --- headlessAuthHandler.ts pre-mint validation errors (headlessStartHandler:45-86) ---

  it("pre-mint 400 (missing tenant/client) — no flow_token, no type key at all", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ code: "invalid_request", message: "tenant and client are required" }, 400),
    );
    await expect(
      transport().start({ redirect_uri: "https://app.acme.com/callback", code_challenge: "c" }),
    ).rejects.toMatchObject({ code: "unknown" }); // Family A has no invalid_request entry; no `type` -> mapByType(undefined) -> unknown
  });

  it("pre-mint 404 (feature flag off / unknown tenant, deliberately indistinguishable) — no flow_token/type", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ code: "not_found", message: "not found" }, 404));
    await expect(
      transport().start({ redirect_uri: "https://app.acme.com/callback", code_challenge: "c" }),
    ).rejects.toMatchObject({ code: "unknown" });
  });

  it("pre-mint 500 internal_error catch-all — no flow_token/type", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ code: "internal_error", message: "internal error" }, 500));
    await expect(
      transport().start({ redirect_uri: "https://app.acme.com/callback", code_challenge: "c" }),
    ).rejects.toMatchObject({ code: "unknown" });
  });

  // --- flowToken.ts headlessFlowTokenBroker 401s ---

  it("flow_token_missing (no X-Flow-Token header) — maps to flow_not_started", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ code: "flow_token_missing", message: "x-flow-token header is required" }, 401),
    );
    await expect(transport().poll("ft-1")).rejects.toMatchObject({ code: "flow_not_started" });
  });

  it("flow_expired (token absent/expired in Redis) — maps verbatim", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ code: "flow_expired", message: "flow token expired or invalid" }, 401));
    await expect(transport().poll("ft-1")).rejects.toMatchObject({ code: "flow_expired" });
  });

  it("flow_client_mismatch (cross-client token replay) — NOT in either whitelist, resolves via `type: expired` fallback, never a bare unknown", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          flow_token: "ft-stale",
          code: "flow_client_mismatch",
          type: "expired",
          message: "flow token does not belong to this tenant/client",
        },
        401,
      ),
    );
    await expect(transport().poll("ft-stale")).rejects.toMatchObject({ code: "flow_expired" });
  });

  // --- response.ts respondCurrentStep (200 success) ---

  it("respondCurrentStep 200 with NO optional keys present at all (raw?.theme etc. undefined) — SDK falls back to previous snapshot values, never crashes on a missing `data`", async () => {
    // Exactly what `res.status(200).json({...})` serializes when
    // raw?.theme/passkey_origin_ok/available_social_logins/
    // passwordless_available are all undefined: those keys are ABSENT from
    // the JSON, not null.
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          flow_token: "sess-abc123",
          status: "needs_input",
          current_step: { ref: "otp-input-form" },
          data: { some_field: "x" },
        },
        200,
      ),
    );
    const result = await transport().poll("sess-abc123");
    expect(result.theme).toBeUndefined();
    expect(result.passkey_origin_ok).toBeUndefined();
    expect(result.available_social_logins).toBeUndefined();
    expect(result.passwordless_available).toBeUndefined();
    expect(result.data).toEqual({ some_field: "x" });
  });

  it("respondCurrentStep 200 with full per-client-resolved branding surfaced verbatim on the flow snapshot", async () => {
    const startEnvelope = {
      flow_token: "sess-abc123",
      status: "needs_input",
      current_step: { ref: "username-password-form" },
      theme: {
        logo: "https://cdn.acme.com/logo.png",
        background_color: "#0a0a0a",
        primary_color: "#ff6600",
        text_color: "#ffffff",
        customer_name: "Acme Corp",
        client_name: "Acme App",
        forgot_password_link: "https://app.acme.com/forgot",
        terms_of_use_link: "https://app.acme.com/terms",
        privacy_policies_link: "https://app.acme.com/privacy",
      },
      passkey_origin_ok: true,
      available_social_logins: [
        { id: "1", name: "Google", alias: "google", type: "google", enabled: true },
      ],
      passwordless_available: true,
      data: {},
    };
    fetchMock.mockResolvedValue(jsonResponse(startEnvelope, 200));

    const sink: HeadlessSessionSink = { completeSignIn: vi.fn() };
    // The flow talks to a real HeadlessTransport (real fetch mock), not a
    // mocked transport — end-to-end through the actual JSON parse boundary.
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.start();

    expect(snapshot.theme).toEqual(startEnvelope.theme);
    expect(snapshot.availableSocialLogins).toEqual(startEnvelope.available_social_logins);
    expect(snapshot.passwordlessAvailable).toBe(true);
    expect(snapshot.passkeyOriginOk).toBe(true);
  });

  it("respondCurrentStep's 400 errorEnvelope branch — flow_token present (post-mint), forwards `type` from the parsed error envelope", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          flow_token: "sess-abc123",
          code: "AUTH-AUTHN-2001",
          message: "request could not be processed",
          type: "authentication",
        },
        400,
      ),
    );
    await expect(transport().submit("sess-abc123", { username: "x", password: "y" })).rejects.toMatchObject({
      code: "invalid_credentials",
    });
  });

  // --- response.ts respondNeedsRedirect (200, social/legacy-SSO kickoff) ---

  it("respondNeedsRedirect's real shape has NO theme/passkey/social/passwordless keys — flow keeps whatever start() already resolved, doesn't wipe branding mid-flow", async () => {
    const sink: HeadlessSessionSink = { completeSignIn: vi.fn() };
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse(
          {
            flow_token: "sess-abc123",
            status: "needs_input",
            current_step: { ref: "username-password-form" },
            theme: { logo: "https://cdn.acme.com/logo.png", client_name: "Acme App" },
            available_social_logins: [{ id: "1", name: "Google", alias: "google", type: "google", enabled: true }],
            passwordless_available: true,
            data: {},
          },
          200,
        ),
      )
      .mockResolvedValueOnce(
        // Literal respondNeedsRedirect shape — response.ts:84-89, verbatim.
        jsonResponse(
          {
            flow_token: "sess-abc123",
            status: "needs_redirect",
            current_step: null,
            data: { redirect_url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=y" },
          },
          200,
        ),
      );
    const assign = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", { value: { ...originalLocation, assign }, writable: true });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    const snapshot = await flow.startSocialLogin("google");

    expect(snapshot.status).toBe("needs_social_redirect");
    // Branding survives the redirect-kickoff hop even though this response
    // literally carries none of those keys — the flow's fallback-to-
    // previous-snapshot merge (`envelope.theme ?? this.snapshot.theme`, …)
    // is what makes "per-app top, tenant fallback" branding stay visible
    // across a social kickoff, not just on start().
    expect(snapshot.theme).toEqual({ logo: "https://cdn.acme.com/logo.png", client_name: "Acme App" });
    expect(snapshot.availableSocialLogins).toEqual([
      { id: "1", name: "Google", alias: "google", type: "google", enabled: true },
    ]);
    expect(snapshot.passwordlessAvailable).toBe(true);

    Object.defineProperty(window, "location", { value: originalLocation, writable: true });
  });

  // --- response.ts respondTerminal (200 authenticated / 422 unsupported_redirect) ---

  it("respondTerminal's authenticated success literally has NO current_step/data/theme keys — completeAuthenticated must not choke on their absence", async () => {
    const sink: HeadlessSessionSink = {
      completeSignIn: vi.fn().mockReturnValue({ sub: "u1", tenant: "acme", roles: [], permissions: [], raw: {} }),
    };
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({ flow_token: "sess-abc123", status: "needs_input", current_step: { ref: "username-password-form" }, data: {} }, 200),
      )
      .mockResolvedValueOnce(
        // Literal respondTerminal success shape — response.ts:127-132, verbatim (no `current_step`, no `data`, no `theme` keys at all).
        jsonResponse({ flow_token: "sess-abc123", status: "authenticated", code: "auth-code-1", oidc_state: "state-1" }, 200),
      );

    // Stub the PKCE exchange so we isolate envelope parsing, not the token endpoint.
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({
      access_token: "at",
      refresh_token: "rt",
      token_type: "Bearer",
      expires_in: 3600,
    });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.error).toBeNull();
  });

  it("respondTerminal's 422 unsupported_redirect — a genuinely unrecognized redirect kind, `type: 'unknown'` per response.ts:122", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          flow_token: "sess-abc123",
          code: "unsupported_redirect",
          message: "this flow requires a browser redirect, not supported by the headless API in Wave 1",
          type: "unknown",
        },
        422,
      ),
    );
    await expect(transport().submit("sess-abc123", { step_ref: "legacy-sso-form" })).rejects.toMatchObject({
      code: "unknown",
    });
  });

  // --- flowToken.ts:39-73 mintHeadlessSession — flow_token IS req.sessionID (a bare UUID, not a JWT) ---

  it("flow_token on the wire is a bare Redis session id (randomUUID()), the SDK must treat it as an opaque string, never parse it", async () => {
    const opaqueToken = "1f6c9e2e-6f0a-4a1b-9d21-3b8a6d0d9e11";
    fetchMock.mockResolvedValue(
      jsonResponse({ flow_token: opaqueToken, status: "needs_input", current_step: { ref: "username-password-form" }, data: {} }, 200),
    );
    const result = await transport().start({ redirect_uri: "https://app.acme.com/callback", code_challenge: "c" });
    expect(result.flow_token).toBe(opaqueToken);
  });
});
