import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import type { HeadlessAuthEnvelope } from "./types";

vi.mock("./transport", () => ({ HeadlessTransport: vi.fn() }));
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

/**
 * Real backend success-envelope shape (wire-contract-v1.md §3.1):
 * `status` + `current_step: {ref, name?}` — NEVER `state`/`step_ref`. Every
 * fixture in this file is built off this shape, not the SDK's own
 * pre-freeze types, so a passing suite actually asserts against what the
 * backend ships.
 */
function envelope(overrides: Partial<HeadlessAuthEnvelope> = {}): HeadlessAuthEnvelope {
  return {
    flow_token: "ft-1",
    status: "needs_input",
    current_step: { ref: "username-password-form" },
    data: {},
    ...overrides,
  };
}

const STORAGE_KEY = `jummon_headless_flow:${OPTIONS.tenant}:${OPTIONS.clientId}`;

function setLocationSearch(search: string): void {
  window.history.pushState(null, "", `/callback${search}`);
}

describe("HeadlessAuthFlow", () => {
  let transportMock: { start: ReturnType<typeof vi.fn>; submit: ReturnType<typeof vi.fn>; poll: ReturnType<typeof vi.fn> };
  let sink: HeadlessSessionSink;

  beforeEach(() => {
    transportMock = { start: vi.fn(), submit: vi.fn(), poll: vi.fn() };
    (HeadlessTransport as unknown as ReturnType<typeof vi.fn>).mockImplementation(() => transportMock);
    sink = { completeSignIn: vi.fn().mockReturnValue({ sub: "u1", tenant: "acme", roles: [], permissions: [], raw: {} }) };
    vi.mocked(exchangeAuthorizationCode).mockReset();
    window.sessionStorage.clear();
    window.history.pushState(null, "", "/");
  });

  afterEach(() => {
    window.sessionStorage.clear();
  });

  // --- Blocker #1: status/current_step -----------------------------------

  it("start() reads `status`+`current_step` off the real envelope, not `state`/`step_ref`", async () => {
    transportMock.start.mockResolvedValue(
      envelope({ status: "needs_input", current_step: { ref: "username-password-form", name: "Password" } }),
    );
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(snapshot.status).toBe("needs_credentials"); // derived via deriveState() from current_step.ref
    expect(snapshot.stepRef).toBe("username-password-form");
    expect(snapshot.flowToken).toBe("ft-1");
    expect(flow.state).toEqual(snapshot);

    const startArgs = transportMock.start.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(startArgs.redirect_uri).toBe(OPTIONS.redirectUri);
    expect(startArgs.code_challenge_method).toBe("S256");
    expect(typeof startArgs.code_challenge).toBe("string");
    expect(typeof startArgs.state).toBe("string");
  });

  it("the terminal `authenticated` status (not a granular state string) actually fires token exchange", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "state-1", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({
      access_token: "at",
      refresh_token: "rt",
      id_token: "it",
      token_type: "Bearer",
      expires_in: 3600,
    });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(exchangeAuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({ tenant: "acme", clientId: "acme-app", code: "auth-code" }),
    );
    expect(sink.completeSignIn).toHaveBeenCalledWith(
      expect.objectContaining({ access_token: "at", refresh_token: "rt" }),
    );
    expect(snapshot.status).toBe("authenticated");
    expect(snapshot.user).toEqual({ sub: "u1", tenant: "acme", roles: [], permissions: [], raw: {} });
  });

  it("a wire status of `unknown` resolves to an error snapshot, never a silent no-op", async () => {
    transportMock.start.mockResolvedValue(envelope({ status: "unknown", current_step: null }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("unknown");
  });

  it("derives needs_mfa/needs_passkey_assertion from current_step.ref via the STEP_REF_TO_STATE table", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(
      envelope({ current_step: { ref: "otp-input-form" }, data: { foo: "bar" } }),
    );
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { username: "jane@example.com", password: "hunter2" });
    expect(snapshot.status).toBe("needs_mfa");
    expect(snapshot.data).toEqual({ foo: "bar" });
  });

  it("surfaces `available_social_logins` from the envelope on the snapshot", async () => {
    const logins = [{ id: "1", name: "Google", alias: "google", type: "google", enabled: true }];
    transportMock.start.mockResolvedValue(envelope({ available_social_logins: logins, passwordless_available: true }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(snapshot.availableSocialLogins).toEqual(logins);
    expect(snapshot.passwordlessAvailable).toBe(true);
  });

  // --- Blocker #2: scope ---------------------------------------------------

  it("start() sends `scope` as a singular space-delimited string (offline_access included), never `scopes: string[]`", async () => {
    transportMock.start.mockResolvedValue(envelope());
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    await flow.start();

    const startArgs = transportMock.start.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(startArgs.scope).toBe("openid profile email offline_access");
    expect(startArgs).not.toHaveProperty("scopes");
  });

  it("respects a caller-supplied scopes array, still joined to a singular string", async () => {
    transportMock.start.mockResolvedValue(envelope());
    const flow = createHeadlessAuthFlow({ ...OPTIONS, scopes: ["openid", "email"] }, sink);

    await flow.start();

    const startArgs = transportMock.start.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(startArgs.scope).toBe("openid email");
  });

  // --- Blocker #3: error shape (flow-level; wire parsing itself is transport.test.ts) --

  it("a transport error resolves to an `error` status snapshot instead of throwing out of submit", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockRejectedValue(new JummonAuthError("invalid_credentials", "nope"));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "wrong");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("invalid_credentials");
  });

  // --- Blocker #4: social resume end-to-end --------------------------------

  it("startSocialLogin() persists {flowToken, codeVerifier, oidcState} to sessionStorage before navigating away", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(
      envelope({
        status: "needs_redirect",
        current_step: null,
        data: { redirect_url: "https://accounts.google.com/o/oauth2/auth" },
      }),
    );
    const assign = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", { value: { ...originalLocation, assign }, writable: true });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    const snapshot = await flow.startSocialLogin("google");

    expect(assign).toHaveBeenCalledWith("https://accounts.google.com/o/oauth2/auth");
    expect(snapshot.status).toBe("needs_social_redirect");

    const stored = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) as string);
    expect(stored.flowToken).toBe("ft-1");
    expect(typeof stored.codeVerifier).toBe("string");
    expect(typeof stored.oidcState).toBe("string");
    expect(stored.tenant).toBe("acme");
    expect(stored.clientId).toBe("acme-app");

    Object.defineProperty(window, "location", { value: originalLocation, writable: true });
  });

  it("a successful start() also persists defensively (covers a tab reload/close-reopen mid-flow)", async () => {
    transportMock.start.mockResolvedValue(envelope());
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    await flow.start();

    expect(window.sessionStorage.getItem(STORAGE_KEY)).not.toBeNull();
  });

  it("resume(): code+state matching the stored oidcState exchanges the code and authenticates", async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        flowToken: "ft-stored",
        codeVerifier: "verifier-123",
        oidcState: "state-abc",
        tenant: OPTIONS.tenant,
        clientId: OPTIONS.clientId,
        redirectUri: OPTIONS.redirectUri,
        issuerHost: OPTIONS.issuerHost,
        savedAt: Date.now(),
      }),
    );
    setLocationSearch("?code=auth-code&state=state-abc");
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({
      access_token: "at",
      refresh_token: "rt",
      token_type: "Bearer",
      expires_in: 3600,
    });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.resume();

    expect(exchangeAuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({ code: "auth-code", codeVerifier: "verifier-123" }),
    );
    expect(snapshot.status).toBe("authenticated");
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(window.location.search).not.toContain("code=");
    expect(window.location.search).not.toContain("state=");
  });

  it("resume(): a mismatched state resolves to a state_mismatch error snapshot and clears the stored flow", async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        flowToken: "ft-stored",
        codeVerifier: "verifier-123",
        oidcState: "state-abc",
        tenant: OPTIONS.tenant,
        clientId: OPTIONS.clientId,
        redirectUri: OPTIONS.redirectUri,
        issuerHost: OPTIONS.issuerHost,
        savedAt: Date.now(),
      }),
    );
    setLocationSearch("?code=auth-code&state=NOT-THE-STORED-STATE");

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.resume();

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("state_mismatch");
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("resume(): an auth_resume=1 marker (no code yet — e.g. MFA-after-social) falls back to poll()", async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        flowToken: "ft-stored",
        codeVerifier: "verifier-123",
        oidcState: "state-abc",
        tenant: OPTIONS.tenant,
        clientId: OPTIONS.clientId,
        redirectUri: OPTIONS.redirectUri,
        issuerHost: OPTIONS.issuerHost,
        savedAt: Date.now(),
      }),
    );
    setLocationSearch("?auth_resume=1");
    transportMock.poll.mockResolvedValue(envelope({ flow_token: "ft-stored", current_step: { ref: "otp-input-form" } }));

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.resume();

    expect(transportMock.poll).toHaveBeenCalledWith("ft-stored");
    expect(snapshot.status).toBe("needs_mfa");
    // Not a definitive success/failure yet — the flow may still need another
    // social hop, so the stored entry is intentionally left in place.
    expect(window.sessionStorage.getItem(STORAGE_KEY)).not.toBeNull();
  });

  it("resume(): neither code nor auth_resume resolves to flow_not_started and clears the stored flow", async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        flowToken: "ft-stored",
        codeVerifier: "verifier-123",
        oidcState: "state-abc",
        tenant: OPTIONS.tenant,
        clientId: OPTIONS.clientId,
        redirectUri: OPTIONS.redirectUri,
        issuerHost: OPTIONS.issuerHost,
        savedAt: Date.now(),
      }),
    );
    setLocationSearch("");

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.resume();

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("flow_not_started");
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("resume(): nothing persisted in this tab resolves to flow_not_started", async () => {
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const snapshot = await flow.resume();

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("flow_not_started");
  });

  // --- Major/minor #5: guard errors land in snapshot.error, not only rejections --

  it("submitPassword() before start() resolves to an error snapshot (flow_not_started), it does not reject", async () => {
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const seen: string[] = [];
    flow.onStateChange((s) => seen.push(s.status));

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("flow_not_started");
    expect(seen).toContain("error");
  });

  it("startPasskeyLogin() resolves to a passkey_origin_unsupported error snapshot when passkeyOriginOk isn't true", async () => {
    transportMock.start.mockResolvedValue(envelope({ passkey_origin_ok: false }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.startPasskeyLogin("jane@example.com");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("passkey_origin_unsupported");
  });

  // --- Major/minor #6: completeAuthenticated() — no-code vs verifier-lost --

  it("completeAuthenticated: no code at all resolves to `unknown`", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(envelope({ status: "authenticated", current_step: null, data: {} }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("unknown");
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  it("completeAuthenticated: code present but the PKCE code_verifier was lost resolves to `pkce_verifier_lost`, distinct from `unknown`", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    // Simulate the JS realm having lost the in-memory PKCE verifier
    // (e.g. a non-social reload outside the resume() recovery path).
    (flow as unknown as { codeVerifier: string | null }).codeVerifier = null;

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("pkce_verifier_lost");
    expect(exchangeAuthorizationCode).not.toHaveBeenCalled();
  });

  // --- Major/minor #7: concurrency guard -----------------------------------

  it("concurrent start() calls (double-click / StrictMode) share one in-flight request", async () => {
    let resolveStart!: (v: HeadlessAuthEnvelope) => void;
    transportMock.start.mockReturnValue(new Promise((resolve) => (resolveStart = resolve)));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const first = flow.start();
    const second = flow.start();
    resolveStart(envelope());
    const [a, b] = await Promise.all([first, second]);

    expect(transportMock.start).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
  });

  it("concurrent submit() calls (double-click on a submit button) share one in-flight request", async () => {
    transportMock.start.mockResolvedValue(envelope());
    let resolveSubmit!: (v: HeadlessAuthEnvelope) => void;
    transportMock.submit.mockReturnValue(new Promise((resolve) => (resolveSubmit = resolve)));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const first = flow.submitPassword("jane@example.com", "hunter2");
    const second = flow.submitPassword("jane@example.com", "hunter2");
    resolveSubmit(envelope({ current_step: { ref: "otp-input-form" } }));
    const [a, b] = await Promise.all([first, second]);

    expect(transportMock.submit).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
  });

  // --- Passkey / social baseline behavior (pre-existing, kept against the new envelope shape) --

  it("startSocialLogin() navigates the browser full-page to redirect_url on status: needs_redirect", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockResolvedValue(
      envelope({
        status: "needs_redirect",
        current_step: null,
        data: { redirect_url: "https://accounts.google.com/o/oauth2/auth" },
      }),
    );
    const assign = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", { value: { ...originalLocation, assign }, writable: true });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    await flow.startSocialLogin("google");

    expect(assign).toHaveBeenCalledWith("https://accounts.google.com/o/oauth2/auth");

    Object.defineProperty(window, "location", { value: originalLocation, writable: true });
  });

  it("onStateChange fires immediately with the current snapshot and on every subsequent transition", async () => {
    transportMock.start.mockResolvedValue(envelope());
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const seen: string[] = [];
    const unsubscribe = flow.onStateChange((snapshot) => seen.push(snapshot.status));

    await flow.start();
    unsubscribe();

    expect(seen[0]).toBe("idle");
    expect(seen).toContain("loading");
    expect(seen[seen.length - 1]).toBe("needs_credentials");
  });

  // --- Prummo resilience #1: internal steps (check-session-id, ip-allow/blocklist) --

  it("auto-submits {} past an internal step (check-session-id) and never surfaces it as current_step", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "check-session-id" } }));
    transportMock.submit.mockResolvedValueOnce(envelope({ current_step: { ref: "username-password-form" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", {});
    expect(snapshot.status).toBe("needs_credentials");
    expect(snapshot.stepRef).toBe("username-password-form");
  });

  it("chains through several internal steps in one call, bounded by MAX_AUTO_ADVANCE_DEPTH", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "ip-blocklist" } }));
    transportMock.submit
      .mockResolvedValueOnce(envelope({ current_step: { ref: "ip-allowlist" } }))
      .mockResolvedValueOnce(envelope({ current_step: { ref: "check-session-id" } }))
      .mockResolvedValueOnce(envelope({ current_step: { ref: "username-password-form" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(transportMock.submit).toHaveBeenCalledTimes(3);
    expect(snapshot.status).toBe("needs_credentials");
  });

  it("gives up after MAX_AUTO_ADVANCE_DEPTH and falls back to the generic required-action state rather than looping forever", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "check-session-id" } }));
    transportMock.submit.mockResolvedValue(envelope({ current_step: { ref: "check-session-id" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(transportMock.submit).toHaveBeenCalledTimes(5); // MAX_AUTO_ADVANCE_DEPTH
    expect(snapshot.status).toBe("needs_required_action");
    expect(snapshot.stepRef).toBe("check-session-id");
  });

  it("autoAdvanceInternalSteps: false surfaces the internal step ref as-is (opt-out)", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "check-session-id" } }));
    const flow = createHeadlessAuthFlow({ ...OPTIONS, autoAdvanceInternalSteps: false }, sink);

    const snapshot = await flow.start();

    expect(transportMock.submit).not.toHaveBeenCalled();
    expect(snapshot.stepRef).toBe("check-session-id");
    expect(snapshot.status).toBe("needs_required_action");
  });

  // --- Prummo resilience #2: MFA submits the `otp` field, not `code` --------

  it("submitMfaCode() sends { otp } on the wire, never { code }", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "otp-input-form" } }));
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({
      access_token: "at",
      token_type: "Bearer",
    });
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await flow.submitMfaCode("257424");

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { otp: "257424" });
  });

  // --- confirmMfaSetup(): otp-configure-form (distinct step, same wire field) --

  it("confirmMfaSetup() sends { otp } on the wire, same field as submitMfaCode but a distinct method for otp-configure-form", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "otp-configure-form" }, data: { otp_string: "otpauth://totp/x" } }));
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({ access_token: "at", token_type: "Bearer" });
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const startSnapshot = await flow.start();

    expect(startSnapshot.status).toBe("needs_mfa_configure");

    await flow.confirmMfaSetup("123456");

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { otp: "123456" });
  });

  // --- submitTermsAgreement(): terms-agreement's string-booleans + LGPD consent gate ---

  it("submitTermsAgreement(true, ...) sends string booleans + terms_version, never native JSON booleans", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "terms-agreement" } }));
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({ access_token: "at", token_type: "Bearer" });
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await flow.submitTermsAgreement(true, { consentAccepted: true, termsVersion: "2026-09-01" });

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", {
      terms_agreed: "true",
      consent_accepted: "true",
      terms_version: "2026-09-01",
    });
  });

  it("submitTermsAgreement(false) sends only terms_agreed:\"false\", no consent/version fields", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "terms-agreement" } }));
    transportMock.submit.mockResolvedValue(envelope({ current_step: { ref: "terms-agreement" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await flow.submitTermsAgreement(false);

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { terms_agreed: "false" });
  });

  it("submitTermsAgreement(true) without consentAccepted throws synchronously (caller bug, never round-trips to the backend)", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "terms-agreement" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await expect(flow.submitTermsAgreement(true)).rejects.toThrow(/consent_accepted/);
    expect(transportMock.submit).not.toHaveBeenCalled();
  });

  // --- submitDeviceConsent(): device-consent-form, body-only now that B4 shipped ---

  it("submitDeviceConsent(true) sends { consent_accepted: \"true\" } in the JSON body — never the query string (B4 fixed)", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "device-consent-form" } }));
    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({ access_token: "at", token_type: "Bearer" });
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await flow.submitDeviceConsent(true);

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { consent_accepted: "true" });
  });

  it("submitDeviceConsent(false) sends { consent_accepted: \"false\" } (string, never a native JSON boolean)", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "device-consent-form" } }));
    transportMock.submit.mockResolvedValue(envelope({ current_step: { ref: "device-consent-form" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await flow.submitDeviceConsent(false);

    const [, body] = transportMock.submit.mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toEqual({ consent_accepted: "false" });
    expect(typeof body.consent_accepted).toBe("string");
  });

  // --- setPassword(): create-password-form's wire fields ---------------------

  it("setPassword() sends { password, confirmation_password } on the wire, and derives needs_password", async () => {
    transportMock.start.mockResolvedValue(envelope({ current_step: { ref: "create-password-form" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const startSnapshot = await flow.start();

    expect(startSnapshot.status).toBe("needs_password");

    transportMock.submit.mockResolvedValue(
      envelope({ status: "authenticated", current_step: null, code: "auth-code", oidc_state: "s", data: {} }),
    );
    vi.mocked(exchangeAuthorizationCode).mockResolvedValue({
      access_token: "at",
      token_type: "Bearer",
    });

    await flow.setPassword("Sup3r$ecret", "Sup3r$ecret");

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", {
      password: "Sup3r$ecret",
      confirmation_password: "Sup3r$ecret",
    });
  });

  // --- Prummo resilience #3: flow_expired auto-restarts the flow ------------

  it("submit() on an expired flow_token transparently restarts via start() and marks the snapshot restartedAfterExpiry", async () => {
    transportMock.start
      .mockResolvedValueOnce(envelope({ flow_token: "ft-1", current_step: { ref: "username-password-form" } }))
      .mockResolvedValueOnce(envelope({ flow_token: "ft-2", current_step: { ref: "username-password-form" } }));
    transportMock.submit.mockRejectedValueOnce(
      new JummonAuthError("flow_expired", "flow expired", { code: "flow_expired", type: "expired" }),
    );
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(transportMock.start).toHaveBeenCalledTimes(2); // original start() + auto-restart
    expect(snapshot.status).toBe("needs_credentials");
    expect(snapshot.flowToken).toBe("ft-2"); // fresh flow_token from the restart, not the expired one
    expect(snapshot.restartedAfterExpiry).toBe(true);
    expect(snapshot.error).toBeNull();
  });

  it("a snapshot right after a restart is exactly one snapshot — the NEXT transition drops restartedAfterExpiry", async () => {
    transportMock.start
      .mockResolvedValueOnce(envelope({ flow_token: "ft-1" }))
      .mockResolvedValueOnce(envelope({ flow_token: "ft-2" }));
    transportMock.submit
      .mockRejectedValueOnce(new JummonAuthError("flow_expired", "flow expired"))
      .mockResolvedValueOnce(envelope({ flow_token: "ft-2", current_step: { ref: "otp-input-form" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    await flow.submitPassword("jane@example.com", "hunter2"); // triggers the restart

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2"); // normal call post-restart

    expect(snapshot.restartedAfterExpiry).toBeUndefined();
  });

  it("autoRestartOnExpiry: false surfaces flow_expired as a normal error snapshot (opt-out)", async () => {
    transportMock.start.mockResolvedValue(envelope());
    transportMock.submit.mockRejectedValue(new JummonAuthError("flow_expired", "flow expired"));
    const flow = createHeadlessAuthFlow({ ...OPTIONS, autoRestartOnExpiry: false }, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("flow_expired");
    expect(transportMock.start).toHaveBeenCalledTimes(1); // no auto-restart
  });

  it("dispose() clears any persisted pending flow", async () => {
    transportMock.start.mockResolvedValue(envelope());
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    expect(window.sessionStorage.getItem(STORAGE_KEY)).not.toBeNull();

    flow.dispose();

    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});
