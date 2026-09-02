import { beforeEach, describe, expect, it, vi } from "vitest";
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

function envelope(overrides: Partial<HeadlessAuthEnvelope> = {}): HeadlessAuthEnvelope {
  return {
    flow_token: "ft-1",
    state: "needs_credentials",
    step_ref: "username-password-form",
    data: {},
    error: null,
    ...overrides,
  };
}

describe("HeadlessAuthFlow", () => {
  let transportMock: { start: ReturnType<typeof vi.fn>; submit: ReturnType<typeof vi.fn>; poll: ReturnType<typeof vi.fn> };
  let sink: HeadlessSessionSink;

  beforeEach(() => {
    transportMock = { start: vi.fn(), submit: vi.fn(), poll: vi.fn() };
    (HeadlessTransport as unknown as ReturnType<typeof vi.fn>).mockImplementation(() => transportMock);
    sink = { completeSignIn: vi.fn().mockReturnValue({ sub: "u1", tenant: "acme", roles: [], permissions: [], raw: {} }) };
    vi.mocked(exchangeAuthorizationCode).mockReset();
  });

  it("start() mints PKCE material and transitions to the first step returned by the Auth API", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);

    const snapshot = await flow.start();

    expect(snapshot.status).toBe("needs_credentials");
    expect(snapshot.flowToken).toBe("ft-1");
    expect(flow.state).toEqual(snapshot);

    const startArgs = transportMock.start.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(startArgs.redirect_uri).toBe(OPTIONS.redirectUri);
    expect(startArgs.code_challenge_method).toBe("S256");
    expect(typeof startArgs.code_challenge).toBe("string");
    expect(typeof startArgs.state).toBe("string");
  });

  it("submitPassword() before start() throws flow_not_started", async () => {
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await expect(flow.submitPassword("jane@example.com", "hunter2")).rejects.toMatchObject({
      code: "flow_not_started",
    });
  });

  it("submitPassword() forwards to submit() with the current flow_token and applies the next envelope", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    transportMock.submit.mockResolvedValue(envelope({ state: "needs_mfa", step_ref: "otp-input-form", data: { foo: "bar" } }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "hunter2");

    expect(transportMock.submit).toHaveBeenCalledWith("ft-1", { username: "jane@example.com", password: "hunter2" });
    expect(snapshot.status).toBe("needs_mfa");
    expect(snapshot.data).toEqual({ foo: "bar" });
  });

  it("on the terminal authenticated envelope, exchanges the code and hands the resulting user to the sink", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    transportMock.submit.mockResolvedValue(envelope({ state: "authenticated", code: "auth-code", oidc_state: "state-1" }));
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

  it("startPasskeyLogin() throws passkey_origin_unsupported when passkeyOriginOk isn't true", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials", passkey_origin_ok: false }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    await expect(flow.startPasskeyLogin("jane@example.com")).rejects.toMatchObject({
      code: "passkey_origin_unsupported",
    });
  });

  it("startSocialLogin() navigates the browser full-page to redirect_url on needs_social_redirect", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    transportMock.submit.mockResolvedValue(
      envelope({ state: "needs_social_redirect", data: { redirect_url: "https://accounts.google.com/o/oauth2/auth" } }),
    );
    const assign = vi.fn();
    const originalLocation = window.location;
    // jsdom's `window.location` isn't directly spy-able (assign is a
    // non-configurable native binding) — swap the whole object for the
    // duration of this test instead.
    Object.defineProperty(window, "location", { value: { ...originalLocation, assign }, writable: true });

    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();
    await flow.startSocialLogin("google");

    expect(assign).toHaveBeenCalledWith("https://accounts.google.com/o/oauth2/auth");

    Object.defineProperty(window, "location", { value: originalLocation, writable: true });
  });

  it("a transport error resolves to an `error` status snapshot instead of throwing out of submit", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    transportMock.submit.mockRejectedValue(new JummonAuthError("invalid_credentials", "nope"));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    await flow.start();

    const snapshot = await flow.submitPassword("jane@example.com", "wrong");

    expect(snapshot.status).toBe("error");
    expect(snapshot.error?.code).toBe("invalid_credentials");
  });

  it("onStateChange fires immediately with the current snapshot and on every subsequent transition", async () => {
    transportMock.start.mockResolvedValue(envelope({ state: "needs_credentials" }));
    const flow = createHeadlessAuthFlow(OPTIONS, sink);
    const seen: string[] = [];
    const unsubscribe = flow.onStateChange((snapshot) => seen.push(snapshot.status));

    await flow.start();
    unsubscribe();

    expect(seen[0]).toBe("idle");
    expect(seen).toContain("loading");
    expect(seen[seen.length - 1]).toBe("needs_credentials");
  });
});
