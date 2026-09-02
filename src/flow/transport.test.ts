import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { HeadlessTransport } from "./transport";
import type { HeadlessAuthEnvelope, HeadlessErrorEnvelope } from "./types";

/** Real backend success-envelope shape (wire-contract-v1.md §3.1) — status + current_step, never state/step_ref. */
function envelope(overrides: Partial<HeadlessAuthEnvelope> = {}): HeadlessAuthEnvelope {
  return {
    flow_token: "ft-1",
    status: "needs_input",
    current_step: { ref: "username-password-form" },
    data: {},
    ...overrides,
  };
}

/** Real backend flat error-envelope shape (wire-contract-v1.md §4.1) — no nested `error` key. */
function errorEnvelope(overrides: Partial<HeadlessErrorEnvelope> = {}): HeadlessErrorEnvelope {
  return {
    flow_token: "ft-1",
    code: "invalid_request",
    message: "Something went wrong.",
    ...overrides,
  };
}

describe("HeadlessTransport", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("puts tenant and client_id in the URL path, never the JSON body (MUST-FIX 4/5)", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(envelope()), { status: 200 }));
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await transport.start({
      redirect_uri: "https://app.acme.com/callback",
      code_challenge: "chal",
      code_challenge_method: "S256",
      state: "state-1",
      nonce: "nonce-1",
      scope: "openid profile email offline_access",
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.dev/api/v1/auth/acme/acme-app/start");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).not.toHaveProperty("tenant");
    expect(body).not.toHaveProperty("client_id");
    expect(body.redirect_uri).toBe("https://app.acme.com/callback");
  });

  it("sends `scope` as a singular space-delimited string, not `scopes: string[]` (blocker #2)", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(envelope()), { status: 200 }));
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await transport.start({
      redirect_uri: "https://app.acme.com/callback",
      code_challenge: "chal",
      code_challenge_method: "S256",
      state: "state-1",
      nonce: "nonce-1",
      scope: "openid profile email offline_access",
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body.scope).toBe("openid profile email offline_access");
    expect(body).not.toHaveProperty("scopes");
  });

  it("sends the flow_token as X-Flow-Token on submit/poll, never as a cookie", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(envelope()), { status: 200 }));
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await transport.submit("ft-abc", { username: "jane@example.com" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.dev/api/v1/auth/acme/acme-app/submit");
    expect((init.headers as Record<string, string>)["X-Flow-Token"]).toBe("ft-abc");
    expect(init.credentials).toBe("omit");
  });

  it("returns the real backend envelope shape unchanged: status + current_step{ref,name}, not state/step_ref", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify(envelope({ current_step: { ref: "otp-input-form", name: "One-time code" } })),
        { status: 200 },
      ),
    );
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    const result = await transport.poll("ft-1");

    expect(result.status).toBe("needs_input");
    expect(result.current_step).toEqual({ ref: "otp-input-form", name: "One-time code" });
    expect(result).not.toHaveProperty("state");
    expect(result).not.toHaveProperty("step_ref");
  });

  it("parses the FLAT {code,message} error envelope — no nested `error` key (blocker #3)", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(errorEnvelope({ code: "AUTH-AUTHN-2001", message: "invalid" })), { status: 401 }),
    );
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await expect(transport.submit("ft-1", { username: "x" })).rejects.toMatchObject({
      code: "invalid_credentials",
    });
  });

  it("maps Family A local codes (flow_expired, cors_origin_rejected) verbatim — previously always collapsed to unknown", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(errorEnvelope({ code: "flow_expired", message: "expired" })), { status: 401 }),
    );
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await expect(transport.poll("ft-1")).rejects.toMatchObject({ code: "flow_expired" });
  });

  it("falls back to the `type` bucket for an unmapped AUTH-* code instead of a bare unknown", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify(errorEnvelope({ code: "AUTH-INT-9999", message: "boom", type: "authentication" })),
        { status: 400 },
      ),
    );
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await expect(transport.submit("ft-1", {})).rejects.toMatchObject({ code: "invalid_credentials" });
  });

  it("classifies a fetch throw on start() as cors_origin_rejected when the browser reports online", async () => {
    vi.stubGlobal("navigator", { onLine: true });
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    const err = await transport
      .start({
        redirect_uri: "https://app.acme.com/callback",
        code_challenge: "chal",
        code_challenge_method: "S256",
        state: "s",
        nonce: "n",
        scope: "openid",
      })
      .catch((e: unknown) => e as JummonAuthError);

    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("cors_origin_rejected");
  });

  it("classifies a fetch throw on submit() (already trusted with a flow_token) as network_unreachable", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    const err = await transport.submit("ft-1", { username: "x" }).catch((e: unknown) => e as JummonAuthError);
    expect(err.code).toBe("network_unreachable");
  });
});
