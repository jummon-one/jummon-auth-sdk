import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { HeadlessTransport } from "./transport";
import type { HeadlessAuthEnvelope } from "./types";

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
      scopes: ["openid"],
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.dev/api/v1/auth/acme/acme-app/start");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).not.toHaveProperty("tenant");
    expect(body).not.toHaveProperty("client_id");
    expect(body.redirect_uri).toBe("https://app.acme.com/callback");
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

  it("maps a wire {error.code} onto a stable JummonAuthErrorCode via mapHeadlessErrorCode", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify(envelope({ error: { code: "AUTH-AUTHN-2001", message: "invalid" } })),
        { status: 401 },
      ),
    );
    const transport = new HeadlessTransport({ tenant: "acme", clientId: "acme-app", issuerHost: "idm.jummon.dev" });

    await expect(transport.submit("ft-1", { username: "x" })).rejects.toMatchObject({
      code: "invalid_credentials",
    });
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
        scopes: ["openid"],
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
