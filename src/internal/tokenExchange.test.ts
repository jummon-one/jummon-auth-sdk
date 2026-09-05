import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { revokeToken } from "./tokenExchange";

/**
 * Exercises `revokeToken()` against the REAL `fetchDiscoveryDocument()` (not
 * mocked) — a fresh `tenant` per test avoids colliding with
 * `fetchDiscoveryDocument`'s module-level per-authority cache.
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe("revokeToken (RFC 7009)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reads revocation_endpoint off the discovery doc (never hardcoded) and POSTs token+token_type_hint+client_id", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/revoke-tenant-1/oidc",
          token_endpoint: "https://idm.jummon.dev/revoke-tenant-1/oidc/oauth/token",
          revocation_endpoint: "https://idm.jummon.dev/revoke-tenant-1/oidc/revoke",
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }));

    const ok = await revokeToken({
      tenant: "revoke-tenant-1",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: "rt-abc",
      tokenTypeHint: "refresh_token",
    });

    expect(ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.dev/revoke-tenant-1/oidc/revoke");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("omit");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("token")).toBe("rt-abc");
    expect(body.get("token_type_hint")).toBe("refresh_token");
    expect(body.get("client_id")).toBe("acme-app");
  });

  it("returns false (never throws) when the discovery doc has no revocation_endpoint", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        issuer: "https://idm.jummon.dev/revoke-tenant-2/oidc",
        token_endpoint: "https://idm.jummon.dev/revoke-tenant-2/oidc/oauth/token",
        // no revocation_endpoint
      }),
    );

    const ok = await revokeToken({
      tenant: "revoke-tenant-2",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: "rt-abc",
      tokenTypeHint: "refresh_token",
    });

    expect(ok).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1); // only the discovery fetch, no revoke POST
  });

  it("returns false (never throws) on a non-2xx revoke response", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/revoke-tenant-3/oidc",
          token_endpoint: "https://idm.jummon.dev/revoke-tenant-3/oidc/oauth/token",
          revocation_endpoint: "https://idm.jummon.dev/revoke-tenant-3/oidc/revoke",
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 500 }));

    const ok = await revokeToken({
      tenant: "revoke-tenant-3",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: "rt-abc",
      tokenTypeHint: "refresh_token",
    });

    expect(ok).toBe(false);
  });

  it("returns false (never throws) when the network fails outright", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    const ok = await revokeToken({
      tenant: "revoke-tenant-4",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: "rt-abc",
      tokenTypeHint: "refresh_token",
    });

    expect(ok).toBe(false);
  });

  it("never logs the token value on any code path", async () => {
    const consoleSpies = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {}),
      vi.spyOn(console, "error").mockImplementation(() => {}),
    ];
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const secretToken = "rt-do-not-log-this-value";

    await revokeToken({
      tenant: "revoke-tenant-5",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: secretToken,
      tokenTypeHint: "refresh_token",
    });

    for (const spy of consoleSpies) {
      for (const call of spy.mock.calls) {
        for (const arg of call) {
          expect(String(arg)).not.toContain(secretToken);
        }
      }
      spy.mockRestore();
    }
  });
});
