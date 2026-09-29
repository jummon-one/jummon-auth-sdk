import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __clearRichClaimsCacheForTests, fetchRichClaims } from "./richClaims";

/**
 * Exercises `fetchRichClaims()` against the REAL `fetchDiscoveryDocument()`
 * (not mocked) — a fresh `tenant` per test avoids colliding with
 * `fetchDiscoveryDocument`'s module-level per-authority cache, same pattern
 * `tokenExchange.test.ts` uses for `revokeToken()`.
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe("fetchRichClaims (issue #8 SDK migration — userinfo as PRIMARY permissions source)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    __clearRichClaimsCacheForTests();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reads userinfo_endpoint off the discovery doc (never hardcoded) and POSTs the access_token as Bearer, no body", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/rich-tenant-1/oidc",
          token_endpoint: "https://idm.jummon.dev/rich-tenant-1/oidc/oauth/token",
          userinfo_endpoint: "https://idm.jummon.dev/rich-tenant-1/oidc/userinfo",
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ permissions: ["catalog:roles:create"], roles: ["Admin"] }));

    const claims = await fetchRichClaims({
      tenant: "rich-tenant-1",
      issuerHost: "idm.jummon.dev",
      accessToken: "at-abc",
    });

    expect(claims).toEqual({ permissions: ["catalog:roles:create"], roles: ["Admin"] });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.dev/rich-tenant-1/oidc/userinfo");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("omit");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer at-abc");
    expect(init.body).toBeUndefined();
  });

  it("caches by access_token — a second call against the SAME token does not re-fetch", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/rich-tenant-2/oidc",
          token_endpoint: "https://idm.jummon.dev/rich-tenant-2/oidc/oauth/token",
          userinfo_endpoint: "https://idm.jummon.dev/rich-tenant-2/oidc/userinfo",
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ permissions: ["catalog:roles:create"] }));

    const args = { tenant: "rich-tenant-2", issuerHost: "idm.jummon.dev", accessToken: "at-cached" };
    const first = await fetchRichClaims(args);
    const second = await fetchRichClaims(args);

    expect(first).toEqual({ permissions: ["catalog:roles:create"] });
    expect(second).toEqual({ permissions: ["catalog:roles:create"] });
    expect(fetchMock).toHaveBeenCalledTimes(2); // discovery + userinfo, ONCE each — not 4
  });

  it("resolves null (never throws) when the discovery doc has no userinfo_endpoint", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        issuer: "https://idm.jummon.dev/rich-tenant-3/oidc",
        token_endpoint: "https://idm.jummon.dev/rich-tenant-3/oidc/oauth/token",
        // no userinfo_endpoint
      }),
    );

    await expect(
      fetchRichClaims({ tenant: "rich-tenant-3", issuerHost: "idm.jummon.dev", accessToken: "at-abc" }),
    ).resolves.toBeNull();
  });

  it("resolves null (never throws) on a non-2xx userinfo response, and does NOT pin the failure in cache (next call retries live)", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/rich-tenant-4/oidc",
          token_endpoint: "https://idm.jummon.dev/rich-tenant-4/oidc/oauth/token",
          userinfo_endpoint: "https://idm.jummon.dev/rich-tenant-4/oidc/userinfo",
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 401 }));

    const args = { tenant: "rich-tenant-4", issuerHost: "idm.jummon.dev", accessToken: "at-expired" };
    await expect(fetchRichClaims(args)).resolves.toBeNull();

    // Second call retries live (not pinned as a cached failure). The
    // discovery doc itself is ALREADY cached per-authority by
    // `fetchDiscoveryDocument` (same tenant/issuerHost as above), so only
    // one more fetch — the userinfo POST — is needed this time.
    fetchMock.mockResolvedValueOnce(jsonResponse({ permissions: ["catalog:roles:create"] }));
    await expect(fetchRichClaims(args)).resolves.toEqual({ permissions: ["catalog:roles:create"] });
  });

  it("resolves null (never throws) when the network fails outright", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    await expect(
      fetchRichClaims({ tenant: "rich-tenant-5", issuerHost: "idm.jummon.dev", accessToken: "at-abc" }),
    ).resolves.toBeNull();
  });

  it("never logs the access_token value on any code path", async () => {
    const consoleSpies = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {}),
      vi.spyOn(console, "error").mockImplementation(() => {}),
    ];
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    const secretToken = "at-do-not-log-this-value";

    await fetchRichClaims({ tenant: "rich-tenant-6", issuerHost: "idm.jummon.dev", accessToken: secretToken });

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
