import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { listCredentials, removeCredential } from "./credentialsSelfService";

describe("listCredentials", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("happy path: GETs .../catalog/me/credentials, Bearer auth, apiHost (not issuerHost) as base, maps kind->type + snake_case->camelCase, surfaces partial_failures", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          credentials: [
            { id: "42", kind: "passkey", name: "My phone", active: true, created_at: "2026-01-01T00:00:00Z" },
            { kind: "otp", name: "Authenticator app", active: true },
          ],
          partial_failures: ["otp"],
        }),
        { status: 200 },
      ),
    );

    const result = await listCredentials("token-1", { apiHost: "api.jummon.dev" });

    expect(result).toEqual({
      credentials: [
        { id: "42", type: "passkey", name: "My phone", active: true, createdAt: "2026-01-01T00:00:00Z" },
        { id: undefined, type: "otp", name: "Authenticator app", active: true, createdAt: undefined },
      ],
      partialFailures: ["otp"],
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials");
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
  });

  it("the otp entry has no id — never fabricated client-side", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ credentials: [{ kind: "otp", active: true }] }), { status: 200 }),
    );

    const result = await listCredentials("token-1", { apiHost: "api.jummon.dev" });

    expect(result.credentials[0]?.id).toBeUndefined();
  });

  it("empty enrollment (no credentials/partial_failures keys) resolves to empty arrays, not a crash", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }));

    await expect(listCredentials("token-1", { apiHost: "api.jummon.dev" })).resolves.toEqual({
      credentials: [],
      partialFailures: [],
    });
  });

  it("maps a 401 to not_authenticated", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "invalid token" }), { status: 401 }),
    );

    await expect(listCredentials("token-1", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "not_authenticated",
    });
  });

  it("maps a 5xx to credentials_fetch_failed, not a bare unknown", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UPSTREAM_REQUEST_FAILED", message: "upstream error" }), {
        status: 500,
      }),
    );

    await expect(listCredentials("token-1", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "credentials_fetch_failed",
    });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(listCredentials("token-1", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "network_unreachable",
    });
  });

  it("classifies a malformed (non-JSON) response as unknown", async () => {
    fetchMock.mockResolvedValueOnce(new Response("not json", { status: 200 }));

    const err = await listCredentials("token-1", { apiHost: "api.jummon.dev" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("unknown");
  });
});

describe("removeCredential", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("happy path: DELETEs .../catalog/me/credentials/{id}, Bearer auth, resolves on 204", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).resolves.toBeUndefined();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/42");
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("URL-encodes the credential id", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await removeCredential("token-1", "cred/with slash", { apiHost: "api.jummon.dev" });

    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/cred%2Fwith%20slash");
  });

  it("maps an ordinary 401 (missing/expired token) to not_authenticated", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "unauthorized", code: "DENY_INVALID_TOKEN", message: "token not active" }), {
        status: 401,
      }),
    );

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "not_authenticated",
    });
  });

  it("gateway step-up rejection (401 INSUFFICIENT_ASSURANCE_LEVEL) maps to step_up_required and parses the WWW-Authenticate header", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: "unauthorized", code: "INSUFFICIENT_ASSURANCE_LEVEL", message: "step-up required" }),
        {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Bearer error="insufficient_user_authentication", acr_values="loa2", max_age=300',
          },
        },
      ),
    );

    const err = await removeCredential("token-1", "42", { apiHost: "api.jummon.dev" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("step_up_required");
    expect((err as JummonAuthError).cause).toEqual({ acrValues: "loa2", maxAgeSeconds: 300 });
    expect(fetchMock).toHaveBeenCalledTimes(1); // never auto-retried
  });

  it("gateway step-up rejection with an unreadable/absent WWW-Authenticate header falls back to this route's KNOWN required_acr='loa2'/max_age=300", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "INSUFFICIENT_ASSURANCE_LEVEL", message: "step-up required" }), {
        status: 401,
        // No WWW-Authenticate header set — simulates the real cross-origin
        // case where CORS doesn't expose it to browser JS.
      }),
    );

    const err = await removeCredential("token-1", "42", { apiHost: "api.jummon.dev" }).catch((e: unknown) => e);
    expect((err as JummonAuthError).code).toBe("step_up_required");
    expect((err as JummonAuthError).cause).toEqual({ acrValues: "loa2", maxAgeSeconds: 300 });
  });

  it("last-factor guard: ME_CREDENTIAL_LAST_FACTOR maps to last_factor_blocked regardless of the (currently-500) status jummon-pkg's unwired PreconditionFailed Kind produces", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ code: "ME_CREDENTIAL_LAST_FACTOR", message: "removing this credential would leave the account with no remaining login factor" }),
        { status: 500 },
      ),
    );

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "last_factor_blocked",
    });
  });

  it("not-found/IDOR guard: ME_CREDENTIAL_NOT_FOUND maps to credential_not_found", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "ME_CREDENTIAL_NOT_FOUND", message: "credential does not belong to the caller or does not exist" }), {
        status: 404,
      }),
    );

    await expect(removeCredential("token-1", "999", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "credential_not_found",
    });
  });

  it("an unclassified failure collapses to credential_removal_failed", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UPSTREAM_REQUEST_FAILED", message: "boom" }), { status: 500 }),
    );

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "credential_removal_failed",
    });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "network_unreachable",
    });
  });

  it("a 5xx with no JSON body collapses to credential_removal_failed with a generic message", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 500 }));

    await expect(removeCredential("token-1", "42", { apiHost: "api.jummon.dev" })).rejects.toMatchObject({
      code: "credential_removal_failed",
    });
  });

  // --- #5b: headless step-up → retry (opts.headlessStepUp) -----------------

  describe("headless step-up retry (#5b, opts.headlessStepUp)", () => {
    function stepUpChallengeResponse(): Response {
      return new Response(
        JSON.stringify({ error: "unauthorized", code: "INSUFFICIENT_ASSURANCE_LEVEL", message: "step-up required" }),
        {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Bearer error="insufficient_user_authentication", acr_values="loa2", max_age=300',
          },
        },
      );
    }

    it("on step_up_required, drives a headless re-auth to loa2 and retries the DELETE with the fresh token", async () => {
      fetchMock
        .mockResolvedValueOnce(stepUpChallengeResponse()) // first DELETE — stale token
        .mockResolvedValueOnce(new Response(null, { status: 204 })); // retried DELETE — fresh token
      const start = vi.fn().mockResolvedValue({ status: "authenticated" });
      const getAccessToken = vi.fn().mockResolvedValue("fresh-loa2-token");

      await expect(
        removeCredential("stale-token", "42", { apiHost: "api.jummon.dev", headlessStepUp: { start, getAccessToken } }),
      ).resolves.toBeUndefined();

      expect(start).toHaveBeenCalledWith({ acrValues: "loa2", maxAge: 300 });
      expect(getAccessToken).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [, secondInit] = fetchMock.mock.calls[1] as [string, RequestInit];
      expect((secondInit.headers as Record<string, string>).Authorization).toBe("Bearer fresh-loa2-token");
    });

    it("never loops: a retried DELETE that ALSO 401s with step_up_required surfaces that error rather than retrying again", async () => {
      fetchMock.mockResolvedValueOnce(stepUpChallengeResponse()).mockResolvedValueOnce(stepUpChallengeResponse());
      const start = vi.fn().mockResolvedValue({ status: "authenticated" });
      const getAccessToken = vi.fn().mockResolvedValue("still-not-loa2-token");

      const err = await removeCredential("stale-token", "42", {
        apiHost: "api.jummon.dev",
        headlessStepUp: { start, getAccessToken },
      }).catch((e: unknown) => e);

      expect((err as JummonAuthError).code).toBe("step_up_required");
      expect(start).toHaveBeenCalledTimes(1); // not retried a second time
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("a re-auth that doesn't reach authenticated (still interactive — e.g. needs_mfa) falls through to the ORIGINAL step_up_required, DELETE never retried", async () => {
      fetchMock.mockResolvedValueOnce(stepUpChallengeResponse());
      const start = vi.fn().mockResolvedValue({ status: "needs_mfa" });
      const getAccessToken = vi.fn();

      const err = await removeCredential("stale-token", "42", {
        apiHost: "api.jummon.dev",
        headlessStepUp: { start, getAccessToken },
      }).catch((e: unknown) => e);

      expect((err as JummonAuthError).code).toBe("step_up_required");
      expect(getAccessToken).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledTimes(1); // DELETE never retried
    });

    it("authenticated but getAccessToken() resolves null (e.g. storage race) falls through to the ORIGINAL step_up_required", async () => {
      fetchMock.mockResolvedValueOnce(stepUpChallengeResponse());
      const start = vi.fn().mockResolvedValue({ status: "authenticated" });
      const getAccessToken = vi.fn().mockResolvedValue(null);

      const err = await removeCredential("stale-token", "42", {
        apiHost: "api.jummon.dev",
        headlessStepUp: { start, getAccessToken },
      }).catch((e: unknown) => e);

      expect((err as JummonAuthError).code).toBe("step_up_required");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("the re-auth attempt itself throwing is swallowed (best-effort) and still surfaces the ORIGINAL step_up_required, never the internal throw", async () => {
      fetchMock.mockResolvedValueOnce(stepUpChallengeResponse());
      const start = vi.fn().mockRejectedValue(new JummonAuthError("network_unreachable", "no network"));

      const err = await removeCredential("stale-token", "42", {
        apiHost: "api.jummon.dev",
        headlessStepUp: { start, getAccessToken: vi.fn() },
      }).catch((e: unknown) => e);

      expect((err as JummonAuthError).code).toBe("step_up_required");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });
});
