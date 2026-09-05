import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { setPasswordSelfService } from "./passwordSelfService";

describe("setPasswordSelfService", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("happy path: POSTs {password, confirmation_password}, Bearer auth, apiHost (not issuerHost) as base, resolves on 204", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(
      setPasswordSelfService("token-1", "Sup3r$ecret", "Sup3r$ecret", { apiHost: "api.jummon.dev" }),
    ).resolves.toBeUndefined();

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/password");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual({ password: "Sup3r$ecret", confirmation_password: "Sup3r$ecret" });
  });

  it("strips a trailing slash from apiHost", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev/" });

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/password");
  });

  it("maps a 401 to not_authenticated", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "invalid token" }), { status: 401 }),
    );

    await expect(
      setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "not_authenticated" });
  });

  it("maps a 403 (FEDERATED_PASSWORD_SET_FORBIDDEN) to access_denied", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ code: "FEDERATED_PASSWORD_SET_FORBIDDEN", message: "federated account" }),
        { status: 403 },
      ),
    );

    const err = await setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("access_denied");
    expect((err as JummonAuthError).message).toBe("federated account");
  });

  it("maps a 400 (password-policy rejection) to invalid_password, not a bare unknown", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "INVALID_PASSWORD", message: "too weak" }), { status: 400 }),
    );

    await expect(
      setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "invalid_password", message: "too weak" });
  });

  it("maps a 5xx with no JSON body to invalid_password with a generic message", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 500 }));

    await expect(
      setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "invalid_password" });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(
      setPasswordSelfService("token-1", "a", "a", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "network_unreachable" });
  });
});
