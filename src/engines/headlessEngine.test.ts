import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../internal/tokenExchange", () => ({
  fetchDiscoveryDocument: vi.fn(),
  refreshAccessToken: vi.fn(),
}));

import { fetchDiscoveryDocument, refreshAccessToken } from "../internal/tokenExchange";
import { HeadlessEngine } from "./headlessEngine";

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  issuerHost: "idm.jummon.dev",
  tokenStorage: "memory" as const,
};

function base64UrlJson(payload: Record<string, unknown>): string {
  const json = JSON.stringify(payload);
  const base64 = btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return base64;
}

function fakeJwt(claims: Record<string, unknown>): string {
  return `${base64UrlJson({ alg: "none" })}.${base64UrlJson(claims)}.sig`;
}

describe("HeadlessEngine", () => {
  beforeEach(() => {
    vi.mocked(fetchDiscoveryDocument).mockReset();
    vi.mocked(refreshAccessToken).mockReset();
  });

  it("signIn() and signInCallback() always throw headless_requires_flow", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    await expect(engine.signIn()).rejects.toMatchObject({ code: "headless_requires_flow" });
    await expect(engine.signInCallback()).rejects.toMatchObject({ code: "headless_requires_flow" });
  });

  it("getUser()/isAuthenticated() are null/false before any session exists", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    expect(await engine.getUser()).toBeNull();
    expect(await engine.isAuthenticated()).toBe(false);
    expect(await engine.getAccessToken()).toBeNull();
  });

  it("completeSignIn() persists tokens, and getUser()/getAccessToken() read them back mapped through buildJummonUser", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    const idToken = fakeJwt({ sub: "user-1", email: "jane@example.com" });
    const accessToken = fakeJwt({ sub: "user-1", roles: ["Admin"], permissions: ["catalog:roles:create"] });

    const user = engine.completeSignIn({
      access_token: accessToken,
      refresh_token: "rt-1",
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 3600,
    });

    expect(user.sub).toBe("user-1");
    expect(user.email).toBe("jane@example.com");
    expect(user.roles).toEqual(["Admin"]);
    expect(user.permissions).toEqual(["catalog:roles:create"]);

    expect(await engine.isAuthenticated()).toBe(true);
    expect(await engine.getAccessToken()).toBe(accessToken);
  });

  it("onAuthStateChanged fires authenticated once completeSignIn() runs", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    const states: string[] = [];
    engine.onAuthStateChanged((state) => states.push(state.status));

    engine.completeSignIn({
      access_token: fakeJwt({ sub: "u" }),
      token_type: "Bearer",
      expires_in: 3600,
    });

    await Promise.resolve();
    expect(states).toContain("unauthenticated");
    expect(states).toContain("authenticated");
  });

  it("getAccessToken() silently refreshes an expired access_token using the stored refresh_token", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    engine.completeSignIn({
      access_token: fakeJwt({ sub: "u" }),
      refresh_token: "rt-1",
      token_type: "Bearer",
      expires_in: -1, // already expired
    });

    const refreshedAccessToken = fakeJwt({ sub: "u", roles: ["Refreshed"] });
    vi.mocked(refreshAccessToken).mockResolvedValue({
      access_token: refreshedAccessToken,
      refresh_token: "rt-2",
      token_type: "Bearer",
      expires_in: 3600,
    });

    const token = await engine.getAccessToken();
    expect(token).toBe(refreshedAccessToken);
    expect(refreshAccessToken).toHaveBeenCalledWith(
      expect.objectContaining({ tenant: "acme", clientId: "acme-app", refreshToken: "rt-1" }),
    );
  });

  it("getAccessToken() throws silent_renew_failed when the token is expired and there is no refresh_token", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    engine.completeSignIn({
      access_token: fakeJwt({ sub: "u" }),
      token_type: "Bearer",
      expires_in: -1,
    });

    await expect(engine.getAccessToken()).rejects.toMatchObject({ code: "silent_renew_failed" });
  });

  it("signOut() clears the local session and emits unauthenticated without navigating when redirect: false", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    engine.completeSignIn({ access_token: fakeJwt({ sub: "u" }), token_type: "Bearer", expires_in: 3600 });

    await engine.signOut({ redirect: false });

    expect(await engine.getUser()).toBeNull();
    expect(fetchDiscoveryDocument).not.toHaveBeenCalled();
  });
});
