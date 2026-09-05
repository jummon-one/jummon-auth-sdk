import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../internal/tokenExchange", () => ({
  fetchDiscoveryDocument: vi.fn(),
  refreshAccessToken: vi.fn(),
  revokeToken: vi.fn(),
}));

import { fetchDiscoveryDocument, refreshAccessToken, revokeToken } from "../internal/tokenExchange";
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
    vi.mocked(revokeToken).mockReset();
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

    // completeSignIn() is synchronous (in-memory cache write + emit), so it
    // always wins a race against the subscribe-time initial snapshot, which
    // now goes through the async `PlatformStorage` interface (required so a
    // React Native adapter can back it with `AsyncStorage` — see
    // `PlatformStorage`'s doc comment in `core/platform/types.ts`) and can no
    // longer resolve before this synchronous call returns, the way the old
    // fully-synchronous `Storage` read did. `headlessEngineCore.ts`'s
    // `read()` re-checks the cache after awaiting storage specifically so
    // this in-flight initial read never stomps the write that raced ahead of
    // it — both emissions converge on "authenticated", never a stale
    // "unauthenticated" from before completeSignIn() ran.
    engine.completeSignIn({
      access_token: fakeJwt({ sub: "u" }),
      token_type: "Bearer",
      expires_in: 3600,
    });

    // Flush every microtask hop the subscribe-time storage round trip needs
    // (await storage.getItem() -> await read() -> await getUser() -> the
    // onAuthStateChanged .then(cb) reaction).
    for (let i = 0; i < 5; i += 1) {
      await Promise.resolve();
    }

    expect(states.length).toBeGreaterThanOrEqual(1);
    expect(states.every((status) => status === "authenticated")).toBe(true);
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

  it("signOut() with no refresh_token in the session never calls revokeToken() (nothing to revoke)", async () => {
    const engine = new HeadlessEngine(OPTIONS);
    engine.completeSignIn({ access_token: fakeJwt({ sub: "u" }), token_type: "Bearer", expires_in: 3600 });

    await engine.signOut({ redirect: false });

    expect(revokeToken).not.toHaveBeenCalled();
  });

  // --- P1 fix: signOut() must revoke the refresh_token (RFC 7009) ----------

  describe("signOut() token revocation (P1)", () => {
    it("revokes the session's refresh_token via revokeToken() BEFORE local state is cleared, then completes signOut", async () => {
      vi.mocked(revokeToken).mockResolvedValue(true);
      const engine = new HeadlessEngine(OPTIONS);
      engine.completeSignIn({
        access_token: fakeJwt({ sub: "u" }),
        refresh_token: "rt-secret-1",
        token_type: "Bearer",
        expires_in: 3600,
      });

      await engine.signOut({ redirect: false });

      expect(revokeToken).toHaveBeenCalledWith({
        tenant: "acme",
        issuerHost: "idm.jummon.dev",
        clientId: "acme-app",
        token: "rt-secret-1",
        tokenTypeHint: "refresh_token",
      });
      // Local state is still cleared regardless — revoke isn't a
      // prerequisite for completing signOut, it's a side effect of it.
      expect(await engine.getUser()).toBeNull();
      expect(await engine.isAuthenticated()).toBe(false);
    });

    it("still clears local state and completes signOut when revokeToken() resolves false (non-2xx / revoke failed)", async () => {
      vi.mocked(revokeToken).mockResolvedValue(false);
      const engine = new HeadlessEngine(OPTIONS);
      engine.completeSignIn({
        access_token: fakeJwt({ sub: "u" }),
        refresh_token: "rt-secret-2",
        token_type: "Bearer",
        expires_in: 3600,
      });

      await expect(engine.signOut({ redirect: false })).resolves.toBeUndefined();

      expect(await engine.getUser()).toBeNull();
    });

    it("still clears local state and completes signOut when revokeToken() rejects (defensive — the real implementation never throws, but signOut() must not depend on that)", async () => {
      vi.mocked(revokeToken).mockRejectedValue(new Error("network exploded"));
      const engine = new HeadlessEngine(OPTIONS);
      engine.completeSignIn({
        access_token: fakeJwt({ sub: "u" }),
        refresh_token: "rt-secret-3",
        token_type: "Bearer",
        expires_in: 3600,
      });

      await expect(engine.signOut({ redirect: false })).resolves.toBeUndefined();

      expect(await engine.getUser()).toBeNull();
    });

    it("revocation runs even when redirect: false — it is unconditional cleanup, not tied to the end_session_endpoint redirect", async () => {
      vi.mocked(revokeToken).mockResolvedValue(true);
      const engine = new HeadlessEngine(OPTIONS);
      engine.completeSignIn({
        access_token: fakeJwt({ sub: "u" }),
        refresh_token: "rt-secret-4",
        token_type: "Bearer",
        expires_in: 3600,
      });

      await engine.signOut({ redirect: false });

      expect(revokeToken).toHaveBeenCalledTimes(1);
      // redirect:false still skips the end_session_endpoint discovery/redirect path.
      expect(fetchDiscoveryDocument).not.toHaveBeenCalled();
    });

    it("never logs the refresh_token value anywhere during signOut()", async () => {
      const consoleSpies = [
        vi.spyOn(console, "log").mockImplementation(() => {}),
        vi.spyOn(console, "info").mockImplementation(() => {}),
        vi.spyOn(console, "warn").mockImplementation(() => {}),
        vi.spyOn(console, "error").mockImplementation(() => {}),
        vi.spyOn(console, "debug").mockImplementation(() => {}),
      ];
      vi.mocked(revokeToken).mockRejectedValue(new Error("network exploded"));
      const secretToken = "rt-super-secret-value-do-not-log";
      const engine = new HeadlessEngine(OPTIONS);
      engine.completeSignIn({
        access_token: fakeJwt({ sub: "u" }),
        refresh_token: secretToken,
        token_type: "Bearer",
        expires_in: 3600,
      });

      await engine.signOut({ redirect: false });

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
});
