import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UserManager } from "oidc-client-ts";

vi.mock("../internal/tokenExchange", () => ({ revokeToken: vi.fn() }));

import { revokeToken } from "../internal/tokenExchange";
import { RedirectEngine } from "./redirectEngine";

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  issuerHost: "idm.jummon.dev",
  tokenStorage: "memory" as const,
};

/** Spies on the `UserManager` prototype methods `RedirectEngine` delegates to — returned together so each test's local variables are inferred from the actual `vi.spyOn` call sites instead of a mismatched hoisted type. */
function spyOnUserManager() {
  const getUserSpy = vi.spyOn(UserManager.prototype, "getUser");
  const removeUserSpy = vi.spyOn(UserManager.prototype, "removeUser").mockResolvedValue();
  const signoutRedirectSpy = vi.spyOn(UserManager.prototype, "signoutRedirect").mockResolvedValue(undefined as never);
  return { getUserSpy, removeUserSpy, signoutRedirectSpy };
}

describe("RedirectEngine.signOut({redirect:false}) token revocation (#9)", () => {
  beforeEach(() => {
    vi.mocked(revokeToken).mockReset().mockResolvedValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("revokes the refresh_token via the discovery-doc revocation_endpoint before removeUser() clears local state", async () => {
    const { getUserSpy, removeUserSpy } = spyOnUserManager();
    getUserSpy.mockResolvedValue({ refresh_token: "rt-secret-1" } as never);
    const engine = new RedirectEngine(OPTIONS);

    await engine.signOut({ redirect: false });

    expect(revokeToken).toHaveBeenCalledWith({
      tenant: "acme",
      issuerHost: "idm.jummon.dev",
      clientId: "acme-app",
      token: "rt-secret-1",
      tokenTypeHint: "refresh_token",
    });
    expect(removeUserSpy).toHaveBeenCalledTimes(1);
  });

  it("never calls revokeToken() when there is no stored user / no refresh_token", async () => {
    const { getUserSpy, removeUserSpy } = spyOnUserManager();
    getUserSpy.mockResolvedValue(null);
    const engine = new RedirectEngine(OPTIONS);

    await engine.signOut({ redirect: false });

    expect(revokeToken).not.toHaveBeenCalled();
    expect(removeUserSpy).toHaveBeenCalledTimes(1);
  });

  it("still completes signOut (removeUser + unauthenticated) when revokeToken() rejects", async () => {
    const { getUserSpy, removeUserSpy } = spyOnUserManager();
    getUserSpy.mockResolvedValue({ refresh_token: "rt-secret-2" } as never);
    vi.mocked(revokeToken).mockRejectedValue(new Error("network exploded"));
    const engine = new RedirectEngine(OPTIONS);
    const states: string[] = [];
    engine.onAuthStateChanged((state) => states.push(state.status));

    await expect(engine.signOut({ redirect: false })).resolves.toBeUndefined();

    expect(removeUserSpy).toHaveBeenCalledTimes(1);
    expect(states).toContain("unauthenticated");
  });

  it("never logs the refresh_token value anywhere during signOut()", async () => {
    const { getUserSpy } = spyOnUserManager();
    const consoleSpies = [
      vi.spyOn(console, "log").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {}),
      vi.spyOn(console, "error").mockImplementation(() => {}),
    ];
    const secretToken = "rt-do-not-log-this-value";
    getUserSpy.mockResolvedValue({ refresh_token: secretToken } as never);
    vi.mocked(revokeToken).mockRejectedValue(new Error("network exploded"));
    const engine = new RedirectEngine(OPTIONS);

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

  it("does NOT call revokeToken() on the default (redirect:true) hosted end-session path — unchanged scope", async () => {
    const { getUserSpy, signoutRedirectSpy } = spyOnUserManager();
    getUserSpy.mockResolvedValue({ refresh_token: "rt-secret-3" } as never);
    const engine = new RedirectEngine(OPTIONS);

    await engine.signOut();

    expect(signoutRedirectSpy).toHaveBeenCalledTimes(1);
    expect(revokeToken).not.toHaveBeenCalled();
  });
});
