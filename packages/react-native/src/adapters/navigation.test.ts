import { describe, expect, it, vi } from "vitest";
import {
  createReactNativeNavigation,
  createRecoveryReturnListener,
  isHttpsRecoveryReturnScheme,
  type LinkingLike,
} from "./navigation";

function mockLinking(initialUrl: string | null = null): LinkingLike & { emit: (url: string) => void } {
  let handler: ((event: { url: string }) => void) | null = null;
  return {
    openURL: vi.fn(),
    getInitialURL: vi.fn().mockResolvedValue(initialUrl),
    addEventListener: vi.fn((_type, cb) => {
      handler = cb;
      return { remove: vi.fn() };
    }),
    emit: (url: string) => handler?.({ url }),
  };
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("createReactNativeNavigation", () => {
  it("redirect() calls Linking.openURL, never an in-app WebView", () => {
    const linking = mockLinking();
    const nav = createReactNativeNavigation(linking);

    nav.redirect("https://accounts.google.com/o/oauth2/v2/auth");

    expect(linking.openURL).toHaveBeenCalledWith("https://accounts.google.com/o/oauth2/v2/auth");
  });

  it("getCurrentUrl() picks up a cold-start deep link via getInitialURL() even with no 'url' event fired", async () => {
    const linking = mockLinking("acme://auth/callback?code=abc&state=s1");
    const nav = createReactNativeNavigation(linking);

    await flushMicrotasks();

    expect(nav.getCurrentUrl()).toBe("acme://auth/callback?code=abc&state=s1");
  });

  it("getCurrentUrl() updates on a warm-relaunch 'url' event", () => {
    const linking = mockLinking(null);
    const nav = createReactNativeNavigation(linking);

    expect(nav.getCurrentUrl()).toBeNull();
    linking.emit("acme://auth/callback?auth_resume=1");

    expect(nav.getCurrentUrl()).toBe("acme://auth/callback?auth_resume=1");
  });

  it("clearAuthParams() is a no-op (nothing to strip from a non-existent URL bar/history)", () => {
    const linking = mockLinking("acme://auth/callback?code=abc");
    const nav = createReactNativeNavigation(linking);

    expect(() => nav.clearAuthParams()).not.toThrow();
  });
});

// threat model §3.5 R12 — App Links / Universal Links only, for the
// recovery-token-bearing return leg specifically. This checks the URL
// SCHEME ONLY — it is necessary but NOT SUFFICIENT for R12's actual
// OS-verification guarantee, which depends on the integrator's native
// config (assetlinks.json/AASA + autoVerify/Associated Domains); see the
// function's own doc comment in navigation.ts.
describe("isHttpsRecoveryReturnScheme", () => {
  it("accepts https:// (App Link / Universal Link shape)", () => {
    expect(isHttpsRecoveryReturnScheme("https://acme.app/recover?token=abc")).toBe(true);
  });

  it("rejects a bare custom URL scheme", () => {
    expect(isHttpsRecoveryReturnScheme("myapp://recover?token=abc")).toBe(false);
    expect(isHttpsRecoveryReturnScheme("acme://recover?token=abc")).toBe(false);
  });

  it("rejects http:// too — App/Universal Links are always https", () => {
    expect(isHttpsRecoveryReturnScheme("http://acme.app/recover?token=abc")).toBe(false);
  });

  it("rejects a malformed URL rather than throwing", () => {
    expect(isHttpsRecoveryReturnScheme("not a url at all")).toBe(false);
  });
});

describe("createRecoveryReturnListener", () => {
  const matchesRecover = (url: string) => url.includes("/recover");

  it("calls onRecoveryReturn for an OS-verified cold-start link", async () => {
    const linking = mockLinking("https://acme.app/recover?token=abc");
    const onRecoveryReturn = vi.fn();
    const onRejectedLink = vi.fn();

    createRecoveryReturnListener(linking, matchesRecover, { onRecoveryReturn, onRejectedLink });
    await flushMicrotasks();

    expect(onRecoveryReturn).toHaveBeenCalledWith("https://acme.app/recover?token=abc");
    expect(onRejectedLink).not.toHaveBeenCalled();
  });

  it("R12: rejects a custom-scheme URL for the recovery leg — onRecoveryReturn is NEVER called for it", async () => {
    const linking = mockLinking("myapp://recover?token=abc");
    const onRecoveryReturn = vi.fn();
    const onRejectedLink = vi.fn();

    createRecoveryReturnListener(linking, matchesRecover, { onRecoveryReturn, onRejectedLink });
    await flushMicrotasks();

    expect(onRecoveryReturn).not.toHaveBeenCalled();
    expect(onRejectedLink).toHaveBeenCalledOnce();
    const [rejectedUrl, error] = onRejectedLink.mock.calls[0] as [string, { code: string }];
    expect(rejectedUrl).toBe("myapp://recover?token=abc");
    expect(error.code).toBe("recovery_link_not_os_verified");
  });

  it("ignores a URL that doesn't match the recovery matcher at all — neither callback fires", async () => {
    const linking = mockLinking("acme://auth/callback?code=abc&state=s1");
    const onRecoveryReturn = vi.fn();
    const onRejectedLink = vi.fn();

    createRecoveryReturnListener(linking, matchesRecover, { onRecoveryReturn, onRejectedLink });
    await flushMicrotasks();

    expect(onRecoveryReturn).not.toHaveBeenCalled();
    expect(onRejectedLink).not.toHaveBeenCalled();
  });

  it("evaluates a warm-relaunch 'url' event the same way as cold start", () => {
    const linking = mockLinking(null);
    const onRecoveryReturn = vi.fn();
    const onRejectedLink = vi.fn();

    createRecoveryReturnListener(linking, matchesRecover, { onRecoveryReturn, onRejectedLink });
    linking.emit("myapp://recover?token=abc");

    expect(onRejectedLink).toHaveBeenCalledOnce();
    expect(onRecoveryReturn).not.toHaveBeenCalled();
  });

  it("returns an unsubscribe function that calls the underlying subscription's remove()", () => {
    const linking = mockLinking(null);
    const unsubscribe = createRecoveryReturnListener(linking, matchesRecover, {
      onRecoveryReturn: vi.fn(),
      onRejectedLink: vi.fn(),
    });

    unsubscribe();

    const addEventListenerMock = linking.addEventListener as unknown as { mock: { results: { value: { remove: () => void } }[] } };
    const result = addEventListenerMock.mock.results[0];
    expect(result?.value.remove).toHaveBeenCalled();
  });
});
