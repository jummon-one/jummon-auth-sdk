import { describe, expect, it, vi } from "vitest";
import { createReactNativeNavigation, type LinkingLike } from "./navigation";

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
