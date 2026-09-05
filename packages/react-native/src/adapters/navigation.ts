import type { PlatformNavigation } from "@jummon/auth/core";

/**
 * Structural shape of RN's `Linking` module (works for both `react-native`'s
 * built-in `Linking` and `expo-linking`, which re-exports a
 * structurally-compatible surface) — defined locally, never imported, same
 * reasoning as the storage/crypto adapters. `addEventListener` returning a
 * `{remove()}` subscription is the RN >=0.65 shape (the modern one); an app
 * on an older RN pins to `react-native@>=0.65` anyway per this package's
 * peerDependency range.
 */
export interface LinkingLike {
  openURL(url: string): Promise<void> | void;
  /** Cold-start deep link — the app was LAUNCHED by this URL, so the `'url'` event below never fires for it. */
  getInitialURL(): Promise<string | null>;
  addEventListener(type: "url", handler: (event: { url: string }) => void): { remove(): void };
}

/**
 * RN has no addressable URL bar — `PlatformNavigation.getCurrentUrl()` must
 * still be SYNCHRONOUS (the core's `resume()` calls it directly, no
 * `await`), so this adapter keeps its own mutable `lastUrl`, updated two
 * ways: once eagerly at construction via `getInitialURL()` (covers a cold
 * start where the deep link that launched the app never fires an `'url'`
 * event), and continuously via the `'url'` event listener (covers a warm
 * relaunch/foreground return after the social-provider hop). A `resume()`
 * call on mount reads whatever `lastUrl` holds at that instant — same
 * "read back on return" shape `core/flowPersistence.ts`'s doc comment
 * describes for storage, applied to navigation instead.
 *
 * `redirect()` opens the system browser (`Linking.openURL` — Android intent
 * chooser / iOS `SFSafariViewController` under an Expo/RN wrapper), never an
 * in-app WebView, per the same rule the browser adapter's doc comment states
 * (Google and other IdPs block embedded-WebView OAuth outright).
 * `clearAuthParams()` is a no-op — there is no history/URL bar to strip
 * `code`/`state` from.
 */
export function createReactNativeNavigation(linking: LinkingLike): PlatformNavigation {
  let lastUrl: string | null = null;

  void linking.getInitialURL().then((url) => {
    if (url) {
      lastUrl = url;
    }
  });
  linking.addEventListener("url", (event) => {
    lastUrl = event.url;
  });

  return {
    redirect(url: string): void {
      void linking.openURL(url);
    },
    getCurrentUrl(): string | null {
      return lastUrl;
    },
    clearAuthParams(): void {
      // No-op — no addressable URL bar/history to strip one-shot params
      // from on this platform, see doc comment above.
    },
  };
}
