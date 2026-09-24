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
 *
 * `clearAuthParams()` has NO history/URL bar to strip `code`/`state` from —
 * but it is NOT a no-op. Bug-class fix (see `core/headlessAuthFlowCore.ts`'s
 * `consumedAuthCode` doc comment for the matching core-side guard): without
 * this, `lastUrl` keeps holding the one-shot `code`/`state` from a
 * social-login/deep-link return FOREVER, so a LATER `resume()` (app
 * foreground / component remount) reads the exact same, already-consumed
 * `code` off `getCurrentUrl()` again and drives a second, doomed
 * `invalid_grant` exchange of a single-use authorization code — even though
 * the FIRST exchange already established the session. `clearAuthParams()`
 * therefore marks the current `lastUrl` as consumed; `getCurrentUrl()`
 * withholds a URL once it's been marked. A genuinely FRESH deep link (a new
 * `'url'` event, or a new cold start) always updates `lastUrl` and is
 * returned normally — this only withholds the exact URL string that was
 * already handed off.
 */
export function createReactNativeNavigation(linking: LinkingLike): PlatformNavigation {
  let lastUrl: string | null = null;
  /**
   * Set by `clearAuthParams()` to whatever `lastUrl` was at that instant —
   * the one-shot `code`/`state` it carried have already been read once and
   * must not be handed back. See this function's doc comment.
   */
  let consumedUrl: string | null = null;

  void linking.getInitialURL().then((url) => {
    if (url) {
      lastUrl = url;
    }
  });
  linking.addEventListener("url", (event) => {
    lastUrl = event.url;
    // A brand-new deep link always supersedes whatever was marked consumed
    // — belt-and-suspenders alongside the `lastUrl !== consumedUrl` check
    // below (which alone would already do the right thing whenever the new
    // URL differs, but a fresh event should never be shadowed by a stale
    // consumed marker regardless).
    consumedUrl = null;
  });

  return {
    redirect(url: string): void {
      void linking.openURL(url);
    },
    getCurrentUrl(): string | null {
      return lastUrl !== null && lastUrl === consumedUrl ? null : lastUrl;
    },
    clearAuthParams(): void {
      // No address bar/history to strip one-shot params from on this
      // platform — instead, forget them by marking the current `lastUrl` as
      // consumed so a later `resume()` can't read the same `code`/`state`
      // off it again. See this function's doc comment above.
      consumedUrl = lastUrl;
    },
  };
}
