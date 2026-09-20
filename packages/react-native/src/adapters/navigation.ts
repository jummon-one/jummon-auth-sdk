import { JummonAuthError, type PlatformNavigation } from "@jummon/auth/core";

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

/**
 * threat model §3.5 R12 (non-negotiable) — the account-recovery return leg
 * is the ONE deep-link entry point in this SDK that MUST reject a bare
 * custom-scheme URL (`myapp://...`) and accept ONLY an OS-verified Android
 * App Link / iOS Universal Link (always `https://`). This is DELIBERATELY
 * separate from `createReactNativeNavigation` above, which stays
 * transport-agnostic for the general OIDC/social-login redirect leg (that
 * leg already carries its own defense — PKCE, `HeadlessAuthFlowCore.start()`
 * — RFC 8252 §8.7 explicitly permits a private-use URI scheme there
 * specifically BECAUSE PKCE covers it; recovery historically had no
 * equivalent binding until R13, so R12 raises its transport bar instead of
 * loosening the already-adequate one).
 *
 * `isOsVerifiedRecoveryLink` is exported standalone (pure, no `Linking`
 * dependency) so an integrator can also use it to gate their OWN routing
 * logic before ever constructing a listener.
 */
export function isOsVerifiedRecoveryLink(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

export interface RecoveryReturnLinkHandlers {
  /** Fires with the OS-verified (`https://`) URL that resumed/foregrounded the app for a recovery return — safe to hand to whatever resumes the recovery UI (e.g. correlating it back to an in-progress `HeadlessRecoveryFlowCore`/`redirectUri` per design). */
  onRecoveryReturn(url: string): void;
  /**
   * Fires when a URL matched `matchesRecoveryReturn` but FAILED the App-Link/
   * Universal-Link check (R12) — `onRecoveryReturn` is never called for it.
   * Required, not optional: a rejection here is a live scheme-hijack signal
   * (T16), never something safe to drop silently. Typical handling: log it
   * (via `auditlog`-equivalent client-side telemetry) and surface a generic
   * "couldn't complete recovery from this link" error to the user — never
   * retry with the rejected URL, never fall back to treating it as valid.
   */
  onRejectedLink(url: string, error: JummonAuthError): void;
}

/**
 * Wires `linking` (cold-start `getInitialURL()` + the `'url'` event) to
 * `handlers`, running EVERY candidate URL through
 * {@link isOsVerifiedRecoveryLink} before ever calling `onRecoveryReturn` —
 * see this module's own doc comment on why this is a separate listener
 * from `createReactNativeNavigation`, not a flag on it.
 *
 * `matchesRecoveryReturn` scopes which URLs this listener even considers a
 * recovery-return candidate at all (e.g. `(url) => url.startsWith(options.
 * redirectUri)` against the same `redirectUri` passed to
 * `HeadlessRecoveryFlowOptions` — design §11.2's "the link `dynamic-flows`
 * mints already carries `reference_url`/`redirect_uri`") — a URL that
 * doesn't match is ignored entirely (neither callback fires), since it's
 * simply not a recovery link, not a rejected one.
 *
 * Returns an unsubscribe function — call it on unmount, same contract as
 * `LinkingLike.addEventListener`'s own `{remove()}`.
 */
export function createRecoveryReturnListener(
  linking: LinkingLike,
  matchesRecoveryReturn: (url: string) => boolean,
  handlers: RecoveryReturnLinkHandlers,
): () => void {
  const evaluate = (url: string | null): void => {
    if (!url || !matchesRecoveryReturn(url)) {
      return;
    }
    if (!isOsVerifiedRecoveryLink(url)) {
      handlers.onRejectedLink(
        url,
        new JummonAuthError(
          "recovery_link_not_os_verified",
          "This account-recovery link must be an OS-verified App Link / Universal Link (https://) — a custom URL scheme was rejected (threat model §3.5 R12).",
        ),
      );
      return;
    }
    handlers.onRecoveryReturn(url);
  };

  void linking.getInitialURL().then(evaluate);
  const subscription = linking.addEventListener("url", (event) => evaluate(event.url));
  return () => subscription.remove();
}
