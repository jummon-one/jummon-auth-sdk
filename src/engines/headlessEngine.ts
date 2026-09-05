import { createBrowserPlatformAdapters } from "../platform/browser";
import type { PlatformAdapters } from "../core/platform/types";
import { HeadlessEngineCore } from "../core/headlessEngineCore";
import type { HeadlessSessionSink } from "../flow/headlessAuthFlow";
import type { TokenResponse } from "../internal/tokenExchange";
import type { AuthEngine, AuthState, JummonAuthOptions, JummonUser, SignInOptions, SignOutOptions } from "../types";

/**
 * `HeadlessEngine implements AuthEngine`. The 8 `AuthEngine` methods
 * delegate to the platform-agnostic `HeadlessEngineCore`
 * (`../core/headlessEngineCore.ts`), constructed here with the default
 * browser adapters (`../platform/browser`) unless a caller supplies its own
 * — the seam a future React Native engine uses to construct the same core
 * with `AsyncStorage`/`Linking`/etc. adapters instead, without importing
 * this class at all.
 *
 * Preserves the exact pre-refactor construction behavior: `new
 * HeadlessEngine(options)` with no second argument throws `ssr_unsupported`
 * synchronously when called outside a browser context (now via
 * `createBrowserPlatformAdapters`, see that function's doc comment).
 *
 * `signIn()`/`signInCallback()` cannot express a multi-step login with a
 * single call, so both fail loud with `headless_requires_flow` rather than
 * silently doing something surprising — `startAuthFlow()`
 * (`../client.ts`) is the real entrypoint.
 */
export class HeadlessEngine implements AuthEngine, HeadlessSessionSink {
  private readonly core: HeadlessEngineCore;

  constructor(options: JummonAuthOptions, adapters: PlatformAdapters = createBrowserPlatformAdapters(options)) {
    this.core = new HeadlessEngineCore(options, adapters);
  }

  signIn(opts?: SignInOptions): Promise<void> {
    return this.core.signIn(opts);
  }

  signInCallback(url?: string): Promise<JummonUser> {
    return this.core.signInCallback(url);
  }

  signOut(opts?: SignOutOptions): Promise<void> {
    return this.core.signOut(opts);
  }

  getUser(): Promise<JummonUser | null> {
    return this.core.getUser();
  }

  getAccessToken(): Promise<string | null> {
    return this.core.getAccessToken();
  }

  isAuthenticated(): Promise<boolean> {
    return this.core.isAuthenticated();
  }

  onAuthStateChanged(cb: (state: AuthState) => void): () => void {
    return this.core.onAuthStateChanged(cb);
  }

  dispose(): void {
    this.core.dispose();
  }

  /** `HeadlessSessionSink` — see `HeadlessEngineCore.completeSignIn()`'s doc comment. */
  completeSignIn(tokens: TokenResponse): JummonUser {
    return this.core.completeSignIn(tokens);
  }
}
