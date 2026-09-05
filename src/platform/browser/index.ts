import { JummonAuthError } from "../../errors";
import type { JummonAuthOptions } from "../../types";
import type { PlatformAdapters } from "../../core/platform/types";
import { createBrowserStorage } from "./storage";
import { browserCrypto } from "./crypto";
import { browserNavigation } from "./navigation";
import { browserWebAuthn } from "./webauthn";

/**
 * Default adapter bag for the WEB package (`@jummon/auth`'s
 * `createJummonAuth()`). This is the ONLY place in the browser wiring layer
 * that checks `typeof window === "undefined"` — the same synchronous,
 * construct-time `ssr_unsupported` throw `HeadlessEngine`/
 * `HeadlessAuthFlowCore`'s constructors performed directly pre-refactor,
 * just relocated here so the agnostic core itself never touches `window`.
 *
 * A React Native engine (Phase 2) never calls this function — it builds its
 * own `PlatformAdapters` and constructs `HeadlessEngineCore`/
 * `HeadlessAuthFlowCore` directly, so it never hits this guard (or `window`
 * at all).
 */
export function createBrowserPlatformAdapters(options: JummonAuthOptions): PlatformAdapters {
  if (typeof window === "undefined") {
    throw new JummonAuthError(
      "ssr_unsupported",
      "createJummonAuth() must run in a browser context (window is undefined). " +
        "Call it from a client component / effect, not during server rendering.",
    );
  }
  return {
    storage: createBrowserStorage(options.tokenStorage),
    crypto: browserCrypto,
    navigation: browserNavigation,
    webauthn: browserWebAuthn,
  };
}

export { browserCrypto, browserNavigation, browserWebAuthn, createBrowserStorage };
