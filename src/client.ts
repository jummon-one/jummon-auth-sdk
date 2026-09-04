import { HeadlessEngine } from "./engines/headlessEngine";
import { RedirectEngine } from "./engines/redirectEngine";
import { JummonAuthError } from "./errors";
import { createHeadlessAuthFlow, type HeadlessAuthFlow } from "./flow/headlessAuthFlow";
import { DEFAULT_API_HOST, enrollPasskey } from "./internal/passkeyEnrollment";
import type {
  AuthEngine,
  AuthState,
  JummonAuthOptions,
  JummonUser,
  PasskeyRegistrationResult,
  SignInOptions,
  SignOutOptions,
} from "./types";

/**
 * The stable public client. Every method here delegates to the current
 * AuthEngine — this shape is what stays identical across v1 (redirect) and
 * v2 (headless); only `createJummonAuth()`'s internal engine selection
 * changes.
 */
export interface JummonAuthClient {
  /** v1 (redirect mode): full-page redirect to the hosted login. Resolves once the browser navigates away. Throws `headless_requires_flow` in headless mode — use `startAuthFlow()` instead. */
  signIn(opts?: SignInOptions): Promise<void>;
  /** Call on the page `redirectUri` points at; exchanges the authorization code for tokens. Not used in headless mode. */
  signInCallback(url?: string): Promise<JummonUser>;
  signOut(opts?: SignOutOptions): Promise<void>;
  getUser(): Promise<JummonUser | null>;
  getAccessToken(): Promise<string | null>;
  isAuthenticated(): Promise<boolean>;
  onAuthStateChanged(cb: (state: AuthState) => void): () => void;
  /** Releases event listeners / stops background silent renew. Call on unmount in non-React apps. */
  dispose(): void;
  /**
   * Standalone, post-login passkey enrollment (the "Enable biometric sign-in"
   * nudge) — works in BOTH `redirect` and `headless` mode, since it only
   * needs an already-authenticated session's access_token, not a
   * `HeadlessAuthFlow`. Distinct from `HeadlessAuthFlow.registerPasskey()`,
   * which answers a `fido-registration` step *during* login — see
   * `../internal/passkeyEnrollment.ts`'s doc comment.
   *
   * Requires a signed-in user: throws `not_authenticated` if
   * `getAccessToken()` resolves to `null`. Call `isPasskeySupported()`
   * (exported from the package root) first to decide whether to render the
   * nudge button at all — this method throws `passkey_origin_unsupported`
   * itself if called anyway on an unsupported browser/origin.
   *
   * Uses `JummonAuthOptions.apiHost` (the API gateway host), NEVER
   * `issuerHost` — see that option's doc comment.
   */
  registerPasskey(name?: string): Promise<PasskeyRegistrationResult>;
}

/**
 * Returned by `createJummonAuth({ ...options, mode: "headless" })` — the
 * same 8-method surface plus `startAuthFlow()`, the multi-step entrypoint
 * for an in-app password/passkey/social login (`system-design.md` §6,
 * `implementation-plan.md` §8).
 */
export interface HeadlessJummonAuthClient extends JummonAuthClient {
  /** Starts a new in-app login flow. See `HeadlessAuthFlow` (`./flow/headlessAuthFlow.ts`). */
  startAuthFlow(): HeadlessAuthFlow;
}

export function createJummonAuth(options: JummonAuthOptions & { mode: "headless" }): HeadlessJummonAuthClient;
export function createJummonAuth(options: JummonAuthOptions & { mode?: "redirect" }): JummonAuthClient;
// Fallback overload for callers holding a `JummonAuthOptions` whose `mode`
// isn't narrowed to a literal at the call site (e.g. `JummonAuthProvider`,
// which forwards arbitrary props) — resolves to the base 8-method surface;
// callers wanting `startAuthFlow()` must pass a literal `mode: "headless"`.
export function createJummonAuth(options: JummonAuthOptions): JummonAuthClient;
export function createJummonAuth(options: JummonAuthOptions): JummonAuthClient | HeadlessJummonAuthClient {
  validateOptions(options);

  if ((options.mode ?? "redirect") === "headless") {
    const engine = new HeadlessEngine(options);
    return {
      ...buildClient(engine, options),
      startAuthFlow: () => createHeadlessAuthFlow(options, engine),
    };
  }

  return buildClient(new RedirectEngine(options), options);
}

function buildClient(engine: AuthEngine, options: JummonAuthOptions): JummonAuthClient {
  return {
    signIn: (opts) => engine.signIn(opts),
    signInCallback: (url) => engine.signInCallback(url),
    signOut: (opts) => engine.signOut(opts),
    getUser: () => engine.getUser(),
    getAccessToken: () => engine.getAccessToken(),
    isAuthenticated: () => engine.isAuthenticated(),
    onAuthStateChanged: (cb) => engine.onAuthStateChanged(cb),
    dispose: () => engine.dispose(),
    registerPasskey: (name) => registerPasskeyViaEngine(engine, options, name),
  };
}

async function registerPasskeyViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
  name?: string,
): Promise<PasskeyRegistrationResult> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "registerPasskey() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return enrollPasskey(accessToken, name, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

function validateOptions(options: JummonAuthOptions): void {
  const missing = (["tenant", "clientId", "redirectUri"] as const).filter((key) => !options[key]);
  if (missing.length > 0) {
    throw new JummonAuthError(
      "invalid_options",
      `createJummonAuth: missing required option(s): ${missing.join(", ")}.`,
    );
  }
}
