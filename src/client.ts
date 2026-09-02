import { RedirectEngine } from "./engines/redirectEngine";
import { JummonAuthError } from "./errors";
import type {
  AuthEngine,
  AuthState,
  JummonAuthOptions,
  JummonUser,
  SignInOptions,
  SignOutOptions,
} from "./types";

/**
 * The stable public client. Every method here delegates to the current
 * AuthEngine — this shape is what stays identical across v1 (redirect) and
 * the future v2 (headless) engine; only `createJummonAuth()`'s internal
 * engine selection changes.
 */
export interface JummonAuthClient {
  /** v1: full-page redirect to the hosted login. Resolves once the browser navigates away. */
  signIn(opts?: SignInOptions): Promise<void>;
  /** Call on the page `redirectUri` points at; exchanges the authorization code for tokens. */
  signInCallback(url?: string): Promise<JummonUser>;
  signOut(opts?: SignOutOptions): Promise<void>;
  getUser(): Promise<JummonUser | null>;
  getAccessToken(): Promise<string | null>;
  isAuthenticated(): Promise<boolean>;
  onAuthStateChanged(cb: (state: AuthState) => void): () => void;
  /** Releases event listeners / stops background silent renew. Call on unmount in non-React apps. */
  dispose(): void;
}

export function createJummonAuth(options: JummonAuthOptions): JummonAuthClient {
  validateOptions(options);
  const engine = createEngine(options);

  return {
    signIn: (opts) => engine.signIn(opts),
    signInCallback: (url) => engine.signInCallback(url),
    signOut: (opts) => engine.signOut(opts),
    getUser: () => engine.getUser(),
    getAccessToken: () => engine.getAccessToken(),
    isAuthenticated: () => engine.isAuthenticated(),
    onAuthStateChanged: (cb) => engine.onAuthStateChanged(cb),
    dispose: () => engine.dispose(),
  };
}

function createEngine(options: JummonAuthOptions): AuthEngine {
  const mode = options.mode ?? "redirect";
  if (mode === "headless") {
    throw new JummonAuthError(
      "engine_not_implemented",
      '"headless" mode is reserved for a future @jummon/auth release (see ROADMAP.md and ' +
        "engineering-team/initiatives/headless-embeddable-auth). v1 supports mode: \"redirect\" only.",
    );
  }
  return new RedirectEngine(options);
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
