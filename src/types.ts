/**
 * Public, stable types for @jummon/auth.
 *
 * These types are the contract consumers (and the React binding) code
 * against. `AuthEngine` is the extension point: `RedirectEngine` (full-page
 * authorization-code + PKCE redirect via oidc-client-ts) and
 * `HeadlessEngine` (in-app password form, passkey, social via
 * system-browser redirect — see ../ROADMAP.md and `./client.ts`'s
 * `HeadlessJummonAuthClient`) both implement it, so the 8-method surface
 * never changes between modes.
 */

/** Engine implementation selector — see `JummonAuthOptions.mode`. */
export type JummonAuthMode = "redirect" | "headless";

export interface JummonAuthOptions {
  /** Tenant slug, e.g. "acme". Never the tenant UUID. */
  tenant: string;
  /** OIDC public client_id registered for this tenant, e.g. "acme-app". */
  clientId: string;
  /**
   * Absolute callback URL the browser returns to after login, e.g.
   * "https://app.example.com/auth/callback". MUST exactly match one
   * of the client's registered `redirect_uris` in Jummon — the auth-engine
   * rejects (or, if it cannot even redirect back, error-pages) a mismatch.
   */
  redirectUri: string;
  /**
   * OIDC scopes requested at /authorize.
   * Default: ["openid", "profile", "email", "offline_access"].
   * "offline_access" is what makes the auth-engine issue a refresh_token —
   * required for getAccessToken() to silently refresh. There is no "roles"
   * scope on Jummon: roles[]/permissions[] ride the token unconditionally.
   */
  scopes?: string[];
  /** Where the browser lands after signOut(). Defaults to `redirectUri`. */
  postLogoutRedirectUri?: string;
  /**
   * Host that serves the tenant's OIDC discovery doc.
   * Default: "idm.jummon.com" (production). Use "idm.jummon.dev" for the
   * dev environment. Never hardcode a full discovery/authorize/token URL —
   * this option is the only host knob; the SDK derives every endpoint from
   * `https://<issuerHost>/<tenant>/oidc/.well-known/openid-configuration`.
   */
  issuerHost?: string;
  /**
   * Engine selector. `"redirect"` (default): full-page redirect to the
   * hosted login. `"headless"`: in-app password/passkey/social login via
   * `createJummonAuth({ ...options, mode: "headless" }).startAuthFlow()` —
   * see `./flow/headlessAuthFlow.ts` and `system-design.md` §6. In headless
   * mode, `signIn()`/`signInCallback()` throw `headless_requires_flow`;
   * `startAuthFlow()` is the real entrypoint.
   */
  mode?: JummonAuthMode;
  /**
   * Automatically renew the access token in the background before it
   * expires (via silent iframe or refresh_token rotation). Default: true.
   */
  automaticSilentRenew?: boolean;
  /**
   * Where the SDK persists the OIDC session (survives full-page reloads and
   * the redirect round-trip). Default: "session". See README "Security /
   * token storage" for the trade-off vs. an httpOnly-cookie-backed BFF.
   */
  tokenStorage?: "session" | "local" | "memory";
  /**
   * Headless mode only. The Auth API interleaves a few input-less internal
   * steps (`check-session-id`, `ip-blocklist`, `ip-allowlist`) that the
   * hosted SSR login auto-advances server-side (`loginHandler.ts`'s
   * `AUTO_POST_STEPS`/`autoProceed`) but the headless wire does not — left
   * unhandled, they'd surface to the app as a phantom "action required"
   * step. Default: true — `HeadlessAuthFlow` auto-submits `{}` for these
   * refs (bounded retries) and never emits them as `current_step`. Set to
   * `false` to see them yourself (they fall through to the generic
   * `needs_required_action` state).
   */
  autoAdvanceInternalSteps?: boolean;
  /**
   * Headless mode only. The flow_token has a short (~5min) absolute TTL; a
   * step submitted after expiry fails with `{type:"expired", code:
   * "flow_expired"}`. Default: true — `HeadlessAuthFlow` transparently calls
   * `start()` again (same tenant/client/redirectUri/scope, fresh PKCE pair)
   * and re-emits from the first step instead of surfacing the error. The
   * restarted snapshot carries `restartedAfterExpiry: true` exactly once so
   * the app can react (e.g. clear a stale form) with a one-line check. Set
   * to `false` to handle `flow_expired` yourself.
   */
  autoRestartOnExpiry?: boolean;
  /**
   * Host that serves the Jummon API gateway (`jummon-api-gateway`) —
   * `client.registerPasskey()`'s only consumer today
   * (`../internal/passkeyEnrollment.ts`, `POST /catalog/me/credentials/
   * passkeys/{begin,finish}`). Default: "api.jummon.com" (production). Use
   * "api.jummon.dev" for the dev environment
   * (`shared/platform.md`'s "Client calls api.jummon.dev/<path>" convention).
   * **Never the same host as `issuerHost`** — that one serves tenant-in-path
   * OIDC discovery only and does not proxy gateway-routed catalog-api calls;
   * `discovery.ts`'s own doc comment calls out `api.jummon.com` as invalid
   * there for the identical reason in reverse.
   */
  apiHost?: string;
}

/** Result of `JummonAuthClient.registerPasskey()` — the newly-enrolled credential. */
export interface PasskeyRegistrationResult {
  /** Opaque credential id, useful for a "Manage passkeys" list; never render it as a secret. */
  credentialId: string;
  /** Display name — the caller-supplied `name`, or a server-side default (e.g. the authenticator's own label) when omitted. */
  name: string;
}

/**
 * Result of `JummonAuthClient.beginOtpEnroll()` — catalog-api's
 * `RegisterOtpBeginResponse` (`POST /catalog/me/credentials/otp/enroll/begin`),
 * disclosed EXACTLY ONCE (a fresh `beginOtpEnroll()` call mints a brand-new
 * secret server-side — never re-fetchable). `secret` is for DISPLAY only
 * (QR / manual-entry fallback) — it is NOT passed to `confirmOtpEnroll(otp)`,
 * which takes only the code; the server validates against its own persisted
 * copy of this exact secret, never a client-supplied one. Never log `secret`,
 * never persist it.
 */
export interface OtpEnrollmentChallenge {
  /** `otpauth://` provisioning URI — render this as a QR code for the authenticator app to scan. */
  otpUrl: string;
  /** Same secret encoded in `otpUrl`, for the "can't scan? enter this code manually" fallback. Display only. */
  secret: string;
}

/** A signed-in Jummon user, derived from the validated id_token + access_token claims. */
export interface JummonUser {
  /** Stable subject identifier (the user's UUID within the tenant). */
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  /** Tenant slug this user authenticated against. */
  tenant: string;
  /**
   * Role names, straight off the token's `roles[]` claim.
   * Never render raw permission strings to end users — map them through
   * your own catalog if you need a friendly label.
   */
  roles: string[];
  /** Permission strings off the token's `permissions[]` claim, e.g. "catalog:roles:create". */
  permissions: string[];
  /** Full decoded claim set (id_token profile merged with access_token claims), escape hatch for anything not modeled above. */
  raw: Record<string, unknown>;
}

export type AuthState =
  | { status: "loading" }
  | { status: "authenticated"; user: JummonUser }
  | { status: "unauthenticated" };

export interface SignInOptions {
  /** Opaque app state round-tripped back to signInCallback() via the OIDC `state` param. */
  state?: unknown;
  /** Extra query params forwarded to /authorize (e.g. a social provider hint). */
  extraQueryParams?: Record<string, string>;
  /** OIDC `prompt` param — "login" forces re-authentication, "none" attempts silent auth. */
  prompt?: "none" | "login" | "consent" | "select_account";
}

export interface SignOutOptions {
  /**
   * When true (default), navigates the browser to the tenant's
   * end_session_endpoint (full logout, clears the IdP session too). When
   * false, only clears the local session — the user stays logged in at
   * Jummon and a next signIn() may not show a login prompt.
   */
  redirect?: boolean;
}

/**
 * The engine interface every auth mechanism implements. `RedirectEngine`
 * (v1) is the only concrete implementation shipped today; it wraps
 * oidc-client-ts's UserManager. `createJummonAuth()` is the only supported
 * way to obtain one — the interface itself is exported for testing/mocking.
 */
export interface AuthEngine {
  signIn(opts?: SignInOptions): Promise<void>;
  /** Call once, on the page that `redirectUri` points at, to exchange the code for tokens. */
  signInCallback(url?: string): Promise<JummonUser>;
  signOut(opts?: SignOutOptions): Promise<void>;
  getUser(): Promise<JummonUser | null>;
  /** Returns a valid access token, silently refreshing first if the cached one is expired. Null if signed out. */
  getAccessToken(): Promise<string | null>;
  isAuthenticated(): Promise<boolean>;
  /** Subscribe to auth state transitions. Returns an unsubscribe function. Fires once immediately with the current state. */
  onAuthStateChanged(cb: (state: AuthState) => void): () => void;
  dispose(): void;
}
