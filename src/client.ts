import { HeadlessEngine } from "./engines/headlessEngine";
import { RedirectEngine } from "./engines/redirectEngine";
import { JummonAuthError } from "./errors";
import {
  createHeadlessAuthFlow,
  type HeadlessAuthFlow,
  type HeadlessSessionSink,
} from "./flow/headlessAuthFlow";
import { listCredentials, removeCredential, type HeadlessStepUp } from "./internal/credentialsSelfService";
import { beginOtpEnrollment, confirmOtpEnrollment } from "./internal/otpEnrollment";
import { DEFAULT_API_HOST, enrollPasskey } from "./internal/passkeyEnrollment";
import { setPasswordSelfService } from "./internal/passwordSelfService";
import type {
  AuthEngine,
  AuthState,
  CredentialListResult,
  JummonAuthOptions,
  JummonUser,
  OtpEnrollmentChallenge,
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
  /**
   * Standalone, post-login "set/change my password" — works in BOTH
   * `redirect` and `headless` mode, since it only needs an
   * already-authenticated session's access_token, not a `HeadlessAuthFlow`.
   * Distinct from `HeadlessAuthFlow.setPassword()`, which answers a
   * `create-password-form` required-action step *during* login — see
   * `../internal/passwordSelfService.ts`'s doc comment.
   *
   * Requires a signed-in user: throws `not_authenticated` if
   * `getAccessToken()` resolves to `null`. Throws `access_denied` for a
   * federated caller (catalog-api's `FEDERATED_PASSWORD_SET_FORBIDDEN`) and
   * `invalid_password` when the tenant's password policy rejects it.
   *
   * Uses `JummonAuthOptions.apiHost` (the API gateway host), NEVER
   * `issuerHost` — see that option's doc comment.
   */
  setPassword(password: string, confirmationPassword: string): Promise<void>;
  /**
   * Standalone, post-login TOTP (authenticator app) enrollment, step 1 of 2
   * — mints a secret + `otpauth://` provisioning URI to render as a QR code.
   * Works in BOTH `redirect` and `headless` mode. Distinct from the in-login
   * `otp-configure-form` required-action step (`HeadlessFlowState`'s
   * `needs_mfa_configure`, already handled via
   * `HeadlessAuthFlow.submitRequiredAction`) — see
   * `../internal/otpEnrollment.ts`'s doc comment.
   *
   * Requires a signed-in user: throws `not_authenticated` if
   * `getAccessToken()` resolves to `null`. Throws `access_denied` for a
   * federated caller (catalog-api's `FEDERATED_OTP_SET_FORBIDDEN`).
   *
   * Uses `JummonAuthOptions.apiHost` (the API gateway host), NEVER
   * `issuerHost` — see that option's doc comment.
   */
  beginOtpEnroll(): Promise<OtpEnrollmentChallenge>;
  /**
   * Standalone, post-login TOTP enrollment, step 2 of 2 — submits the first
   * code the user's authenticator app generated. There is no `secret`
   * parameter: the server validates against the secret it minted and
   * persisted at `beginOtpEnroll()`, never one the client supplies — see
   * `../internal/otpEnrollment.ts`'s doc comment for why (a prior version
   * of this method took a `secret` argument and was an MFA-takeover hole).
   *
   * Requires a signed-in user (same `not_authenticated`/`access_denied`
   * conditions as `beginOtpEnroll()`). Throws `otp_enrollment_failed` when
   * the code doesn't match, or when `beginOtpEnroll()` was never called (or
   * its enrollment window lapsed).
   */
  confirmOtpEnroll(otp: string): Promise<void>;
  /**
   * Standalone, post-login list of every credential the signed-in user has
   * enrolled — passkeys + the OTP authenticator (#227,
   * `GET /catalog/me/credentials`; see `CredentialSummary`'s doc for why
   * only those 2 kinds — password/recovery-codes have their own dedicated
   * self-service verbs and never appear here). The "Manage sign-in methods"
   * screen's data source. Works in BOTH `redirect` and `headless` mode.
   * Only ever reflects the CALLER's own credentials — there is no
   * admin/other-user variant on this method; that stays on `catalog-api`'s
   * `/catalog/users/{id}/credentials/*` admin surface.
   *
   * Requires a signed-in user: throws `not_authenticated` if
   * `getAccessToken()` resolves to `null`. Throws `credentials_fetch_failed`
   * for anything else — see `../internal/credentialsSelfService.ts`.
   *
   * Uses `JummonAuthOptions.apiHost` (the API gateway host), NEVER
   * `issuerHost` — see that option's doc comment.
   */
  listCredentials(): Promise<CredentialListResult>;
  /**
   * Standalone, post-login removal of one enrolled PASSKEY (#228,
   * `DELETE /catalog/me/credentials/{id}`) — the counterpart to
   * `registerPasskey()` for taking a credential OUT of the account,
   * id-addressed via `CredentialSummary.id` (`listCredentials()`). Only a
   * `"passkey"`-kind `CredentialSummary` has an `id` at all — the `"otp"`
   * entry has none (see that type's doc); remove/replace OTP via
   * `POST /catalog/me/credentials/otp/reset` instead. Works in BOTH
   * `redirect` and `headless` mode.
   *
   * The server enforces two independent guards, surfaced as distinct typed
   * errors:
   *  - `last_factor_blocked` — removal would leave the account with no
   *    working sign-in method (`ME_CREDENTIAL_LAST_FACTOR`). Never retried;
   *    the UI's only correct move is prompting the user to enroll a
   *    replacement first.
   *  - `step_up_required` — enforced at the GATEWAY, not catalog-api (this
   *    route requires a fresh `acr=loa2` token, RFC 9470). `redirect` mode
   *    does NOT auto-retry — see `../internal/credentialsSelfService.ts`'s
   *    doc comment for the re-authenticate-then-retry recipe. `headless`
   *    mode (#5b) attempts an internal, best-effort headless re-auth +
   *    retry first — this error only reaches the caller when that attempt
   *    itself couldn't complete silently (see `HeadlessStepUp`'s doc
   *    comment, same file).
   *  - `credential_not_found` — the id is empty/malformed, or simply not
   *    one of the caller's own (`ME_CREDENTIAL_NOT_FOUND`, deliberately the
   *    SAME code for both — no IDOR oracle).
   *
   * Requires a signed-in user: throws `not_authenticated` if
   * `getAccessToken()` resolves to `null`. Throws `credential_removal_failed`
   * for anything else unclassified — see
   * `../internal/credentialsSelfService.ts`.
   *
   * Uses `JummonAuthOptions.apiHost` (the API gateway host), NEVER
   * `issuerHost` — see that option's doc comment.
   */
  removeCredential(credentialId: string): Promise<void>;
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
    setPassword: (password, confirmationPassword) =>
      setPasswordViaEngine(engine, options, password, confirmationPassword),
    beginOtpEnroll: () => beginOtpEnrollViaEngine(engine, options),
    confirmOtpEnroll: (otp) => confirmOtpEnrollViaEngine(engine, options, otp),
    listCredentials: () => listCredentialsViaEngine(engine, options),
    removeCredential: (credentialId) => removeCredentialViaEngine(engine, options, credentialId),
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

async function setPasswordViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
  password: string,
  confirmationPassword: string,
): Promise<void> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "setPassword() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return setPasswordSelfService(accessToken, password, confirmationPassword, {
    apiHost: options.apiHost ?? DEFAULT_API_HOST,
  });
}

async function beginOtpEnrollViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
): Promise<OtpEnrollmentChallenge> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "beginOtpEnroll() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return beginOtpEnrollment(accessToken, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function confirmOtpEnrollViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
  otp: string,
): Promise<void> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "confirmOtpEnroll() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return confirmOtpEnrollment(accessToken, otp, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function listCredentialsViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
): Promise<CredentialListResult> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "listCredentials() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return listCredentials(accessToken, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function removeCredentialViaEngine(
  engine: AuthEngine,
  options: JummonAuthOptions,
  credentialId: string,
): Promise<void> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      "removeCredential() requires a signed-in user — call it after getUser()/isAuthenticated() " +
        "confirms an active session.",
    );
  }
  return removeCredential(accessToken, credentialId, {
    apiHost: options.apiHost ?? DEFAULT_API_HOST,
    headlessStepUp: buildHeadlessStepUp(engine, options),
  });
}

/**
 * #5b — `undefined` in `redirect` mode (or for any future `AuthEngine` that
 * doesn't implement `HeadlessSessionSink`): `removeCredential()` then falls
 * back to its pre-#5b behavior exactly (throw `step_up_required`, caller
 * re-authenticates via `signIn({ extraQueryParams: { acr_values } })`).
 * Constructs a FRESH `HeadlessAuthFlow` (`createHeadlessAuthFlow`) per call
 * rather than reusing `startAuthFlow()`'s flow — this is an internal,
 * caller-invisible re-auth attempt, not something the app's own in-progress
 * login flow (if any) should observe or have its state mutated by.
 */
function buildHeadlessStepUp(engine: AuthEngine, options: JummonAuthOptions): HeadlessStepUp | undefined {
  if (options.mode !== "headless" || !isHeadlessSessionSink(engine)) {
    return undefined;
  }
  const flow = createHeadlessAuthFlow(options, engine);
  return {
    start: (opts) => flow.start(opts),
    getAccessToken: () => engine.getAccessToken(),
  };
}

function isHeadlessSessionSink(engine: AuthEngine): engine is AuthEngine & HeadlessSessionSink {
  return typeof (engine as Partial<HeadlessSessionSink>).completeSignIn === "function";
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
