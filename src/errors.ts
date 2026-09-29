/**
 * Typed errors. Every failure path the public API can throw resolves to a
 * JummonAuthError with a stable `code` — consumers should switch on `code`,
 * never on `message` (message text is free to change).
 */

export type JummonAuthErrorCode =
  | "invalid_options"
  | "ssr_unsupported"
  | "discovery_unreachable"
  | "invalid_redirect_uri"
  | "login_required"
  | "interaction_required"
  | "consent_required"
  | "access_denied"
  | "state_mismatch"
  | "callback_missing_params"
  | "not_authenticated"
  | "silent_renew_failed"
  | "signin_failed"
  | "signout_failed"
  | "engine_not_implemented"
  | "network_unreachable"
  // Headless mode (`mode: "headless"`, `HeadlessAuthFlow` — see
  // ../ROADMAP.md and engineering-team/initiatives/headless-embeddable-auth).
  | "headless_requires_flow"
  | "flow_not_started"
  | "flow_expired"
  | "invalid_credentials"
  | "invalid_mfa_code"
  | "rate_limited"
  | "passkey_failed"
  | "passkey_origin_unsupported"
  /** Standalone `JummonAuthClient.setPassword()` (`../internal/passwordSelfService.ts`) got a non-401/403 failure off `POST /catalog/me/credentials/password` — most commonly the tenant's password policy rejected it (catalog-api's own `INVALID_PASSWORD`). Distinct from `invalid_credentials` (that one is about a *login* attempt, not a self-service password change). */
  | "invalid_password"
  /** Standalone `JummonAuthClient.confirmOtpEnroll()` (`../internal/otpEnrollment.ts`) got a non-401/403 failure off `POST /catalog/me/credentials/otp/enroll/finish` — most commonly the submitted code didn't match the secret `beginOtpEnroll()` minted server-side, or `beginOtpEnroll()` was never called (or its window lapsed) so there is no pending enrollment to confirm (catalog-api collapses the upstream `jummon-user-management` confirm failure into a generic wrap; the right UX is always "check the code and try again", same posture as `passkey_failed`). */
  | "otp_enrollment_failed"
  /** Standalone `JummonAuthClient.listCredentials()` (`../internal/credentialsSelfService.ts`) got a non-401 failure off `GET /catalog/me/credentials` — the read equivalent of `passkey_failed`/`otp_enrollment_failed`'s "collapse everything unclassified" posture; there is nothing actionable to distinguish here beyond "try again". */
  | "credentials_fetch_failed"
  /**
   * Standalone `JummonAuthClient.removeCredential()`
   * (`../internal/credentialsSelfService.ts`) got catalog-api's
   * `ME_CREDENTIAL_LAST_FACTOR` off `DELETE /catalog/me/credentials/{id}`
   * (`catalog-api/internal/catalog/me/service/credentials.go`'s
   * `strongFactorCount` guard — the account would be left with no working
   * login factor) — distinct from `access_denied` (which means "not
   * allowed", not "would lock you out"). Never retried automatically; the
   * UI's only correct move is telling the user to enroll a replacement
   * factor first.
   */
  | "last_factor_blocked"
  /** Standalone `JummonAuthClient.removeCredential()` got catalog-api's `ME_CREDENTIAL_NOT_FOUND` — the target id is empty, malformed, or simply not present in the caller's OWN credential list. Deliberately the SAME code for all three (no IDOR oracle — `credentials.go`'s own doc), so this SDK does not attempt to distinguish "not yours" from "doesn't exist" either. */
  | "credential_not_found"
  /**
   * Standalone `JummonAuthClient.removeCredential()` was rejected at the
   * **gateway**, before catalog-api ever ran, because the caller's token
   * doesn't meet the route's assurance requirement — RFC 9470 step-up
   * (`jummon-api-gateway/internal/auth/orchestrator.go`'s `MeetsLoaRequirement`
   * check, `DecisionDenyAssurance` = `"INSUFFICIENT_ASSURANCE_LEVEL"`, 401).
   * `err.cause` is a `StepUpChallenge` (`../internal/credentialsSelfService.ts`)
   * naming the `acrValues`/`maxAgeSeconds` a fresh authentication must
   * satisfy. In `redirect` mode this SDK does NOT auto-retry: satisfying a
   * step-up challenge requires a full-page OIDC redirect, which cannot be
   * silently completed inside one `removeCredential()` call — re-authenticate
   * (e.g. `signIn({ prompt: "login", extraQueryParams: { acr_values:
   * err.cause.acrValues } })`), then call `removeCredential()` again. In
   * `headless` mode (#5b) this error only surfaces when the internal
   * step-up retry itself couldn't complete silently (a genuinely
   * interactive re-auth is still needed) — see
   * `credentialsSelfService.ts`'s `HeadlessStepUp` doc comment.
   * Distinct from `passkey_failed` (an *enrollment* ceremony failure, not a
   * re-auth challenge) and from `last_factor_blocked` (a different guard —
   * this one, once satisfied, unblocks the SAME removal).
   */
  | "step_up_required"
  /** Standalone `JummonAuthClient.removeCredential()` got a non-401/`ME_CREDENTIAL_NOT_FOUND`/`ME_CREDENTIAL_LAST_FACTOR` failure off `DELETE /catalog/me/credentials/{id}` — same "one actionable outcome, try again" collapse `otp_enrollment_failed`/`passkey_failed` already document for their own endpoints. */
  | "credential_removal_failed"
  | "social_login_failed"
  | "cors_origin_rejected"
  /** Terminal `authenticated` envelope carried a `code`, but this JS realm lost `code_verifier` (e.g. a non-social reload mid-flow) — distinct from "no code at all" (`unknown`). Recovery: call `resume()`, or restart with `start()`. */
  | "pkce_verifier_lost"
  | "unknown";

/**
 * Backend's error taxonomy classification (`jummon-auth-engine/internal/
 * apierror/contract.go`'s `Type`, forwarded on the headless wire as
 * `HeadlessErrorEnvelope.type`, wire-contract-v1.md §4.3). Exists precisely
 * so this SDK doesn't need to enumerate every `codes.go` row — see
 * `mapByType` below.
 */
export type ErrorClass =
  | "configuration"
  | "authentication"
  | "authorization"
  | "temporary"
  | "expired"
  | "network"
  | "not_found"
  | "forbidden"
  | "unknown";

export class JummonAuthError extends Error {
  readonly code: JummonAuthErrorCode;
  readonly cause?: unknown;

  constructor(code: JummonAuthErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "JummonAuthError";
    this.code = code;
    this.cause = cause;
    Object.setPrototypeOf(this, JummonAuthError.prototype);
  }
}

/**
 * Normalizes anything oidc-client-ts (or the network layer) can throw into a
 * JummonAuthError. oidc-client-ts's ErrorResponse carries the OIDC `error`
 * query param as `.error` — that maps 1:1 to a handful of well-known codes;
 * everything else collapses to "unknown" with the original error preserved
 * as `cause` so callers can still log/inspect it.
 */
export function toJummonAuthError(err: unknown): JummonAuthError {
  if (err instanceof JummonAuthError) {
    return err;
  }

  const asRecord = err as { error?: string; message?: string } | undefined;
  const oidcErrorCode = asRecord?.error;

  switch (oidcErrorCode) {
    case "login_required":
      return new JummonAuthError("login_required", "The user must sign in again.", err);
    case "interaction_required":
      return new JummonAuthError(
        "interaction_required",
        "The user must complete an interactive step at the IdP.",
        err,
      );
    case "consent_required":
      return new JummonAuthError("consent_required", "The user must grant consent.", err);
    case "access_denied":
      return new JummonAuthError("access_denied", "The user or the IdP denied the request.", err);
    case "invalid_redirect_uri":
      return new JummonAuthError(
        "invalid_redirect_uri",
        "redirect_uri is not registered for this client_id in this tenant.",
        err,
      );
    default:
      break;
  }

  const message =
    asRecord?.message ?? (err instanceof Error ? err.message : "Unknown authentication error.");
  return new JummonAuthError("unknown", message, err);
}

/**
 * Family A — the Auth API's own local vocabulary (wire-contract-v1.md
 * §4.2), never touches auth-engine: snake_case, lowercase, not
 * `AUTH-*`-namespaced. Checked BEFORE the `AUTH-*` table (`HEADLESS_PUBLIC_CODE_MAP`)
 * — these codes already exist as valid `JummonAuthErrorCode` members
 * (`flow_expired`, `cors_origin_rejected`) but previously always collapsed
 * to "unknown" because `mapHeadlessErrorCode` only recognized `AUTH-*`-shaped
 * strings.
 */
const HEADLESS_LOCAL_CODE_MAP: Record<string, JummonAuthErrorCode> = {
  flow_token_missing: "flow_not_started",
  flow_expired: "flow_expired",
  cors_origin_rejected: "cors_origin_rejected",
};

/**
 * Family B — auth-engine's public codes (`AUTH-<CATEGORY>-<NNNN>`, sourced
 * from `jummon-auth-engine/internal/apierror/codes.go`'s `Map`), forwarded
 * verbatim onto the headless wire. Grounded in `design/ux-spec-wave1.md` §3's
 * error/microcopy library and wire-contract-v1.md §5. Deliberately NOT
 * exhaustive against `codes.go`'s ~150 rows — anything unmapped falls
 * through to `mapByType` (§4.3) instead of a bare "unknown".
 *
 * `INVALID_CREDENTIALS` (AUTH-AUTHN-2001) and `USER_NOT_FOUND`
 * (AUTH-AUTHN-2004) are deliberately collapsed to the same
 * `invalid_credentials` code — they are distinct public codes on the wire
 * today, and forwarding either verbatim is a username-enumeration leak
 * (security review MUST-FIX, `security-note.md` §3). The Auth API route is
 * expected to collapse these before they reach the wire too; this mapping
 * is defense-in-depth on the SDK side, not a substitute for that fix.
 */
const HEADLESS_PUBLIC_CODE_MAP: Record<string, JummonAuthErrorCode> = {
  "AUTH-AUTHN-2001": "invalid_credentials",
  "AUTH-AUTHN-2004": "invalid_credentials",
  "AUTH-AUTHN-2003": "invalid_mfa_code",
  "AUTH-LIM-5001": "rate_limited",
  "AUTH-EXP-4001": "flow_expired",
  "AUTH-EXP-4002": "flow_expired",
  "AUTH-EXP-4003": "flow_expired",
  "AUTH-AUTHN-2010": "passkey_failed",
  "AUTH-AUTHN-2011": "passkey_failed",
  "AUTH-AUTHN-2012": "passkey_failed",
  "AUTH-AUTHN-2216": "passkey_failed",
  "AUTH-AUTHN-2217": "passkey_failed",
  "AUTH-AUTHN-2300": "social_login_failed",
  "AUTH-AUTHN-2301": "social_login_failed",
  "AUTH-AUTHN-2303": "social_login_failed",
  "AUTH-AUTHN-2304": "social_login_failed",
};

/**
 * §4.3 fallback — used only when neither Family A nor Family B matches the
 * literal `code`. Sourced from the backend's `type` field (`ErrorClass`,
 * already computed server-side via `parseErrorEnvelope`), so every future
 * `codes.go` addition degrades safely without a coordinated SDK release.
 */
function mapByType(type: ErrorClass | undefined): JummonAuthErrorCode {
  switch (type) {
    case "authentication":
      return "invalid_credentials";
    case "authorization":
    case "forbidden":
      return "access_denied";
    case "expired":
      return "flow_expired";
    case "network":
      return "network_unreachable";
    default:
      return "unknown";
  }
}

/**
 * Maps the headless Auth API's `{code, type}` (wire-contract-v1.md §4) to a
 * stable SDK `JummonAuthErrorCode`. Checks Family A verbatim first, then the
 * Family B `AUTH-*` table, then falls back to the `type`-bucket classification
 * — never a bare "unknown" for a code the whitelist simply hasn't caught up
 * with yet.
 */
export function mapHeadlessErrorCode(
  publicCode: string | null | undefined,
  type?: ErrorClass,
): JummonAuthErrorCode {
  if (!publicCode) {
    return "unknown";
  }
  if (publicCode in HEADLESS_LOCAL_CODE_MAP) {
    return HEADLESS_LOCAL_CODE_MAP[publicCode] as JummonAuthErrorCode;
  }
  if (publicCode in HEADLESS_PUBLIC_CODE_MAP) {
    return HEADLESS_PUBLIC_CODE_MAP[publicCode] as JummonAuthErrorCode;
  }
  return mapByType(type);
}
