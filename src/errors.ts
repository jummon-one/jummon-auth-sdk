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
  | "social_login_failed"
  | "cors_origin_rejected"
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
 * Maps the headless Auth API's public `{error.code}` (`jummon-auth-engine/
 * internal/apierror/codes.go`) to a stable SDK `JummonAuthErrorCode`.
 * Grounded in `design/ux-spec-wave1.md` §3's error/microcopy library.
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

export function mapHeadlessErrorCode(publicCode: string | null | undefined): JummonAuthErrorCode {
  if (!publicCode) {
    return "unknown";
  }
  return HEADLESS_PUBLIC_CODE_MAP[publicCode] ?? "unknown";
}
