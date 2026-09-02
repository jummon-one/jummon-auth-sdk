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
