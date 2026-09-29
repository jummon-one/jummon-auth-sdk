import { JummonAuthError } from "../errors";
import type { RecoveryCodesGenerated } from "../types";

/**
 * Standalone, post-login backup recovery-code enrollment — `catalog-api`'s
 * `POST /catalog/me/credentials/recovery-codes/generate` and
 * `GET /catalog/me/credentials/recovery-codes/status` (self-service, no
 * RBAC, build #73 — `catalog-api/internal/catalog/me/{handler,dto}.go`'s
 * `GenerateRecoveryCodesSelf`/`RecoveryCodesSelfStatus`, mirroring
 * `RegisterOtpBegin`/`RegisterPasskeyBegin`'s role for their own credential
 * types). This is deliberately a DIFFERENT surface from
 * `HeadlessRecoveryFlow`'s journey-driven `recovery-codes-form` (mode=redeem
 * is a recovery FACTOR; mode=generate there fires automatically right after
 * a credential re-enrollment, no Recovery Grant either way but inside an
 * unauthenticated recovery execution) — this one runs AFTER login is
 * already complete (bearer = the user's own access_token) and hits the API
 * gateway (`apiHost`), never the Auth API (`issuerHost`) or dynamic-flows —
 * same `apiHost`/`issuerHost` split `../internal/passkeyEnrollment.ts`
 * documents.
 *
 * `generateRecoveryCodesSelf()` ALWAYS replaces the caller's whole set —
 * there is no "add codes" operation, mirroring the server-side
 * `recoverycodes.Usecase.GenerateSelfService` invariant ("never appends").
 * `getRecoveryCodesSelfStatus()` is a read, never exposes the codes
 * themselves — use it to render "you already have backup codes configured"
 * before the user opts into a (destructive) regenerate.
 */

const RECOVERY_CODES_BASE_PATH = "/catalog/me/credentials/recovery-codes";

export interface RecoveryCodesEnrollmentOptions {
  apiHost: string;
}

interface GenerateRecoveryCodesSelfResponseBody {
  codes: string[];
}

interface RecoveryCodesSelfStatusResponseBody {
  has_unredeemed_codes: boolean;
}

/** `models.HTTPError` — see `../internal/passkeyEnrollment.ts`'s identical doc comment on `CatalogHTTPErrorBody`; duplicated rather than shared so the two modules evolve independently. */
interface CatalogHTTPErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * Mints a fresh backup-code set for the CALLER'S OWN account, replacing
 * any previous set. `accessToken` must already be a valid (non-expired)
 * user access_token — callers go through
 * `JummonAuthClient.generateRecoveryCodes()` (`../client.ts`), which
 * resolves it via `engine.getAccessToken()` first.
 */
export async function generateRecoveryCodesSelf(
  accessToken: string,
  opts: RecoveryCodesEnrollmentOptions,
): Promise<RecoveryCodesGenerated> {
  const url = recoveryCodesUrl(opts, "generate");

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
      // Bearer, not a cookie — same rationale as HeadlessTransport
      // (../flow/transport.ts): no shared cookie jar with this origin.
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 401) {
    throw unauthenticatedError();
  }

  if (!response.ok) {
    throw await toRecoveryCodesError(response);
  }

  let payload: GenerateRecoveryCodesSelfResponseBody;
  try {
    payload = (await response.json()) as GenerateRecoveryCodesSelfResponseBody;
  } catch (err) {
    throw new JummonAuthError("unknown", "Malformed response from the Jummon API gateway.", err);
  }

  return { codes: payload.codes ?? [] };
}

/**
 * Reports whether the CALLER'S OWN account already has an unredeemed
 * backup-code set — never returns the codes themselves. `accessToken` has
 * the same requirement as `generateRecoveryCodesSelf()`.
 */
export async function getRecoveryCodesSelfStatus(
  accessToken: string,
  opts: RecoveryCodesEnrollmentOptions,
): Promise<boolean> {
  const url = recoveryCodesUrl(opts, "status");

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 401) {
    throw unauthenticatedError();
  }

  if (!response.ok) {
    throw await toRecoveryCodesError(response);
  }

  let payload: RecoveryCodesSelfStatusResponseBody;
  try {
    payload = (await response.json()) as RecoveryCodesSelfStatusResponseBody;
  } catch (err) {
    throw new JummonAuthError("unknown", "Malformed response from the Jummon API gateway.", err);
  }

  return Boolean(payload.has_unredeemed_codes);
}

function recoveryCodesUrl(opts: RecoveryCodesEnrollmentOptions, action: "generate" | "status"): string {
  const host = opts.apiHost.trim().replace(/\/+$/, "");
  return `https://${host}${RECOVERY_CODES_BASE_PATH}/${action}`;
}

function unauthenticatedError(): JummonAuthError {
  return new JummonAuthError(
    "not_authenticated",
    "The access token is missing, invalid, or expired — sign in again before managing recovery codes.",
  );
}

/**
 * `/catalog/me/*`'s self-service routes wrap upstream failures into a
 * generic `models.HTTPError` — same posture `../internal/otpEnrollment.ts`'s
 * `toOtpEnrollmentError` documents. Everything collapses to
 * `recovery_codes_failed` — there is no federation-guard case here (unlike
 * OTP/password), since a backup-code set is a bootstrap/recovery credential,
 * not a local-login-identity field.
 */
async function toRecoveryCodesError(response: Response): Promise<JummonAuthError> {
  let body: CatalogHTTPErrorBody = {};
  try {
    body = (await response.json()) as CatalogHTTPErrorBody;
  } catch {
    // Some error paths (e.g. a raw 5xx from an intermediary) may not
    // return JSON at all — fall through to the generic message below.
  }
  return new JummonAuthError(
    "recovery_codes_failed",
    body.message ?? "Could not manage recovery codes — try again.",
    body,
  );
}
