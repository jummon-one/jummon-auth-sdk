import { JummonAuthError } from "../errors";
import type { OtpEnrollmentChallenge } from "../types";

/**
 * Standalone, post-login TOTP (authenticator app) enrollment — `catalog-api`'s
 * `POST /catalog/me/credentials/otp/enroll/{begin,finish}` (self-service, no
 * RBAC — `catalog-api/internal/catalog/me/{handler,dto}.go`'s
 * `RegisterOtpBegin`/`RegisterOtpFinish`, whose doc comments literally name
 * this SDK's `enrollOtp()` as the intended caller, mirroring
 * `RegisterPasskeyBegin`/`Finish`'s role for WebAuthn). This is deliberately
 * a DIFFERENT surface from the in-login `otp-configure-form` required-action
 * step (`HeadlessFlowState`'s `needs_mfa_configure`, already handled by
 * `HeadlessAuthFlow.submitRequiredAction`/`stepState.ts` — nothing to add
 * there). This one runs AFTER login is already complete (bearer = the
 * user's own access_token) and hits the API gateway (`apiHost`), never the
 * Auth API (`issuerHost`) — same apiHost/issuerHost split
 * `../internal/passkeyEnrollment.ts` documents.
 *
 * Two-call ceremony, split into two exported functions (not a single
 * begin-then-navigator-API round trip like passkeys — there is no browser
 * API here, just a human reading a QR code and typing back a code, an
 * inherently async UI step the caller drives):
 *  - `beginOtpEnrollment()` — mints a secret + `otpauth://` provisioning URI
 *    (`RegisterOtpBeginResponse{otp_secret, otp_url}`), disclosed EXACTLY
 *    ONCE per call (a second `begin` mints a brand-new secret, invalidating
 *    the first — same "generate once" contract `otp_configure.go`'s OnGet
 *    documents server-side for the in-login step). `otp_secret` is for the
 *    caller's own QR / manual-entry display ONLY.
 *  - `confirmOtpEnrollment()` — submits `{otp}` (`RegisterOtpFinishRequest`).
 *    There is deliberately no secret in this request: jummon-user-management
 *    validates the code against the secret ITS OWN `begin` call minted and
 *    persisted server-side (short TTL), never a client-supplied one. A
 *    prior version of this contract also took a `secret` argument here and
 *    forwarded it as `otp_secret` — the server trusted it as validation
 *    authority with no binding to what `begin` actually minted, so any
 *    caller holding a valid access_token could confirm an attacker-chosen
 *    secret and silently replace a working OTP factor (MFA-takeover).
 *    Success is `204 No Content`; a missing/expired pending enrollment
 *    (never called `begin`, or its window lapsed) is rejected.
 */

const OTP_ENROLL_BASE_PATH = "/catalog/me/credentials/otp/enroll";

export interface OtpEnrollmentOptions {
  apiHost: string;
}

interface RegisterOtpBeginResponseBody {
  otp_secret: string;
  otp_url: string;
}

/** `models.HTTPError` (`jummon-pkg/pkg/models/http_error.go`) — see `../internal/passkeyEnrollment.ts`'s identical doc comment on `CatalogHTTPErrorBody`; duplicated rather than shared so the two modules evolve independently. */
interface CatalogHTTPErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * Starts the standalone TOTP enrollment ceremony. `accessToken` must
 * already be a valid (non-expired) user access_token — callers go through
 * `JummonAuthClient.beginOtpEnroll()` (`../client.ts`), which resolves it
 * via `engine.getAccessToken()` first.
 */
export async function beginOtpEnrollment(
  accessToken: string,
  opts: OtpEnrollmentOptions,
): Promise<OtpEnrollmentChallenge> {
  const url = otpEnrollUrl(opts, "begin");

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
    throw await toOtpEnrollmentError(response);
  }

  let payload: RegisterOtpBeginResponseBody;
  try {
    payload = (await response.json()) as RegisterOtpBeginResponseBody;
  } catch (err) {
    throw new JummonAuthError("unknown", "Malformed response from the Jummon API gateway.", err);
  }

  return { otpUrl: payload.otp_url, secret: payload.otp_secret };
}

/**
 * Finishes the ceremony `beginOtpEnrollment()` started. Submits ONLY the
 * code the user's authenticator app generated — there is no secret
 * parameter: the server validates against the secret it minted and
 * persisted at `beginOtpEnrollment()`, not one the client echoes back (see
 * this module's doc comment). `accessToken` has the same requirement as
 * `beginOtpEnrollment()`.
 */
export async function confirmOtpEnrollment(
  accessToken: string,
  otp: string,
  opts: OtpEnrollmentOptions,
): Promise<void> {
  const url = otpEnrollUrl(opts, "finish");

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ otp }),
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 204 || response.ok) {
    return;
  }

  if (response.status === 401) {
    throw unauthenticatedError();
  }

  throw await toOtpEnrollmentError(response);
}

function otpEnrollUrl(opts: OtpEnrollmentOptions, action: "begin" | "finish"): string {
  const host = opts.apiHost.trim().replace(/\/+$/, "");
  return `https://${host}${OTP_ENROLL_BASE_PATH}/${action}`;
}

function unauthenticatedError(): JummonAuthError {
  return new JummonAuthError(
    "not_authenticated",
    "The access token is missing, invalid, or expired — sign in again before enrolling OTP.",
  );
}

/**
 * `/catalog/me/*`'s self-service routes wrap upstream (jummon-user-management
 * S2S) failures into a generic `models.HTTPError` — same posture
 * `../internal/passkeyEnrollment.ts`'s `toRegistrationError` documents for
 * the passkey ceremony. `403` is the one distinguishable case
 * (`FEDERATED_OTP_SET_FORBIDDEN`); everything else (a bad/expired code on
 * finish, a malformed request, an upstream 5xx) collapses to
 * `otp_enrollment_failed` — the one actionable outcome ("check the code and
 * try again") is the same regardless of which it was.
 */
async function toOtpEnrollmentError(response: Response): Promise<JummonAuthError> {
  let body: CatalogHTTPErrorBody = {};
  try {
    body = (await response.json()) as CatalogHTTPErrorBody;
  } catch {
    // Some error paths (e.g. a raw 5xx from an intermediary) may not
    // return JSON at all — fall through to the generic message below.
  }
  if (response.status === 403) {
    return new JummonAuthError(
      "access_denied",
      body.message ?? "Not allowed to enroll OTP for this account (federated identity?).",
      body,
    );
  }
  return new JummonAuthError(
    "otp_enrollment_failed",
    body.message ?? "OTP enrollment failed — check the code and try again.",
    body,
  );
}
