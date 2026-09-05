import { JummonAuthError } from "../errors";

/**
 * Standalone, post-login "set my password" — `catalog-api`'s
 * `POST /catalog/me/credentials/password` (self-service, no RBAC —
 * `catalog-api/internal/catalog/me/{handler,dto}.go`'s `SetPassword`, which
 * delegates to the same `usersdomain.Service.SetPassword` the admin surface
 * (`POST /catalog/users/{id}/credentials/password`) uses — same
 * `FEDERATED_PASSWORD_SET_FORBIDDEN` guard applies here). This is
 * deliberately a DIFFERENT surface from `HeadlessAuthFlow.setPassword()`
 * (`../flow/headlessAuthFlow.ts`), which answers the `create-password-form`
 * required-action step *inside* an in-progress login (bearer =
 * flow_token). This one runs AFTER login is already complete (bearer = the
 * user's own access_token) and hits the API gateway (`apiHost`), never the
 * Auth API (`issuerHost`) — see `JummonAuthOptions.apiHost`'s doc comment
 * for why those two hosts are never interchangeable (mirrors
 * `../internal/passkeyEnrollment.ts`).
 *
 * Wire body: `{password, confirmation_password}` — matches catalog-api's
 * `usersdto.SetPasswordRequest` byte-for-byte (both fields `binding:
 * "required"`). Success is `204 No Content` — there is no response body to
 * decode, unlike the passkey begin/finish round trip.
 */

const PASSWORD_PATH = "/catalog/me/credentials/password";

export interface PasswordSelfServiceOptions {
  apiHost: string;
}

/**
 * `models.HTTPError` (`jummon-pkg/pkg/models/http_error.go`) — the generic
 * error envelope every Go service in the platform returns. Same shape
 * `../internal/passkeyEnrollment.ts`'s `CatalogHTTPErrorBody` documents;
 * duplicated here rather than shared so this module has no import-time
 * dependency on the passkey module (they evolve independently).
 */
interface CatalogHTTPErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * Runs the standalone self-service password set/change. `accessToken` must
 * already be a valid (non-expired) user access_token — callers go through
 * `JummonAuthClient.setPassword()` (`../client.ts`), which resolves it via
 * `engine.getAccessToken()` first.
 */
export async function setPasswordSelfService(
  accessToken: string,
  password: string,
  confirmationPassword: string,
  opts: PasswordSelfServiceOptions,
): Promise<void> {
  const host = opts.apiHost.trim().replace(/\/+$/, "");
  const url = `https://${host}${PASSWORD_PATH}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ password, confirmation_password: confirmationPassword }),
      // Bearer, not a cookie — same rationale as HeadlessTransport
      // (../flow/transport.ts): no shared cookie jar with this origin.
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 204 || response.ok) {
    return;
  }

  if (response.status === 401) {
    throw new JummonAuthError(
      "not_authenticated",
      "The access token is missing, invalid, or expired — sign in again before setting a password.",
    );
  }

  // Every failure path here (400 policy rejection, 403 federated guard, 5xx)
  // returns a JSON body — but tolerate a non-JSON/empty body defensively
  // rather than let a malformed error response mask the real status code.
  let payload: CatalogHTTPErrorBody = {};
  try {
    payload = (await response.json()) as CatalogHTTPErrorBody;
  } catch {
    // no-op — payload stays {}
  }

  throw toSetPasswordError(response.status, payload);
}

function toSetPasswordError(status: number, body: CatalogHTTPErrorBody): JummonAuthError {
  if (status === 403) {
    return new JummonAuthError(
      "access_denied",
      body.message ?? "Not allowed to set a password for this account (federated identity?).",
      body,
    );
  }
  return new JummonAuthError(
    "invalid_password",
    body.message ?? "The password could not be set — check it meets the tenant's password policy.",
    body,
  );
}
