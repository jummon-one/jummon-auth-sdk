import { JummonAuthError } from "../errors";
import { decodeCredentialCreationOptions, encodeAttestationForWire } from "../flow/webauthn";
import type { PasskeyRegistrationResult } from "../types";

/**
 * Standalone, post-login passkey enrollment — `catalog-api`'s
 * `/catalog/me/credentials/passkeys/{begin,finish}` (self-service, no RBAC —
 * `catalog-api/internal/catalog/me/{handler,dto}.go`'s `RegisterPasskeyBegin`/
 * `RegisterPasskeyFinish`, whose doc comments literally name this SDK method
 * as the intended caller). This is deliberately a DIFFERENT surface from
 * `HeadlessAuthFlow.registerPasskey()` (`../flow/headlessAuthFlow.ts`), which
 * answers a `fido-registration` required-action step *inside* an in-progress
 * login (`/api/v1/auth/*`, bearer = flow_token). This one runs AFTER login is
 * already complete (bearer = the user's own access_token) and hits the API
 * gateway (`apiHost`), never the Auth API (`issuerHost`) — see
 * `JummonAuthOptions.apiHost`'s doc comment for why those two hosts are never
 * interchangeable.
 *
 * Reuses `webauthn.ts`'s codec unchanged: `RegisterPasskeyBeginResponse.options`
 * is base64url-outer-enveloped exactly like the in-login
 * `fido_registration_options`, and `RegisterPasskeyFinishRequest.attestation`
 * is the same `encodeAttestationForWire()` shape — no new wire format to
 * learn on either side.
 */

/** Default API gateway host — production. Mirrors `DEFAULT_ISSUER_HOST` in `../discovery.ts`; use `"api.jummon.dev"` for the dev environment (`shared/platform.md`'s "Client calls api.jummon.dev/<path>" convention). Never the same host as `issuerHost` — that one serves tenant-in-path OIDC discovery, not gateway-proxied catalog-api routes. */
export const DEFAULT_API_HOST = "api.jummon.com";

const PASSKEYS_BASE_PATH = "/catalog/me/credentials/passkeys";

export interface PasskeyEnrollmentOptions {
  apiHost: string;
}

interface RegisterPasskeyBeginResponseBody {
  ceremony_id: string;
  options: string;
}

interface RegisterPasskeyFinishResponseBody {
  credential_id: string;
  name: string;
}

/** `models.HTTPError` (`jummon-pkg/pkg/models/http_error.go`) — the generic error envelope every Go service in the platform returns, DISTINCT from the headless Auth API's own `{code,message,type}` (`../flow/types.ts`'s `HeadlessErrorEnvelope`). No `type` field here, so `mapHeadlessErrorCode` (`../errors.ts`) does not apply to this endpoint. */
interface CatalogHTTPErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * Feature-detects WebAuthn/passkey support in the CURRENT browser context —
 * the standalone-enrollment equivalent of `HeadlessFlowSnapshot.passkeyOriginOk`.
 * That flag is computed server-side, per tenant+client, only as a side effect
 * of a headless login `start()` call (`../flow/headlessAuthFlow.ts`); there is
 * no such call here, so this is a client-side capability check instead —
 * "is this origin/browser even able to attempt a ceremony" (secure context +
 * `PublicKeyCredential`/`navigator.credentials.create` present), not "has an
 * admin configured this tenant's `passwordless_config` RP". Exported so an
 * app can gate its "Enable passkey" nudge button before ever calling
 * `registerPasskey()`.
 */
export function isPasskeySupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof navigator !== "undefined" &&
    typeof navigator.credentials?.create === "function" &&
    typeof (window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential === "function"
  );
}

/**
 * Runs the full begin → `navigator.credentials.create()` → finish ceremony.
 * `accessToken` must already be a valid (non-expired) user access_token —
 * callers go through `JummonAuthClient.registerPasskey()` (`../client.ts`),
 * which resolves it via `engine.getAccessToken()` first.
 */
export async function enrollPasskey(
  accessToken: string,
  name: string | undefined,
  opts: PasskeyEnrollmentOptions,
): Promise<PasskeyRegistrationResult> {
  if (!isPasskeySupported()) {
    throw new JummonAuthError(
      "passkey_origin_unsupported",
      "WebAuthn isn't available in this browser/origin — registerPasskey() requires a secure context " +
        "(HTTPS) and platform support for navigator.credentials.create().",
    );
  }

  const begin = await request<RegisterPasskeyBeginResponseBody>(opts, "POST", "begin", accessToken);

  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey: decodeCredentialCreationOptions(begin.options),
    })) as PublicKeyCredential | null;
  } catch (err) {
    // Covers the user dismissing/cancelling the platform UI
    // (NotAllowedError) as well as any other WebAuthn-level rejection.
    throw passkeyFailedError(err);
  }
  if (!credential) {
    throw passkeyFailedError();
  }

  const finish = await request<RegisterPasskeyFinishResponseBody>(opts, "POST", "finish", accessToken, {
    ceremony_id: begin.ceremony_id,
    attestation: encodeAttestationForWire(credential),
    name,
  });

  return { credentialId: finish.credential_id, name: finish.name };
}

async function request<T>(
  opts: PasskeyEnrollmentOptions,
  method: "GET" | "POST",
  action: "begin" | "finish",
  accessToken: string,
  body?: unknown,
): Promise<T> {
  const host = opts.apiHost.trim().replace(/\/+$/, "");
  const url = `https://${host}${PASSKEYS_BASE_PATH}/${action}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      // Bearer, not a cookie — same rationale as HeadlessTransport
      // (../flow/transport.ts): no shared cookie jar with this origin.
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 401) {
    throw new JummonAuthError(
      "not_authenticated",
      "The access token is missing, invalid, or expired — sign in again before registering a passkey.",
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (err) {
    throw new JummonAuthError("unknown", "Malformed response from the Jummon API gateway.", err);
  }

  if (!response.ok) {
    throw toRegistrationError(response.status, payload as CatalogHTTPErrorBody);
  }
  return payload as T;
}

/**
 * `/catalog/me/*`'s self-service routes wrap EVERY upstream (auth-engine S2S)
 * failure into one of three generic codes — `UPSTREAM_NOT_FOUND` (404, e.g.
 * the ceremony expired or was never started — `fido.CeremonyStore` is a
 * short-TTL Redis entry), `UPSTREAM_VALIDATION_FAILED` (400, e.g. the
 * attestation failed WebAuthn verification), or `UPSTREAM_REQUEST_FAILED`
 * (500) — see catalog-api's `wrap()`
 * (`internal/catalog/users/repository/repository.go`). None of these carry
 * the `AUTH-*` taxonomy `mapHeadlessErrorCode` (`../errors.ts`) knows about —
 * that table is specific to the login-flow headless Auth API's own error
 * envelope (`{code,message,type}`), a different wire than this one
 * (`models.HTTPError`, no `type`). So every catalog-api-side failure here
 * collapses to `passkey_failed` — the one actionable outcome for the caller
 * ("try again") is the same regardless of which of the three it was.
 */
function toRegistrationError(status: number, body: CatalogHTTPErrorBody): JummonAuthError {
  if (status === 403) {
    return new JummonAuthError("access_denied", body.message ?? "Not allowed to register a passkey.", body);
  }
  return passkeyFailedError(body);
}

function passkeyFailedError(cause?: unknown): JummonAuthError {
  return new JummonAuthError(
    "passkey_failed",
    "We couldn't register this passkey. Try again, or use another sign-in method.",
    cause,
  );
}
