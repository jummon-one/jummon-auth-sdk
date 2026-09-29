import { JummonAuthError } from "../errors";
import type { CredentialListResult, CredentialSummary } from "../types";

/**
 * Standalone, post-login credential lifecycle management — `catalog-api`'s
 * shipped `GET /catalog/me/credentials` (#227,
 * `internal/catalog/me/{handler,dto,domain,service}.go`'s `ListCredentials`)
 * and `DELETE /catalog/me/credentials/{id}` (#228, `RemoveCredential`),
 * self-service, same `/catalog/me/*` namespace `../internal/
 * passkeyEnrollment.ts` (`/passkeys/*`), `../internal/otpEnrollment.ts`
 * (`/otp/enroll/*`), and `../internal/passwordSelfService.ts` (`/password`)
 * already operate under — this module is the "list everything I've
 * enrolled, remove one" pair layered on top of those per-kind enrollment
 * endpoints, not a replacement for any of them. Runs AFTER login is already
 * complete (bearer = the user's own access_token) and hits the API gateway
 * (`apiHost`), never the Auth API (`issuerHost`) — same apiHost/issuerHost
 * split every other `/catalog/me/*` module in this SDK documents.
 *
 * ## removeCredential()'s step-up model — GATEWAY-enforced, not inline
 *
 * `RemoveCredential`'s own doc comment (`me/domain/domain.go`) is explicit:
 * "Step-up / fresh re-auth: enforced at the BORDER, not here — the gateway
 * route for DELETE /catalog/me/credentials/{id} carries required_acr +
 * required_acr_max_age_seconds ... so a stale/low-assurance token never
 * reaches this handler at all (border-only-auth)." Concretely, this route's
 * `gateway_route_configs` row (`jummon-scripts/gateway/catalog/
 * catalog_routes.sql`) sets `required_acr='loa2'`,
 * `required_acr_max_age_seconds=300` — a token whose `acr`/`auth_time`
 * doesn't satisfy that never reaches catalog-api; the GATEWAY itself
 * rejects it (`jummon-api-gateway/internal/auth/orchestrator.go`'s step 4d,
 * `authsecurity.MeetsLoaRequirement`) with:
 *
 *   HTTP 401, body `{"error":"unauthorized","code":"INSUFFICIENT_ASSURANCE_LEVEL","message":"..."}`
 *   header `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="loa2", max_age=300`
 *
 * (`jummon-api-gateway/internal/auth/decision.go`'s `WriteDenyResponse` +
 * `StepUpWWWAuthenticate`, RFC 9470 §5). There is NO inline WebAuthn
 * ceremony on this endpoint — that model (an ad hoc 428 + assertion posted
 * back to the DELETE body) does not exist server-side, and per the SDK
 * lifecycle security gate's adjudication should not: step-up enforcement
 * stays entirely at the gateway's already-proven `MeetsLoaRequirement` gate,
 * never a bespoke per-endpoint mechanism
 * (`initiatives/headless-embeddable-auth/SDK-LC-SECURITY-GATE.md`,
 * "Option B ... explicitly rejected"). `removeCredential()` below detects
 * this exact rejection and throws `step_up_required` with the parsed
 * challenge — see that function's doc comment for the redirect-mode retry
 * recipe, and `HeadlessStepUp` below (#5b) for the headless-mode one.
 *
 * // reconcile: `Access-Control-Expose-Headers` does not currently list
 * // `WWW-Authenticate` anywhere in jummon-api-gateway (grepped
 * // `internal/`) — a CROSS-ORIGIN caller (the normal case: a customer app
 * // on its own origin calling api.jummon.dev) gets `null` from
 * // `response.headers.get("WWW-Authenticate")` per the Fetch spec (it is
 * // not a CORS-safelisted response header). `parseStepUpChallenge()` below
 * // is defensive for when that's fixed / same-origin; until then this
 * // module falls back to `KNOWN_REMOVE_CREDENTIAL_STEP_UP`, the literal
 * // `required_acr`/`required_acr_max_age_seconds` values this ONE route is
 * // configured with today. Flag to the gateway owner if a future step-up
 * // route needs the header actually readable client-side.
 */

const CREDENTIALS_BASE_PATH = "/catalog/me/credentials";

/**
 * #5b — headless-mode step-up adapter, wired in by `../client.ts`'s
 * `removeCredentialViaEngine()` ONLY when `mode: "headless"` (`RedirectEngine`
 * has no equivalent — a redirect-mode caller still re-authenticates via
 * `signIn({ extraQueryParams: { acr_values } })`, a full-page nav that
 * cannot happen inside this function). Narrowly typed (not the full
 * `HeadlessAuthFlow` surface) so this module never needs to import anything
 * from `../core`/`../flow`. `start()` mirrors `HeadlessAuthFlowCore.start()`'s
 * `acr_values`/`max_age` option (#5b, `../core/headlessAuthFlowCore.ts`);
 * `getAccessToken()` mirrors `AuthEngine.getAccessToken()` — called AFTER a
 * `start()` that resolves to `authenticated` to pick up the freshly-minted,
 * hopefully-now-loa2 token.
 *
 * `removeCredential()` treats this ENTIRELY as best-effort: a genuinely
 * interactive re-auth (password/MFA — the common case, since this wire
 * carries no session cookie, `../flow/transport.ts`'s `credentials: "omit"`)
 * cannot be completed silently inside one call, so `start()` not reaching
 * `authenticated` (or throwing) falls straight through to the SAME
 * `step_up_required` this function always threw — the caller can still
 * drive `startAuthFlow()` itself and retry, exactly as before #5b. What this
 * closes is the case a plain `signIn()`-less re-auth CAN complete headlessly
 * (or a future silent step-up path), which had NO wire at all before #5b.
 */
export interface HeadlessStepUp {
  start(opts: { acrValues?: string; maxAge?: number }): Promise<{ status: string }>;
  getAccessToken(): Promise<string | null>;
}

export interface CredentialsSelfServiceOptions {
  apiHost: string;
  /** #5b, headless mode only — see `HeadlessStepUp`'s doc comment. `undefined` (redirect mode, or no engine wiring) preserves the exact pre-#5b `removeCredential()` behavior. */
  headlessStepUp?: HeadlessStepUp;
}

interface CredentialSummaryWire {
  id?: string;
  kind: string;
  name?: string;
  active: boolean;
  created_at?: string;
}

interface ListCredentialsResponseBody {
  credentials: CredentialSummaryWire[];
  partial_failures?: string[];
}

/** `models.HTTPError` (`jummon-pkg/pkg/models/http_error.go`) — same shape every other `/catalog/me/*` module in this SDK documents (`../internal/passkeyEnrollment.ts`'s `CatalogHTTPErrorBody`); duplicated here rather than shared so this module evolves independently. */
interface CatalogHTTPErrorBody {
  code?: string;
  error?: string;
  message?: string;
}

/**
 * RFC 9470 §5 step-up challenge, parsed off the gateway's
 * `WWW-Authenticate` header (or the known-route fallback — see this
 * module's doc comment) on an `INSUFFICIENT_ASSURANCE_LEVEL` 401.
 * `err.cause` on a `step_up_required` `JummonAuthError` is always exactly
 * this shape.
 */
export interface StepUpChallenge {
  /** The `acr_values` a fresh authentication must satisfy, e.g. `"loa2"`. Feed straight into `SignInOptions.extraQueryParams.acr_values` for a redirect-mode re-auth. */
  acrValues: string;
  /** The freshness window (seconds) `auth_time` must fall within, when the gateway sent one. `undefined` when the challenge carried no `max_age` (0/absent server-side means "no freshness requirement", only ACR level matters). */
  maxAgeSeconds?: number;
}

/** This route's (`DELETE /catalog/me/credentials/{id}`) configured `gateway_route_configs` row — `jummon-scripts/gateway/catalog/catalog_routes.sql`. Used ONLY when the `WWW-Authenticate` header isn't readable (see this module's doc comment's CORS note). */
const KNOWN_REMOVE_CREDENTIAL_STEP_UP: StepUpChallenge = { acrValues: "loa2", maxAgeSeconds: 300 };

/**
 * Lists every credential the signed-in user has enrolled (passkeys + the
 * OTP authenticator — see `CredentialSummary`'s doc for why only those two
 * kinds appear here) — the data source for a "Manage sign-in methods"
 * screen. `accessToken` must already be a valid (non-expired) user
 * access_token — callers go through `JummonAuthClient.listCredentials()`
 * (`../client.ts`), which resolves it via `engine.getAccessToken()` first.
 */
export async function listCredentials(
  accessToken: string,
  opts: CredentialsSelfServiceOptions,
): Promise<CredentialListResult> {
  const url = credentialsUrl(opts);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
      // Bearer, not a cookie — same rationale as HeadlessTransport
      // (../flow/transport.ts): no shared cookie jar with this origin.
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 401) {
    throw unauthenticatedError("list your credentials");
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (err) {
    throw new JummonAuthError("unknown", "Malformed response from the Jummon API gateway.", err);
  }

  if (!response.ok) {
    const body = payload as CatalogHTTPErrorBody;
    throw new JummonAuthError(
      "credentials_fetch_failed",
      body.message ?? "Could not load your enrolled sign-in methods. Try again in a moment.",
      body,
    );
  }

  const body = payload as ListCredentialsResponseBody;
  const credentials: CredentialSummary[] = (body.credentials ?? []).map((c) => ({
    id: c.id,
    type: c.kind,
    name: c.name,
    active: c.active,
    createdAt: c.created_at,
  }));
  return { credentials, partialFailures: body.partial_failures ?? [] };
}

/**
 * Removes one enrolled credential. `accessToken`/callers have the same
 * requirement as `listCredentials()`.
 *
 * Three outcomes, mapped to distinct typed errors (never collapsed into
 * each other):
 *  - `ME_CREDENTIAL_LAST_FACTOR` (`me/service/credentials.go`'s
 *    `strongFactorCount` guard) → `last_factor_blocked`, never retried.
 *  - `ME_CREDENTIAL_NOT_FOUND` (empty/malformed id, or not the caller's own
 *    — deliberately the SAME code for both, no IDOR oracle) →
 *    `credential_not_found`.
 *  - The gateway's OWN `INSUFFICIENT_ASSURANCE_LEVEL` 401 (this route
 *    requires a fresh `acr=loa2` token — see this module's doc comment) →
 *    `step_up_required`. **Redirect mode: not auto-retried** — completing a
 *    step-up means the user re-authenticates, which this function cannot
 *    silently do inside one call (a redirect-mode re-auth is a full-page
 *    navigation that tears down the current JS realm). Re-authenticate via
 *    the SDK's EXISTING auth surface (`signIn({ prompt: "login",
 *    extraQueryParams: { acr_values: challenge.acrValues } })`), then call
 *    `removeCredential()` again — the retry is the caller re-invoking this
 *    same idempotent function, not internal state this module tracks.
 *    **Headless mode: auto-retried when `opts.headlessStepUp` is wired**
 *    (`../client.ts`'s `removeCredentialViaEngine()`, always the case for
 *    `HeadlessJummonAuthClient`) — see `HeadlessStepUp`'s doc comment for
 *    exactly what "auto" means here (best-effort; a genuinely interactive
 *    re-auth still surfaces the SAME `step_up_required` the caller would
 *    have gotten pre-#5b).
 */
export async function removeCredential(
  accessToken: string,
  credentialId: string,
  opts: CredentialsSelfServiceOptions,
): Promise<void> {
  return removeCredentialAttempt(accessToken, credentialId, opts, /* allowHeadlessStepUpRetry */ true);
}

async function removeCredentialAttempt(
  accessToken: string,
  credentialId: string,
  opts: CredentialsSelfServiceOptions,
  allowHeadlessStepUpRetry: boolean,
): Promise<void> {
  const url = `${credentialsUrl(opts)}/${encodeURIComponent(credentialId)}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "DELETE",
      headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the Jummon API gateway.", err);
  }

  if (response.status === 204 || response.ok) {
    return;
  }

  let body: CatalogHTTPErrorBody = {};
  try {
    body = (await response.json()) as CatalogHTTPErrorBody;
  } catch {
    // Some error paths (e.g. a raw 5xx from an intermediary) may not
    // return JSON at all — fall through with an empty body.
  }

  if (response.status === 401 && body.code === "INSUFFICIENT_ASSURANCE_LEVEL") {
    const challenge = parseStepUpChallenge(response.headers.get("WWW-Authenticate")) ?? KNOWN_REMOVE_CREDENTIAL_STEP_UP;

    // #5b — headless mode only (`opts.headlessStepUp` set), and only once
    // per outer `removeCredential()` call (`allowHeadlessStepUpRetry`
    // guards against a retried DELETE hitting ANOTHER 401 and looping).
    // Entirely best-effort: `start()` not reaching `authenticated`, or any
    // throw along this path, falls straight through to the SAME
    // `step_up_required` below — never a different/unexpected error out of
    // this function.
    if (allowHeadlessStepUpRetry && opts.headlessStepUp) {
      try {
        const reauth = await opts.headlessStepUp.start({
          acrValues: challenge.acrValues,
          maxAge: challenge.maxAgeSeconds,
        });
        if (reauth.status === "authenticated") {
          const freshToken = await opts.headlessStepUp.getAccessToken();
          if (freshToken) {
            return removeCredentialAttempt(freshToken, credentialId, opts, /* allowHeadlessStepUpRetry */ false);
          }
        }
      } catch {
        // best-effort — fall through to the standard step_up_required below
        // so the caller gets the SAME clear, actionable error it always did,
        // never a different/unrelated one from this internal retry attempt.
      }
    }

    throw new JummonAuthError(
      "step_up_required",
      body.message || "This action requires you to re-authenticate before it can continue.",
      challenge,
    );
  }
  if (response.status === 401) {
    throw unauthenticatedError("remove a credential");
  }
  if (body.code === "ME_CREDENTIAL_LAST_FACTOR") {
    throw new JummonAuthError(
      "last_factor_blocked",
      body.message ??
        "This is your only remaining way to sign in — enroll another sign-in method before removing this one.",
      body,
    );
  }
  if (body.code === "ME_CREDENTIAL_NOT_FOUND") {
    throw new JummonAuthError(
      "credential_not_found",
      body.message ?? "This credential doesn't exist, or doesn't belong to your account.",
      body,
    );
  }
  throw new JummonAuthError("credential_removal_failed", body.message ?? "We couldn't remove this credential. Try again.", body);
}

/** Parses RFC 9470 §5's `Bearer error="insufficient_user_authentication", acr_values="<x>", max_age=<n>` — `null` when the header is absent/unreadable or carries no `acr_values` (see this module's doc comment's CORS note on why that's the common case today). */
function parseStepUpChallenge(header: string | null): StepUpChallenge | null {
  if (!header) {
    return null;
  }
  const acrMatch = /acr_values="([^"]*)"/.exec(header);
  if (!acrMatch || !acrMatch[1]) {
    return null;
  }
  const maxAgeMatch = /max_age=(\d+)/.exec(header);
  return { acrValues: acrMatch[1], maxAgeSeconds: maxAgeMatch ? Number(maxAgeMatch[1]) : undefined };
}

function unauthenticatedError(action: string): JummonAuthError {
  return new JummonAuthError(
    "not_authenticated",
    `The access token is missing, invalid, or expired — sign in again before you ${action}.`,
  );
}

function credentialsUrl(opts: CredentialsSelfServiceOptions): string {
  const host = opts.apiHost.trim().replace(/\/+$/, "");
  return `https://${host}${CREDENTIALS_BASE_PATH}`;
}
