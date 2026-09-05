/**
 * Wire types for the headless Auth API namespace
 * (`jummon-login-interface`'s `POST /api/v1/auth/:tenant/:clientId/{start,
 * submit}` and `GET /api/v1/auth/:tenant/:clientId/poll`).
 *
 * Frozen against
 * `engineering-team/initiatives/headless-embeddable-auth/design/wire-contract-v1.md`
 * — both `jummon-login-interface` (backend) and this SDK code against that
 * document. Any future field/status/code-taxonomy change bumps it to
 * `wire-contract-v2.md` through the same two-sided review; treat drift from
 * the shipped route as an integration bug to reconcile against that file,
 * never a silent SDK-side workaround.
 *
 * Two decisions the contract locks in:
 *  - `tenant`/`client_id` are never a JSON body field anywhere in this
 *    contract — both live in the URL path
 *    (`/api/v1/auth/:tenant/:clientId/*`) so the Auth API's CORS layer can
 *    resolve its per-client origin allowlist at *preflight* time (a
 *    cross-origin POST's `OPTIONS` preflight has no body) and so tenant
 *    resolution never depends on an unvalidated body field.
 *  - `code`/`oidc_state` are separate top-level fields on the `authenticated`
 *    envelope, present iff `status === "authenticated"` — never folded into
 *    a reused `state`/`status` key.
 */

import type { ErrorClass } from "../errors";

/**
 * Every field here is already the RESOLVED value — the backend merges a
 * per-CLIENT branding override on top of the tenant's own theme
 * (`initiatives/headless-embeddable-auth/design/per-client-whitelabel.md`
 * §3.1: `authentication_step_resolver.go`'s `ApplyClientThemeOverride`,
 * applied at the same `/auth/steps` emission site this SDK's `theme` field
 * already reads). A client with no override renders byte-for-byte the same
 * as today's tenant-only theme; a client with a partial override (e.g. only
 * `logo`/`client_name`) still inherits the tenant's colors/links
 * field-by-field. The SDK does no merging itself — `HeadlessAuthFlowImpl`
 * just surfaces whatever this object already resolved to, same as
 * `available_social_logins`/`passwordless_available`/`passkey_origin_ok`.
 */
export interface HeadlessThemeConfig {
  logo?: string;
  background_color?: string;
  background_img?: string;
  text_color?: string;
  primary_color?: string;
  customer_name?: string;
  client_name?: string;
  forgot_password_link?: string;
  terms_of_use_link?: string;
  /** Note the wire key is plural — `privacy_policies_link`, not `privacy_policy_link` (`models.go:84`). */
  privacy_policies_link?: string;
}

/**
 * The SDK's PUBLIC, consumer-facing state — a client-side DX layer, not a
 * wire type. Derived from `HeadlessWireStep.ref` (+ `data`) via
 * `deriveState()` (`./stepState.ts`); the wire itself only ever carries the
 * 4-value `HeadlessWireStatus` below (wire-contract-v1.md §3.2/§3.3).
 */
export type HeadlessFlowState =
  | "needs_credentials"
  | "needs_passkey_assertion"
  | "needs_password"
  | "needs_mfa"
  | "needs_mfa_configure"
  | "needs_social_redirect"
  | "needs_required_action"
  | "authenticated"
  | "error";

/** `current_step`'s ref-only projection — the backend must never spread the raw internal `AuthenticationStep` here (config JSON, check_session, validate_password, …). */
export interface HeadlessWireStep {
  /** == `AuthenticationStep.ComponentName` — e.g. "username-password-form", "otp-input-form", "otp-configure-form", "terms-agreement", "consent-form", "device-consent-form", "fido-registration". */
  ref: string;
  /** == `AuthenticationStep.Name` — human label, optional, non-authoritative. */
  name?: string;
}

export interface SocialLoginOption {
  id: string;
  /** Display label. */
  name: string;
  /** The value `startSocialLogin(provider)` submits as `social_login`. */
  alias: string;
  /** Vendor family, e.g. "google", "microsoft" — NOT necessarily unique per tenant. */
  type: string;
  enabled: boolean;
}

export type HeadlessWireStatus = "needs_input" | "needs_redirect" | "authenticated" | "unknown";

/**
 * The backend-authoritative success/step envelope (wire-contract-v1.md
 * §3.1). Every non-2xx response is a `HeadlessErrorEnvelope` instead — the
 * two shapes are structurally distinct, there is no shared `error` field.
 */
export interface HeadlessAuthEnvelope {
  flow_token: string;
  status: HeadlessWireStatus;
  /** Present iff `status === "needs_input"`. */
  current_step: HeadlessWireStep | null;
  /** Only present on `start()`. */
  theme?: HeadlessThemeConfig | null;
  /** Nullable: `null` when the tenant hasn't enabled passwordless at all. */
  passkey_origin_ok?: boolean | null;
  /** Top-level convenience copy of `data.available_social_logins`. */
  available_social_logins?: SocialLoginOption[];
  /** Top-level convenience copy of `data.passwordless_available`. */
  passwordless_available?: boolean;
  data: Record<string, unknown>;
  /** Present iff `status === "authenticated"` — the OIDC authorization code. */
  code?: string;
  /** Present iff `status === "authenticated"` — the OIDC `state` param round-tripped from `start()`. */
  oidc_state?: string;
  /** Present iff `status === "needs_redirect"` (mirrored into `data.redirect_url` too, kept for convenience). */
}

/**
 * Flat error envelope — every non-2xx headless response body (wire-contract-v1.md §4.1).
 * `flow_token` is absent only on pre-session-mint validation 400s (missing
 * tenantId/clientId, missing redirect_uri/code_challenge, client_id
 * mismatch); `type` is absent on the same pre-mint errors.
 */
export interface HeadlessErrorEnvelope {
  flow_token?: string;
  code: string;
  message: string;
  type?: ErrorClass;
}

export interface HeadlessStartRequestBody {
  redirect_uri: string;
  code_challenge: string;
  /** Optional, default "S256" server-side. */
  code_challenge_method?: "S256";
  /** Optional on the wire, but the SDK MUST always send it — needed for the social-resume CSRF check (`resume()`). */
  state?: string;
  nonce?: string;
  /** Singular, space-delimited OIDC scope string (RFC 6749 wire shape) — never `scopes: string[]`. Default "openid" server-side if omitted. */
  scope?: string;
}
