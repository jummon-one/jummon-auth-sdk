/**
 * Wire types for the headless Auth API namespace
 * (`jummon-login-interface`'s `POST /api/v1/auth/:tenant/:clientId/{start,
 * submit}` and `GET /api/v1/auth/:tenant/:clientId/poll`).
 *
 * `system-design.md` §3.3 states this envelope is "illustrative, not
 * frozen," and `implementation-plan.md` §11 open question 5 explicitly
 * leaves the literal field names for back-end + SDK to agree in one
 * sitting. This SDK codes against the contract below; treat drift from the
 * shipped route as an integration bug to reconcile against this file, not a
 * silent SDK-side workaround.
 *
 * Two decisions made here resolve ambiguity the design docs left open,
 * both driven by the security review of `implementation-plan.md`:
 *  - `tenant`/`client_id` are never a JSON body field anywhere in this
 *    contract — both live in the URL path
 *    (`/api/v1/auth/:tenant/:clientId/*`) so the Auth API's CORS layer can
 *    resolve its per-client origin allowlist at *preflight* time (a
 *    cross-origin POST's `OPTIONS` preflight has no body — MUST-FIX 5) and
 *    so tenant resolution never depends on an unvalidated body field
 *    (MUST-FIX 4, the `proxyHeaders.ts` hardcoded-tenant-fallback risk).
 *  - `code`/`oidc_state` are separate top-level fields on the `authenticated`
 *    envelope, not a reused `state` key. `implementation-plan.md` §7 item 4
 *    literally writes `{state: "authenticated", code, state}`, which
 *    collides the flow-machine `state` with the OIDC `state` param in the
 *    same object — this SDK disambiguates; align the backend route to this
 *    shape rather than the plan's literal (ambiguous) example.
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

export type HeadlessFlowState =
  | "needs_credentials"
  | "needs_passkey_options"
  | "needs_passkey_assertion"
  | "needs_mfa"
  | "needs_mfa_configure"
  | "needs_social_redirect"
  | "needs_required_action"
  | "authenticated"
  | "error";

export interface HeadlessAuthEnvelope {
  flow_token: string;
  state: HeadlessFlowState;
  step_ref: string | null;
  /** Only present on `start` (`implementation-plan.md` §4 — `start` doubles as the branding fetch). */
  theme?: HeadlessThemeConfig | null;
  /** Nullable: `null` when the tenant hasn't enabled passwordless at all (`ux-spec-wave1.md` §4). */
  passkey_origin_ok?: boolean | null;
  data: Record<string, unknown>;
  error: { code: string; message: string } | null;
  /** Present only when `state === "authenticated"` — the OIDC authorization code. */
  code?: string;
  /** Present only when `state === "authenticated"` — the OIDC `state` param round-tripped from `start()`. */
  oidc_state?: string;
}

export interface HeadlessStartRequestBody {
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256";
  state: string;
  nonce: string;
  scopes: string[];
}
