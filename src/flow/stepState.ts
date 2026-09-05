import type { HeadlessFlowState, HeadlessWireStep } from "./types";

/**
 * Client-side derivation from the wire's ref-only `current_step` to the
 * SDK's richer public `HeadlessFlowSnapshot.status` (wire-contract-v1.md
 * §3.2/§3.3). The backend deliberately does NOT emit a granular per-step-type
 * enum on the wire — doing so would duplicate the tenant-authorable
 * step-flow system into a second, parallel enum that drifts the moment a
 * tenant adds a custom step. Mirrors `jummon-login-interface`'s own
 * `stepComponentMap.ts`/`services-auth.ts`'s `getStep()`, just executed in
 * the browser instead of on the server.
 */
const STEP_REF_TO_STATE: Record<string, HeadlessFlowState> = {
  "username-password-form": "needs_credentials",
  "otp-input-form": "needs_mfa",
  "otp-configure-form": "needs_mfa_configure",
  // jummon-auth-engine's create_password.go — served both for first-time
  // onboarding (REQUIRED_ACTION_CONFIGURE_PASSWORD) and recovery
  // (REQUIRED_ACTION_UPDATE_PASSWORD). `HeadlessAuthFlow.setPassword()`
  // answers this step.
  "create-password-form": "needs_password",
  "terms-agreement": "needs_required_action",
  "consent-form": "needs_required_action",
  "device-consent-form": "needs_required_action",
  "fido-registration": "needs_required_action",
};

/**
 * `status === "unknown"` (defensive backend fallback) and the terminal
 * `authenticated` status are handled by the caller before this is ever
 * invoked — this only derives the DX state for `status === "needs_input"`.
 */
export function deriveState(step: HeadlessWireStep | null, data: Record<string, unknown>): HeadlessFlowState {
  if (!step) {
    return "error";
  }
  // Two-phase passkey login shares ONE step ref (username-password-form) —
  // the assertion-required signal lives in `data`, not in a distinct ref
  // (mirrors HeadlessAuthFlowImpl.startPasskeyLogin's existing
  // data.fido_login_options check).
  if (step.ref === "username-password-form" && typeof data.fido_login_options === "string") {
    return "needs_passkey_assertion";
  }
  return STEP_REF_TO_STATE[step.ref] ?? "needs_required_action";
}
