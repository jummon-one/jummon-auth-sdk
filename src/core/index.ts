/**
 * `@jummon/auth/core` — the platform-agnostic core, exported as its own
 * subpath so a future platform package (e.g. `@jummon/auth-react-native`,
 * Phase 2 — see `../../ROADMAP.md`'s "Phase 2: React Native" section) can
 * construct `HeadlessEngineCore`/`HeadlessAuthFlowCore` directly against its
 * own `PlatformAdapters`, without going through this package's browser-only
 * default wiring (`../engines/headlessEngine.ts`,
 * `../flow/headlessAuthFlow.ts`, `../platform/browser/*`) at all.
 *
 * Nothing exported here touches `window`/`document`/`navigator`/
 * `crypto.subtle`/`oidc-client-ts` — every such access lives behind the
 * `Platform*` interfaces below, resolved by whatever adapters the caller
 * constructs these classes with.
 *
 * This subpath is ADDITIVE — it does not change `@jummon/auth`'s main entry
 * (`.`) or `./react` in any way; the web `createJummonAuth()` path does not
 * import from here, it imports the core classes directly.
 */

export { HeadlessEngineCore, HEADLESS_SESSION_STORAGE_PREFIX } from "./headlessEngineCore";
export {
  HeadlessAuthFlowCore,
  type HeadlessAuthFlow,
  type HeadlessFlowSnapshot,
  type HeadlessSessionSink,
} from "./headlessAuthFlowCore";
export { HEADLESS_FLOW_STORAGE_PREFIX } from "./flowPersistence";

export type {
  PlatformAdapters,
  PlatformCrypto,
  PlatformNavigation,
  PlatformStorage,
  PlatformWebAuthn,
} from "./platform/types";
export { generateOpaqueId, generatePkcePair, type PkcePair } from "./platform/pkce";
export {
  buildDeviceConsentSubmit,
  buildTermsAgreementSubmit,
  type CreatePasswordStepData,
  type CreatePasswordSubmit,
  type DeviceConsentStepData,
  type DeviceConsentSubmit,
  type OtpConfigureSubmit,
  type TermsAgreementSubmit,
  type ValidatePhoneStepData,
  type ValidatePhoneSubmit,
  type VerifyEmailStepData,
  type VerifyEmailSubmit,
} from "../flow/stepPayloads";

// Pure fetch-based, platform-agnostic already (no `window`/DOM coupling) —
// see `../../ROADMAP.md`'s Phase 2 item 7. `setPasswordSelfService`/
// `beginOtpEnrollment`/`confirmOtpEnrollment` never touched a platform
// adapter to begin with. `enrollPasskey`/`isPasskeySupported` are re-exported
// as thin wrappers that make the `webauthn` argument REQUIRED (the underlying
// `../internal/passkeyEnrollment.ts` functions default it to the browser
// adapter for the web package's convenience) — a platform package importing
// from `@jummon/auth/core` must always supply its own `PlatformWebAuthn`
// explicitly, so this subpath never silently resolves to `navigator.credentials`.
import {
  enrollPasskey as enrollPasskeyWithDefault,
  isPasskeySupported as isPasskeySupportedWithDefault,
  DEFAULT_API_HOST,
  type PasskeyEnrollmentOptions,
} from "../internal/passkeyEnrollment";
import type { PlatformWebAuthn } from "./platform/types";
import type { PasskeyRegistrationResult } from "../types";

export { DEFAULT_API_HOST, type PasskeyEnrollmentOptions };

export function isPasskeySupported(webauthn: PlatformWebAuthn): boolean {
  return isPasskeySupportedWithDefault(webauthn);
}

export function enrollPasskey(
  accessToken: string,
  name: string | undefined,
  opts: PasskeyEnrollmentOptions,
  webauthn: PlatformWebAuthn,
): Promise<PasskeyRegistrationResult> {
  return enrollPasskeyWithDefault(accessToken, name, opts, webauthn);
}

export { setPasswordSelfService, type PasswordSelfServiceOptions } from "../internal/passwordSelfService";
export {
  beginOtpEnrollment,
  confirmOtpEnrollment,
  type OtpEnrollmentOptions,
} from "../internal/otpEnrollment";

// Re-exported so a platform package can build the same `JummonUser`/
// `AuthEngine` shapes and talk to the same wire without re-deriving them —
// these already ship in the main entry too; duplicated here for
// discoverability from a "just building a platform adapter" starting point.
export type {
  AuthEngine,
  AuthState,
  JummonAuthMode,
  JummonAuthOptions,
  JummonUser,
  OtpEnrollmentChallenge,
  PasskeyRegistrationResult,
  SignInOptions,
  SignOutOptions,
} from "../types";
export { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "../errors";
export type { ErrorClass, JummonAuthErrorCode } from "../errors";
export { buildAuthority, DEFAULT_ISSUER_HOST } from "../discovery";
export { buildJummonUser } from "../mapUser";
