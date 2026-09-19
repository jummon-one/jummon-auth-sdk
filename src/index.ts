export { createJummonAuth } from "./client";
export type { HeadlessJummonAuthClient, JummonAuthClient } from "./client";

export { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "./errors";
export type { ErrorClass, JummonAuthErrorCode } from "./errors";

export { buildAuthority, DEFAULT_ISSUER_HOST } from "./discovery";

export { DEFAULT_API_HOST, isPasskeySupported } from "./internal/passkeyEnrollment";

export type { HeadlessAuthFlow, HeadlessFlowSnapshot } from "./flow/headlessAuthFlow";

// Credential-type-aware account recovery (issue #163/#165). Exported
// directly (not yet wired into JummonAuthClient — see
// headlessRecoveryFlowCore.ts's doc comment for what's deferred to Wave 4),
// same posture createHeadlessAuthFlow had before client.ts integration.
export { createHeadlessRecoveryFlow } from "./flow/headlessRecoveryFlow";
export type { HeadlessRecoveryFlowOptions, HeadlessRecoveryFlowSnapshot } from "./flow/headlessRecoveryFlow";
export type {
  HeadlessAuthEnvelope,
  HeadlessErrorEnvelope,
  HeadlessFlowState,
  HeadlessLoginLayout,
  HeadlessLoginMethodLane,
  HeadlessLoginMethodPlacement,
  HeadlessLoginMethodRef,
  HeadlessStartRequestBody,
  HeadlessThemeConfig,
  HeadlessWireStatus,
  HeadlessWireStep,
  SocialLoginOption,
} from "./flow/types";

// ADR-0002 Wave 3 (#155) — the typed, lane-grouped projection of
// `data.login_layout` a consumer actually reads off
// `HeadlessFlowSnapshot.loginLayout`. See `./flow/loginLayout.ts`.
export { deriveLoginLayout } from "./flow/loginLayout";
export type { HeadlessLoginMethodDescriptor, HeadlessLoginMethodLayout } from "./flow/loginLayout";

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
} from "./flow/stepPayloads";

export type {
  AuthEngine,
  AuthState,
  JummonAuthMode,
  JummonAuthOptions,
  JummonUser,
  OtpEnrollmentChallenge,
  PasskeyRegistrationResult,
  RecoveryCodesGenerated,
  SignInOptions,
  SignOutOptions,
} from "./types";
