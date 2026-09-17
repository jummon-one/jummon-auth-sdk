export { createJummonAuth } from "./client";
export type { HeadlessJummonAuthClient, JummonAuthClient } from "./client";

export { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "./errors";
export type { ErrorClass, JummonAuthErrorCode } from "./errors";

export { buildAuthority, DEFAULT_ISSUER_HOST } from "./discovery";

export { DEFAULT_API_HOST, isPasskeySupported } from "./internal/passkeyEnrollment";

export type { HeadlessAuthFlow, HeadlessFlowSnapshot } from "./flow/headlessAuthFlow";
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
  SignInOptions,
  SignOutOptions,
} from "./types";
