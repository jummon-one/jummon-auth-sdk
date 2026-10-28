export { createJummonAuth } from "./client";
export type { HeadlessJummonAuthClient, JummonAuthClient } from "./client";

export { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "./errors";
export type { ErrorClass, JummonAuthErrorCode } from "./errors";

export { buildAuthority, DEFAULT_ISSUER_HOST } from "./discovery";

export { DEFAULT_API_HOST, isPasskeySupported } from "./internal/passkeyEnrollment";

export type { HeadlessAuthFlow, HeadlessFlowSnapshot, HeadlessStartOptions } from "./flow/headlessAuthFlow";

// Credential-type-aware account recovery (issue #163/#165). Wired into
// `HeadlessJummonAuthClient.startRecoveryFlow()` (`./client.ts`) — the
// standalone `createHeadlessRecoveryFlow` export below remains available
// for a caller with no `createJummonAuth()` client at all (e.g. an
// unauthenticated recovery-link landing page); see
// `headlessRecoveryFlowCore.ts`'s doc comment for the full step-driving API
// and threat-model posture (PKCE device-binding, in-memory-only token).
export { createHeadlessRecoveryFlow } from "./flow/headlessRecoveryFlow";
export type {
  HeadlessRecoveryFlow,
  HeadlessRecoveryFlowOptions,
  HeadlessRecoveryFlowSnapshot,
  HeadlessRecoveryStartOptions,
} from "./flow/headlessRecoveryFlow";
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
  CredentialListResult,
  CredentialSummary,
  JummonAuthMode,
  JummonAuthOptions,
  JummonUser,
  OtpEnrollmentChallenge,
  PasskeyRegistrationResult,
  RecoveryCodesGenerated,
  SignInOptions,
  SignOutOptions,
} from "./types";

// #228 — the RFC 9470 step-up challenge carried as `err.cause` on a
// `step_up_required` JummonAuthError off `removeCredential()`.
export type { StepUpChallenge } from "./internal/credentialsSelfService";
