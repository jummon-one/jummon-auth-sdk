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
  HeadlessStartRequestBody,
  HeadlessThemeConfig,
  HeadlessWireStatus,
  HeadlessWireStep,
  SocialLoginOption,
} from "./flow/types";

export type {
  AuthEngine,
  AuthState,
  JummonAuthMode,
  JummonAuthOptions,
  JummonUser,
  PasskeyRegistrationResult,
  SignInOptions,
  SignOutOptions,
} from "./types";
