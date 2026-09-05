/**
 * `@jummon/auth-react-native` — React Native/Expo adapters for
 * `@jummon/auth`'s agnostic core (`@jummon/auth/core`), per
 * `engineering-team/initiatives/headless-embeddable-auth/
 * SDK-DEFINITIVE-REVIEW-SYNTHESIS-2026-09-05.md`'s blocker B2 and
 * `ROADMAP.md`'s "Phase 2 — React Native" section in the web package.
 *
 * This package is HEADLESS-ONLY by design — RN has no addressable URL bar
 * to redirect to a hosted login page and back, so
 * `createJummonAuthReactNative()` always builds a `HeadlessEngineCore`/
 * `HeadlessAuthFlowCore` pair (`@jummon/auth`'s `RedirectEngine`,
 * `oidc-client-ts`, and `platform/browser/*` are never imported here).
 *
 * Typical usage, with the SAME React binding the web package ships
 * (`@jummon/auth/react`, reworked to be platform-agnostic — see that
 * package's `useHeadlessAuthFlow()`):
 *
 * ```tsx
 * import AsyncStorage from "@react-native-async-storage/async-storage";
 * import * as SecureStore from "expo-secure-store";
 * import * as ExpoCrypto from "expo-crypto";
 * import { Linking } from "react-native";
 * import { Passkey } from "react-native-passkey";
 * import { createJummonAuthReactNative } from "@jummon/auth-react-native";
 * import { JummonAuthProvider, useHeadlessAuthFlow } from "@jummon/auth/react";
 *
 * const client = createJummonAuthReactNative(
 *   { tenant: "acme", clientId: "acme-app", redirectUri: "acme://auth/callback" },
 *   { asyncStorage: AsyncStorage, secureStore: SecureStore, expoCrypto: ExpoCrypto, linking: Linking, passkey: Passkey },
 * );
 *
 * function App() {
 *   return (
 *     <JummonAuthProvider client={client}>
 *       <LoginScreen />
 *     </JummonAuthProvider>
 *   );
 * }
 *
 * function LoginScreen() {
 *   const { snapshot, start, submitPassword } = useHeadlessAuthFlow();
 *   // ...render your own UI off `snapshot.status`
 * }
 * ```
 */
export {
  createJummonAuthReactNative,
  type JummonAuthReactNativeClient,
  type ReactNativeAuthOptions,
} from "./client";

export {
  createReactNativePlatformAdapters,
  type ReactNativePlatformDeps,
  createReactNativeStorage,
  type AsyncStorageLike,
  type SecureStoreLike,
  type SecureStorageLike,
  type ReactNativeStorageDeps,
  createReactNativeCrypto,
  type ExpoCryptoLike,
  createReactNativeNavigation,
  type LinkingLike,
  createReactNativeWebAuthn,
  type ReactNativePasskeyLike,
  type PasskeyCreateRequest,
  type PasskeyCreateResult,
  type PasskeyGetRequest,
  type PasskeyGetResult,
} from "./adapters";

// Re-exported for convenience — a caller building a login screen typically
// needs these alongside `createJummonAuthReactNative()`.
export type {
  HeadlessAuthFlow,
  HeadlessFlowSnapshot,
  JummonUser,
  OtpEnrollmentChallenge,
  PasskeyRegistrationResult,
} from "@jummon/auth/core";
export { JummonAuthError } from "@jummon/auth/core";
export type { JummonAuthErrorCode } from "@jummon/auth/core";
