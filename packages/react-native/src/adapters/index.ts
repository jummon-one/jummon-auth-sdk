import type { PlatformAdapters } from "@jummon/auth/core";
import { createReactNativeStorage, type ReactNativeStorageDeps } from "./storage";
import { createReactNativeCrypto, type ExpoCryptoLike } from "./crypto";
import { createReactNativeNavigation, type LinkingLike } from "./navigation";
import { createReactNativeWebAuthn, type ReactNativePasskeyLike } from "./webauthn";
import { createReactNativeRiskSignals, type RiskSignalsNativeDeps } from "./riskSignals";

export interface ReactNativePlatformDeps extends ReactNativeStorageDeps {
  expoCrypto: ExpoCryptoLike;
  linking: LinkingLike;
  /** Omit if the app has no passkey story yet — mirrors `PlatformAdapters.webauthn`'s own optionality (`@jummon/auth/core`). */
  passkey?: ReactNativePasskeyLike;
  /** Omit for the built-in `Intl`-only fallback (timezone only, no lang/device_class) — see `createReactNativeRiskSignals()`'s doc comment. Only read at all when the app also passes `collectRiskSignals: true` to `createJummonAuthReactNative()`. */
  riskSignals?: RiskSignalsNativeDeps;
}

/**
 * Assembles the full `PlatformAdapters` bag from the four RN-native
 * dependencies the consuming app wires in — the RN analogue of
 * `@jummon/auth`'s `createBrowserPlatformAdapters()`
 * (`../platform/browser/index.ts`), except every native module is supplied
 * by the caller (constructor injection) instead of read off a global,
 * because none of `AsyncStorage`/`SecureStore`/`expo-crypto`/`Linking`/
 * `react-native-passkey` is a global in the RN JS runtime the way
 * `window`/`navigator`/`crypto` are in a browser.
 */
export function createReactNativePlatformAdapters(deps: ReactNativePlatformDeps): PlatformAdapters {
  return {
    storage: createReactNativeStorage(deps),
    crypto: createReactNativeCrypto(deps.expoCrypto),
    navigation: createReactNativeNavigation(deps.linking),
    webauthn: deps.passkey ? createReactNativeWebAuthn(deps.passkey) : undefined,
    riskSignals: createReactNativeRiskSignals(deps.riskSignals),
  };
}

export {
  createReactNativeStorage,
  type AsyncStorageLike,
  type SecureStoreLike,
  type SecureStorageLike,
  type ReactNativeStorageDeps,
} from "./storage";
export { createReactNativeCrypto, type ExpoCryptoLike } from "./crypto";
export { createReactNativeNavigation, type LinkingLike } from "./navigation";
export {
  createReactNativeWebAuthn,
  type ReactNativePasskeyLike,
  type PasskeyCreateRequest,
  type PasskeyCreateResult,
  type PasskeyGetRequest,
  type PasskeyGetResult,
} from "./webauthn";
export { createReactNativeRiskSignals, type RiskSignalsNativeDeps } from "./riskSignals";
