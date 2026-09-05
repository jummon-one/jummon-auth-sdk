import {
  HEADLESS_FLOW_STORAGE_PREFIX,
  HEADLESS_SESSION_STORAGE_PREFIX,
  type PlatformStorage,
} from "@jummon/auth/core";

/**
 * Structural shape of `@react-native-async-storage/async-storage`'s default
 * export (the module's three methods this adapter actually calls) — defined
 * locally rather than imported from the real package so this package never
 * needs it as an actual dependency (only a documented peer, see
 * `../../package.json`'s `peerDependenciesMeta`). The RN app imports the real
 * module and passes it straight through:
 *
 * ```ts
 * import AsyncStorage from "@react-native-async-storage/async-storage";
 * createReactNativeStorage({ asyncStorage: AsyncStorage, secureStore });
 * ```
 */
export interface AsyncStorageLike {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

/**
 * Structural shape of `expo-secure-store`'s module-level functions
 * (`getItemAsync`/`setItemAsync`/`deleteItemAsync`) — the primary secure
 * backend this adapter targets on Expo. Same "define locally, never import
 * the real package" reasoning as `AsyncStorageLike`.
 */
export interface SecureStoreLike {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}

/**
 * Keychain fallback interface — for a bare-RN app (no Expo) using
 * `react-native-keychain` or an equivalent, wrapped by the app into this
 * `AsyncStorage`-shaped interface instead of `expo-secure-store`'s three
 * `*Async` verbs. `createReactNativeStorage` accepts either shape for
 * `secureStore` (see the union below) so neither backend is privileged.
 */
export type SecureStorageLike = SecureStoreLike | AsyncStorageLike;

function isSecureStoreLike(store: SecureStorageLike): store is SecureStoreLike {
  return typeof (store as Partial<SecureStoreLike>).getItemAsync === "function";
}

export interface ReactNativeStorageDeps {
  /** Backs `flowPersistence.ts`'s resume state (`HEADLESS_FLOW_STORAGE_PREFIX` keys) — short-lived, non-secret, safe in plain AsyncStorage. */
  asyncStorage: AsyncStorageLike;
  /** Backs `HeadlessEngineCore`'s session tokens (`HEADLESS_SESSION_STORAGE_PREFIX` keys) — long-lived credentials, MUST go through the platform keychain, never plain AsyncStorage. */
  secureStore: SecureStorageLike;
}

/**
 * Composite `PlatformStorage` that ROUTES by key prefix instead of exposing
 * two separate storages to the core — `PlatformAdapters` has one `storage`
 * field shared by `HeadlessEngineCore` (token session, prefix
 * `HEADLESS_SESSION_STORAGE_PREFIX`) and `HeadlessAuthFlowCore`'s
 * `flowPersistence.ts` (in-flight resume state, prefix
 * `HEADLESS_FLOW_STORAGE_PREFIX`). Matches the synthesis's explicit ask:
 * "AsyncStorage for non-secret flow state + expo-secure-store (with a
 * keychain fallback interface) for tokens" — every other key (there are
 * none today, but a future core addition might introduce one) falls back to
 * `asyncStorage` rather than silently landing in the secure store or being
 * dropped.
 */
export function createReactNativeStorage(deps: ReactNativeStorageDeps): PlatformStorage {
  const { asyncStorage, secureStore } = deps;
  const secure = isSecureStoreLike(secureStore)
    ? {
        getItem: (key: string) => secureStore.getItemAsync(key),
        setItem: (key: string, value: string) => secureStore.setItemAsync(key, value),
        removeItem: (key: string) => secureStore.deleteItemAsync(key),
      }
    : secureStore;

  const backendFor = (key: string): AsyncStorageLike =>
    key.startsWith(HEADLESS_SESSION_STORAGE_PREFIX) ? secure : asyncStorage;

  return {
    async getItem(key: string): Promise<string | null> {
      return backendFor(key).getItem(key);
    },
    async setItem(key: string, value: string): Promise<void> {
      return backendFor(key).setItem(key, value);
    },
    async removeItem(key: string): Promise<void> {
      return backendFor(key).removeItem(key);
    },
  };
}

// Re-exported so a caller building a custom routing rule doesn't need to
// import `@jummon/auth/core` a second time just for these two constants.
export { HEADLESS_FLOW_STORAGE_PREFIX, HEADLESS_SESSION_STORAGE_PREFIX };
