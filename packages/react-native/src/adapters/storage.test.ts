import { describe, expect, it, vi } from "vitest";
import { HEADLESS_FLOW_STORAGE_PREFIX, HEADLESS_SESSION_STORAGE_PREFIX } from "@jummon/auth/core";
import { createReactNativeStorage, type AsyncStorageLike, type SecureStoreLike } from "./storage";

function mockAsyncStorage(): AsyncStorageLike & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    getItem: vi.fn(async (key: string) => store.get(key) ?? null),
    setItem: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
    removeItem: vi.fn(async (key: string) => {
      store.delete(key);
    }),
  };
}

function mockSecureStore(): SecureStoreLike & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    getItemAsync: vi.fn(async (key: string) => store.get(key) ?? null),
    setItemAsync: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
    deleteItemAsync: vi.fn(async (key: string) => {
      store.delete(key);
    }),
  };
}

describe("createReactNativeStorage", () => {
  it("routes session-token keys (HEADLESS_SESSION_STORAGE_PREFIX) to the secure store, never AsyncStorage", async () => {
    const asyncStorage = mockAsyncStorage();
    const secureStore = mockSecureStore();
    const storage = createReactNativeStorage({ asyncStorage, secureStore });
    const key = `${HEADLESS_SESSION_STORAGE_PREFIX}acme.acme-app`;

    await storage.setItem(key, "token-payload");

    expect(secureStore.setItemAsync).toHaveBeenCalledWith(key, "token-payload");
    expect(asyncStorage.setItem).not.toHaveBeenCalled();
    expect(await storage.getItem(key)).toBe("token-payload");

    await storage.removeItem(key);
    expect(secureStore.deleteItemAsync).toHaveBeenCalledWith(key);
    expect(await storage.getItem(key)).toBeNull();
  });

  it("routes flow-resume keys (HEADLESS_FLOW_STORAGE_PREFIX) to AsyncStorage, never the secure store", async () => {
    const asyncStorage = mockAsyncStorage();
    const secureStore = mockSecureStore();
    const storage = createReactNativeStorage({ asyncStorage, secureStore });
    const key = `${HEADLESS_FLOW_STORAGE_PREFIX}acme:acme-app`;

    await storage.setItem(key, "flow-payload");

    expect(asyncStorage.setItem).toHaveBeenCalledWith(key, "flow-payload");
    expect(secureStore.setItemAsync).not.toHaveBeenCalled();
    expect(await storage.getItem(key)).toBe("flow-payload");
  });

  it("accepts an AsyncStorage-shaped keychain fallback for `secureStore` (bare-RN react-native-keychain shim)", async () => {
    const asyncStorage = mockAsyncStorage();
    const keychainShim = mockAsyncStorage(); // same {getItem,setItem,removeItem} shape as AsyncStorage
    const storage = createReactNativeStorage({ asyncStorage, secureStore: keychainShim });
    const key = `${HEADLESS_SESSION_STORAGE_PREFIX}acme.acme-app`;

    await storage.setItem(key, "token-payload");

    expect(keychainShim.setItem).toHaveBeenCalledWith(key, "token-payload");
    expect(asyncStorage.setItem).not.toHaveBeenCalled();
  });

  it("defaults an unrecognized key prefix to AsyncStorage, never the secure store", async () => {
    const asyncStorage = mockAsyncStorage();
    const secureStore = mockSecureStore();
    const storage = createReactNativeStorage({ asyncStorage, secureStore });

    await storage.setItem("some_other_key", "x");

    expect(asyncStorage.setItem).toHaveBeenCalledWith("some_other_key", "x");
    expect(secureStore.setItemAsync).not.toHaveBeenCalled();
  });
});
