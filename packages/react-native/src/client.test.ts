import { describe, expect, it, vi } from "vitest";
import { HEADLESS_SESSION_STORAGE_PREFIX } from "@jummon/auth/core";
import { createJummonAuthReactNative, type ReactNativeAuthOptions } from "./client";
import type { AsyncStorageLike, SecureStoreLike } from "./adapters/storage";
import type { ExpoCryptoLike } from "./adapters/crypto";
import type { LinkingLike } from "./adapters/navigation";
import type { ReactNativePasskeyLike } from "./adapters/webauthn";

const OPTIONS: ReactNativeAuthOptions = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "acme://auth/callback",
};

function fakeAsyncStorage(seed: Record<string, string> = {}): AsyncStorageLike {
  const store = new Map(Object.entries(seed));
  return {
    getItem: vi.fn(async (key) => store.get(key) ?? null),
    setItem: vi.fn(async (key, value) => void store.set(key, value)),
    removeItem: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeSecureStore(seed: Record<string, string> = {}): SecureStoreLike {
  const store = new Map(Object.entries(seed));
  return {
    getItemAsync: vi.fn(async (key) => store.get(key) ?? null),
    setItemAsync: vi.fn(async (key, value) => void store.set(key, value)),
    deleteItemAsync: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeExpoCrypto(): ExpoCryptoLike {
  return {
    getRandomBytesAsync: vi.fn(async (n: number) => new Uint8Array(n)),
    digest: vi.fn(async () => new Uint8Array(32).buffer),
  };
}
function fakeLinking(): LinkingLike {
  return {
    openURL: vi.fn(),
    getInitialURL: vi.fn().mockResolvedValue(null),
    addEventListener: vi.fn().mockReturnValue({ remove: vi.fn() }),
  };
}
function fakePasskey(): ReactNativePasskeyLike {
  return { isSupported: vi.fn().mockReturnValue(true), create: vi.fn(), get: vi.fn() };
}

function baseDeps(overrides: { secureStoreSeed?: Record<string, string>; passkey?: ReactNativePasskeyLike } = {}) {
  return {
    asyncStorage: fakeAsyncStorage(),
    secureStore: fakeSecureStore(overrides.secureStoreSeed),
    expoCrypto: fakeExpoCrypto(),
    linking: fakeLinking(),
    passkey: overrides.passkey,
  };
}

describe("createJummonAuthReactNative", () => {
  it("throws invalid_options when a required option is missing", () => {
    expect(() =>
      createJummonAuthReactNative({ tenant: "acme", clientId: "", redirectUri: "acme://cb" }, baseDeps()),
    ).toThrow(/missing required option/);
  });

  it("signIn()/signInCallback() throw headless_requires_flow — startAuthFlow() is the real entrypoint (RN is always headless)", async () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    await expect(client.signIn()).rejects.toMatchObject({ code: "headless_requires_flow" });
    await expect(client.signInCallback()).rejects.toMatchObject({ code: "headless_requires_flow" });
  });

  it("startAuthFlow() returns a fresh, idle HeadlessAuthFlow every call", () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    const flow1 = client.startAuthFlow();
    const flow2 = client.startAuthFlow();

    expect(flow1).not.toBe(flow2);
    expect(flow1.state.status).toBe("idle");
    expect(typeof flow1.start).toBe("function");
  });

  it("getUser()/isAuthenticated() reflect no session when storage is empty", async () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    expect(await client.getUser()).toBeNull();
    expect(await client.isAuthenticated()).toBe(false);
    expect(await client.getAccessToken()).toBeNull();
  });

  describe("standalone post-login methods", () => {
    it("registerPasskey() throws not_authenticated with no session, without ever touching the network", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps({ passkey: fakePasskey() }));

      await expect(client.registerPasskey()).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("setPassword() throws not_authenticated with no session", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());

      await expect(client.setPassword("a", "a")).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("beginOtpEnroll()/confirmOtpEnroll() throw not_authenticated with no session", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());

      await expect(client.beginOtpEnroll()).rejects.toMatchObject({ code: "not_authenticated" });
      await expect(client.confirmOtpEnroll("123456")).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("registerPasskey() throws passkey_origin_unsupported when authenticated but no `passkey` adapter was supplied", async () => {
      const sessionKey = `${HEADLESS_SESSION_STORAGE_PREFIX}${OPTIONS.tenant}.${OPTIONS.clientId}`;
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
      const secureStoreSeed = {
        [sessionKey]: JSON.stringify({ access_token: "at", token_type: "Bearer", expires_at: futureExpiry }),
      };
      const client = createJummonAuthReactNative(OPTIONS, baseDeps({ secureStoreSeed }));

      await expect(client.registerPasskey()).rejects.toMatchObject({ code: "passkey_origin_unsupported" });
    });
  });

  it("dispose() does not throw", () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());
    expect(() => client.dispose()).not.toThrow();
  });
});
