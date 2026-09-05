import { describe, expect, it, vi } from "vitest";
import { createReactNativePlatformAdapters } from "./index";
import type { AsyncStorageLike, SecureStoreLike } from "./storage";
import type { ExpoCryptoLike } from "./crypto";
import type { LinkingLike } from "./navigation";
import type { ReactNativePasskeyLike } from "./webauthn";

function fakeAsyncStorage(): AsyncStorageLike {
  return { getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn() };
}
function fakeSecureStore(): SecureStoreLike {
  return { getItemAsync: vi.fn(), setItemAsync: vi.fn(), deleteItemAsync: vi.fn() };
}
function fakeExpoCrypto(): ExpoCryptoLike {
  return { getRandomBytesAsync: vi.fn(), digest: vi.fn() };
}
function fakeLinking(): LinkingLike {
  return { openURL: vi.fn(), getInitialURL: vi.fn().mockResolvedValue(null), addEventListener: vi.fn().mockReturnValue({ remove: vi.fn() }) };
}
function fakePasskey(): ReactNativePasskeyLike {
  return { isSupported: vi.fn(), create: vi.fn(), get: vi.fn() };
}

describe("createReactNativePlatformAdapters", () => {
  it("assembles all four adapters, with webauthn present when `passkey` is supplied", () => {
    const adapters = createReactNativePlatformAdapters({
      asyncStorage: fakeAsyncStorage(),
      secureStore: fakeSecureStore(),
      expoCrypto: fakeExpoCrypto(),
      linking: fakeLinking(),
      passkey: fakePasskey(),
    });

    expect(adapters.storage).toBeDefined();
    expect(adapters.crypto).toBeDefined();
    expect(adapters.navigation).toBeDefined();
    expect(adapters.webauthn).toBeDefined();
    expect(adapters.riskSignals).toBeDefined();
  });

  it("omits `webauthn` entirely when `passkey` is not supplied — degrades to passkey_failed/passkey_origin_unsupported per PlatformAdapters' own contract, never a crash", () => {
    const adapters = createReactNativePlatformAdapters({
      asyncStorage: fakeAsyncStorage(),
      secureStore: fakeSecureStore(),
      expoCrypto: fakeExpoCrypto(),
      linking: fakeLinking(),
    });

    expect(adapters.webauthn).toBeUndefined();
  });

  it("always provides `riskSignals` (never undefined) — it degrades per-field to null internally rather than needing to be omitted like webauthn", () => {
    const adapters = createReactNativePlatformAdapters({
      asyncStorage: fakeAsyncStorage(),
      secureStore: fakeSecureStore(),
      expoCrypto: fakeExpoCrypto(),
      linking: fakeLinking(),
    });

    expect(adapters.riskSignals).toBeDefined();
    expect(adapters.riskSignals?.getLanguage()).toBeNull();
  });

  it("wires supplied `riskSignals` deps through to the adapter", () => {
    const adapters = createReactNativePlatformAdapters({
      asyncStorage: fakeAsyncStorage(),
      secureStore: fakeSecureStore(),
      expoCrypto: fakeExpoCrypto(),
      linking: fakeLinking(),
      riskSignals: { getLanguage: () => "pt-BR" },
    });

    expect(adapters.riskSignals?.getLanguage()).toBe("pt-BR");
  });
});
