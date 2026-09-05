import { describe, expect, it, vi } from "vitest";
import { getOrCreateDeviceId, rotateDeviceId, DEVICE_ID_STORAGE_PREFIX } from "./deviceId";
import type { PlatformCrypto, PlatformStorage } from "./platform/types";

function makeStorage(): PlatformStorage & { store: Map<string, string> } {
  const store = new Map<string, string>();
  return {
    store,
    getItem: vi.fn(async (key: string) => store.get(key) ?? null),
    setItem: vi.fn(async (key: string, value: string) => void store.set(key, value)),
    removeItem: vi.fn(async (key: string) => void store.delete(key)),
  };
}

/** Deterministic-but-distinct fake CSPRNG — increments a counter into the byte array so successive calls never collide. */
function makeCrypto(): PlatformCrypto {
  let counter = 0;
  return {
    randomBytes(length: number): Uint8Array {
      counter += 1;
      const bytes = new Uint8Array(length);
      bytes[0] = counter % 256;
      return bytes;
    },
    async sha256(data: Uint8Array): Promise<Uint8Array> {
      return data;
    },
  };
}

describe("getOrCreateDeviceId / rotateDeviceId (#85 risk-signal-collector)", () => {
  it("mints and persists a device id on first call, under a key namespaced by tenant+clientId", async () => {
    const storage = makeStorage();
    const crypto = makeCrypto();

    const id = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");

    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
    expect(storage.store.get(`${DEVICE_ID_STORAGE_PREFIX}acme.acme-app`)).toBe(id);
  });

  it("returns the SAME id on subsequent calls (stable within a session) instead of minting a new one every time", async () => {
    const storage = makeStorage();
    const crypto = makeCrypto();

    const first = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");
    const second = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");
    const third = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");

    expect(second).toBe(first);
    expect(third).toBe(first);
  });

  it("namespaces by (tenant, clientId) — different tenant/client pairs never share a device id", async () => {
    const storage = makeStorage();
    const crypto = makeCrypto();

    const idA = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");
    const idB = await getOrCreateDeviceId(storage, crypto, "acme", "other-app");
    const idC = await getOrCreateDeviceId(storage, crypto, "other-tenant", "acme-app");

    expect(idB).not.toBe(idA);
    expect(idC).not.toBe(idA);
  });

  it("rotateDeviceId() clears the stored id — the NEXT getOrCreateDeviceId() call mints a different one", async () => {
    const storage = makeStorage();
    const crypto = makeCrypto();

    const before = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");
    await rotateDeviceId(storage, "acme", "acme-app");
    expect(storage.store.has(`${DEVICE_ID_STORAGE_PREFIX}acme.acme-app`)).toBe(false);
    const after = await getOrCreateDeviceId(storage, crypto, "acme", "acme-app");

    expect(after).not.toBe(before);
  });

  it("is best-effort — a storage read failure still mints a usable id rather than throwing", async () => {
    const storage: PlatformStorage = {
      getItem: vi.fn().mockRejectedValue(new Error("storage unavailable")),
      setItem: vi.fn().mockRejectedValue(new Error("storage unavailable")),
      removeItem: vi.fn(),
    };
    const crypto = makeCrypto();

    await expect(getOrCreateDeviceId(storage, crypto, "acme", "acme-app")).resolves.toEqual(expect.any(String));
  });

  it("rotateDeviceId() is best-effort — a storage removal failure never throws", async () => {
    const storage: PlatformStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn().mockRejectedValue(new Error("storage unavailable")),
    };

    await expect(rotateDeviceId(storage, "acme", "acme-app")).resolves.toBeUndefined();
  });
});
