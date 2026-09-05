import { generateOpaqueId } from "./platform/pkce";
import type { PlatformCrypto, PlatformStorage } from "./platform/types";

/**
 * `client_signal.device_id` (initiative #85,
 * `engineering-team/initiatives/risk-signal-collector/README.md`) — a
 * first-party, per-`(tenant,client)`, opaque random identifier, persisted
 * via the injected `PlatformStorage` and rotated on `signOut()`
 * (`HeadlessEngineCore.signOut()`). Shared by both `HeadlessEngineCore`
 * (which rotates it) and `HeadlessAuthFlowCore` (which reads it into the
 * risk-signals payload) — neither holds the value in its own instance
 * state, both go through this module so there is exactly one source of
 * truth regardless of how many `HeadlessAuthFlowCore` instances a caller
 * creates against the same underlying storage.
 *
 * Explicitly NOT a cross-tenant-stable identifier (the spec's own ban) —
 * the storage key is namespaced by tenant+clientId, same pattern
 * `headlessEngineCore.ts`'s own session key and `flowPersistence.ts`'s flow
 * key already use.
 */
export const DEVICE_ID_STORAGE_PREFIX = "jummon.headless.device_id.";

/** Byte length of the random device id — same size `generatePkcePair`'s `code_verifier` uses; ample entropy for an opaque, non-guessable identifier without being needlessly large on the wire. */
const DEVICE_ID_BYTES = 16;

function storageKey(tenant: string, clientId: string): string {
  return `${DEVICE_ID_STORAGE_PREFIX}${tenant}.${clientId}`;
}

/**
 * Returns the persisted device id for this `(tenant, clientId)`, minting
 * and persisting a fresh one on first use (or right after a rotation).
 * Best-effort persistence — a storage read/write failure never blocks the
 * caller (the risk-signal collector degrades to a fresh, unpersisted id for
 * that one request rather than failing the submit it's attached to).
 */
export async function getOrCreateDeviceId(
  storage: PlatformStorage,
  crypto: PlatformCrypto,
  tenant: string,
  clientId: string,
): Promise<string> {
  const key = storageKey(tenant, clientId);
  let existing: string | null = null;
  try {
    existing = await storage.getItem(key);
  } catch {
    // best-effort — fall through to minting a fresh one.
  }
  if (existing) {
    return existing;
  }
  const id = await generateOpaqueId(crypto, DEVICE_ID_BYTES);
  try {
    await storage.setItem(key, id);
  } catch {
    // best-effort — the minted id is still usable for this one request even
    // if it doesn't survive to the next.
  }
  return id;
}

/**
 * Rotates (clears) the device id for this `(tenant, clientId)` — the next
 * `getOrCreateDeviceId()` call mints a brand-new one. Called from
 * `HeadlessEngineCore.signOut()` unconditionally (even when there was no
 * active session), same best-effort posture as the rest of this module.
 */
export async function rotateDeviceId(storage: PlatformStorage, tenant: string, clientId: string): Promise<void> {
  try {
    await storage.removeItem(storageKey(tenant, clientId));
  } catch {
    // best-effort, see doc comment above.
  }
}
