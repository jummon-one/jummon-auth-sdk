import type { PlatformStorage } from "./platform/types";

/**
 * Social-resume persistence (wire-contract-v1.md §7.3), storage-adapter-backed
 * — the platform-agnostic replacement for the pre-refactor
 * `flow/persistence.ts`, which read/wrote `window.sessionStorage` directly.
 *
 * A social-login kickoff is a full top-level navigation away from the
 * customer's origin — `HeadlessAuthFlowCore`'s instance fields
 * (`codeVerifier`, `snapshot`) don't survive that round trip. On web,
 * `sessionStorage` is scoped to (tab, origin) and *does* survive a full-page
 * navigation away and back to the same origin in the same tab; on React
 * Native there is no navigation-away/back round trip in the same sense (the
 * app process itself may be backgrounded or relaunched), but the same
 * "persist before handing off control, read back on return" shape still
 * applies via `AsyncStorage` — hence the async `PlatformStorage` interface
 * here instead of the old direct `Storage` access.
 */

/**
 * Prefix of the storage key this module persists flow-resume state under
 * (full key: `storageKey()` below). Exported for the same reason
 * `headlessEngineCore.ts` exports `HEADLESS_SESSION_STORAGE_PREFIX` — a
 * composite `PlatformStorage` that routes by key (e.g.
 * `@jummon/auth-react-native`'s AsyncStorage-vs-SecureStore split) needs a
 * stable prefix to match against instead of a duplicated literal.
 */
export const HEADLESS_FLOW_STORAGE_PREFIX = "jummon_headless_flow:";

export interface StoredHeadlessFlow {
  flowToken: string;
  codeVerifier: string;
  oidcState: string;
  tenant: string;
  clientId: string;
  redirectUri: string;
  issuerHost: string;
  savedAt: number;
  /**
   * `Date.now()` at the ORIGINAL `start()` call — distinct from `savedAt`
   * above, which is refreshed every time this record is re-persisted
   * (including right before a social-provider redirect, well after the
   * flow actually started). Restored by `resume()` so `client_signal.flow_ms`
   * (#85, risk-signal-collector) still measures elapsed-since-start
   * correctly across a social-redirect round trip, not elapsed-since-the-
   * last-persist.
   */
  flowStartedAt: number;
}

/** Namespaced per tenant+clientId so multiple flows on one origin don't collide. */
function storageKey(tenant: string, clientId: string): string {
  return `${HEADLESS_FLOW_STORAGE_PREFIX}${tenant}:${clientId}`;
}

/**
 * Best-effort — the underlying adapter can reject (private-browsing quota,
 * disabled storage, a genuinely failing `AsyncStorage` write). A failure here
 * must never block the auth flow itself, only degrade the social-resume/
 * app-relaunch recovery path.
 */
export async function persistFlow(storage: PlatformStorage, flow: StoredHeadlessFlow): Promise<void> {
  try {
    await storage.setItem(storageKey(flow.tenant, flow.clientId), JSON.stringify(flow));
  } catch {
    // best-effort, see doc comment above.
  }
}

export async function readStoredFlow(
  storage: PlatformStorage,
  tenant: string,
  clientId: string,
): Promise<StoredHeadlessFlow | null> {
  try {
    const raw = await storage.getItem(storageKey(tenant, clientId));
    if (!raw) {
      return null;
    }
    return JSON.parse(raw) as StoredHeadlessFlow;
  } catch {
    return null;
  }
}

/**
 * Fire-and-forget by design — `HeadlessAuthFlow.dispose()` is a synchronous
 * `void` method in the public interface (unchanged by this refactor), so it
 * cannot await the underlying adapter call. On the browser adapter this is
 * still effectively synchronous (a `Storage.removeItem` call has no internal
 * `await`, so it runs to completion before this function's returned Promise
 * is even observed); on an adapter with a genuinely async backing store
 * (RN's `AsyncStorage`), a `dispose()` call right before the app is torn
 * down races the write the same way any other best-effort cleanup does.
 */
export function clearStoredFlow(storage: PlatformStorage, tenant: string, clientId: string): void {
  void storage.removeItem(storageKey(tenant, clientId)).catch(() => {
    // best-effort, see doc comment above.
  });
}

/** Awaited variant of `clearStoredFlow`, used everywhere except `dispose()` (i.e. every call site that's already inside an `async` method and can afford to wait for the removal to actually land). */
export async function clearStoredFlowAsync(storage: PlatformStorage, tenant: string, clientId: string): Promise<void> {
  try {
    await storage.removeItem(storageKey(tenant, clientId));
  } catch {
    // best-effort, see doc comment above.
  }
}
