import { resolveStorage } from "../../internal/storage";
import type { JummonAuthOptions } from "../../types";
import type { PlatformStorage } from "../../core/platform/types";

/**
 * Browser `PlatformStorage` — wraps the existing synchronous
 * `window.localStorage`/`sessionStorage`/`MemoryStorage` resolution
 * (`../../internal/storage.ts`, unchanged) in the async shape the agnostic
 * core requires. No behavior change: an `async` method with no internal
 * `await` still runs its body — the actual `Storage.getItem`/`setItem`/
 * `removeItem` call — synchronously before the returned Promise is ever
 * observed by a caller.
 */
export function createBrowserStorage(kind: JummonAuthOptions["tokenStorage"]): PlatformStorage {
  const sync = resolveStorage(kind);
  return {
    async getItem(key: string): Promise<string | null> {
      return sync.getItem(key);
    },
    async setItem(key: string, value: string): Promise<void> {
      sync.setItem(key, value);
    },
    async removeItem(key: string): Promise<void> {
      sync.removeItem(key);
    },
  };
}
