import type { JummonAuthOptions } from "../types";

/**
 * Storage resolution shared by every `AuthEngine` implementation
 * (`RedirectEngine`, `HeadlessEngine`) — extracted so both engines resolve
 * `tokenStorage` identically instead of each hand-rolling it
 * (`implementation-plan.md` §8 item 1).
 */
export function resolveStorage(kind: JummonAuthOptions["tokenStorage"]): Storage {
  if (kind === "local") {
    return window.localStorage;
  }
  if (kind === "memory") {
    return new MemoryStorage();
  }
  return window.sessionStorage;
}

/**
 * In-memory Storage shim for `tokenStorage: "memory"`. Trades "survives a
 * full-page reload" for "nothing to steal via XSS reading storage" — see
 * README "Security / token storage" for when to pick this over the
 * session-storage default (which oidc-client-ts itself defaults to, and
 * which every redirect-flow SPA SDK relies on to survive the navigation
 * away from and back to the app during signInCallback()).
 */
export class MemoryStorage implements Storage {
  private readonly data = new Map<string, string>();

  get length(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }

  getItem(key: string): string | null {
    return this.data.has(key) ? (this.data.get(key) as string) : null;
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}
