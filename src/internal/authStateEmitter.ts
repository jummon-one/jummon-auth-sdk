import type { AuthState } from "../types";

/**
 * Listener plumbing shared by every `AuthEngine` implementation — extracted
 * out of `RedirectEngine` so `HeadlessEngine` emits `AuthState` transitions
 * through the exact same pattern instead of duplicating a `Set` + emit loop
 * (`implementation-plan.md` §8 item 1).
 */
export class AuthStateEmitter {
  private readonly listeners = new Set<(state: AuthState) => void>();

  subscribe(cb: (state: AuthState) => void): () => void {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  }

  emit(state: AuthState): void {
    for (const listener of this.listeners) {
      listener(state);
    }
  }

  clear(): void {
    this.listeners.clear();
  }
}
