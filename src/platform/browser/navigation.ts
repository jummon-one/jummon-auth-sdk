import type { PlatformNavigation } from "../../core/platform/types";

/**
 * Browser `PlatformNavigation` — `window.location`/`window.history`.
 * Byte-for-byte the same behavior as the pre-refactor direct calls in
 * `flow/headlessAuthFlow.ts` and `flow/persistence.ts`'s
 * `stripAuthParamsFromUrl()`.
 */
export const browserNavigation: PlatformNavigation = {
  redirect(url: string): void {
    window.location.assign(url);
  },

  getCurrentUrl(): string | null {
    return window.location.href;
  },

  /**
   * `resume()` strips `code`/`state`/`auth_resume` from the visible
   * URL/history right after reading them — these are one-shot OIDC/social-hop
   * markers and must never linger in browser history or be re-processed on a
   * later reload.
   */
  clearAuthParams(): void {
    if (typeof window.history?.replaceState !== "function") {
      return;
    }
    const url = new URL(window.location.href);
    let changed = false;
    for (const param of ["code", "state", "auth_resume"]) {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        changed = true;
      }
    }
    if (!changed) {
      return;
    }
    const query = url.searchParams.toString();
    const newUrl = `${url.pathname}${query ? `?${query}` : ""}${url.hash}`;
    window.history.replaceState(window.history.state, "", newUrl);
  },
};
