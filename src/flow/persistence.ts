/**
 * Social-resume persistence (wire-contract-v1.md §7.3). A social-login
 * kickoff is a full top-level navigation away from the customer's origin —
 * `HeadlessAuthFlowImpl`'s instance fields (`codeVerifier`, `snapshot`) don't
 * survive that round trip. `sessionStorage` is scoped to (tab, origin) and
 * *does* survive a full-page navigation away and back to the same origin in
 * the same tab — the same mechanism PKCE SPA libraries already rely on for
 * an OAuth redirect round trip, applied here to the headless flow-token
 * instead of a bare `code_verifier`.
 */

export interface StoredHeadlessFlow {
  flowToken: string;
  codeVerifier: string;
  oidcState: string;
  tenant: string;
  clientId: string;
  redirectUri: string;
  issuerHost: string;
  savedAt: number;
}

/** Namespaced per tenant+clientId so multiple flows on one origin don't collide. */
function storageKey(tenant: string, clientId: string): string {
  return `jummon_headless_flow:${tenant}:${clientId}`;
}

/**
 * Best-effort — `sessionStorage` can throw (private browsing quota,
 * disabled storage). A failure here must never block the auth flow itself,
 * only degrade the social-resume/tab-reload recovery path.
 */
export function persistFlow(flow: StoredHeadlessFlow): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.sessionStorage.setItem(storageKey(flow.tenant, flow.clientId), JSON.stringify(flow));
  } catch {
    // best-effort, see doc comment above.
  }
}

export function readStoredFlow(tenant: string, clientId: string): StoredHeadlessFlow | null {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const raw = window.sessionStorage.getItem(storageKey(tenant, clientId));
    if (!raw) {
      return null;
    }
    return JSON.parse(raw) as StoredHeadlessFlow;
  } catch {
    return null;
  }
}

export function clearStoredFlow(tenant: string, clientId: string): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.sessionStorage.removeItem(storageKey(tenant, clientId));
  } catch {
    // best-effort, see doc comment above.
  }
}

/**
 * `resume()` strips `code`/`state`/`auth_resume` from the visible URL/history
 * right after reading them — these are one-shot OIDC/social-hop markers and
 * must never linger in browser history or be re-processed on a later reload.
 */
export function stripAuthParamsFromUrl(): void {
  if (typeof window === "undefined" || typeof window.history?.replaceState !== "function") {
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
}
