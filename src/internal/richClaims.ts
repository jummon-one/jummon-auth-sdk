import { fetchDiscoveryDocument } from "./tokenExchange";

/**
 * Shape of `POST /oidc/userinfo`'s relevant fields — the "rich claims"
 * source every other platform consumer already prefers over the JWT-only
 * decode (`catalog-api`'s `internal/platform/richclaims`, `cockpit-bff`'s
 * `richClaimsFetcher`, `jummon-b2b-ui`'s `useAuthz` dual-read — see
 * `shared/conventions.md` and issue #8's "claim-placement rework"). This is
 * the SDK-side leg of that migration: the prerequisite that lets #8 strip
 * `permissions[]` off the access-token JWT without breaking this SDK's
 * customers, because `permissions` survives on userinfo even after the
 * token itself is slimmed.
 */
export interface RichClaims {
  roles?: string[];
  permissions?: string[];
  /**
   * Identity provider / federation alias that authenticated this user
   * (e.g. "google-workspace"), auth-engine's `idp` claim (#261). Present on
   * a federated/SSO login, absent/empty on a local-credential login. Read
   * off `RichClaims` the same way `roles`/`permissions` are — see
   * `mapUser.ts`'s `buildJummonUser`.
   */
  idp?: string;
  [key: string]: unknown;
}

interface FetchRichClaimsArgs {
  tenant: string;
  issuerHost: string;
  /** The signed-in user's access_token, sent as the userinfo Bearer. */
  accessToken: string;
}

/**
 * Per-access_token cache of in-flight/settled userinfo fetches. A JWT string
 * is immutable for its own lifetime, so keying on the raw token value means:
 * every `getUser()`/`isAuthenticated()` call against the SAME token (the
 * common case — most calls happen between sign-in and the next silent
 * refresh) is served from cache instead of re-hitting the network, while a
 * fresh token from sign-in/refresh naturally gets its own entry. Unlike the
 * Go backends' equivalent caches (`richclaims.go`, `richclaims.go` in
 * cockpit-bff), which hash the token before using it as a cache key purely
 * as defense-in-depth against a key ending up in a shared/inspectable
 * store, this cache is a plain in-memory `Map` local to the page/tab that
 * is never logged, persisted, or serialized — hashing would add no
 * additional protection here.
 *
 * Only SUCCESSFUL fetches are cached. A failed fetch (discovery
 * unreachable, network error, non-2xx, malformed body) is deliberately NOT
 * pinned in the cache, so a transient userinfo outage self-heals on the
 * very next call instead of sticking every caller on the degraded
 * JWT-fallback path for the rest of the access token's lifetime.
 */
const cache = new Map<string, Promise<RichClaims | null>>();

/**
 * Fetches `permissions`/`roles` from the tenant's userinfo endpoint,
 * resolved off the OIDC discovery doc (`userinfo_endpoint` —
 * `tokenExchange.ts`'s `DiscoveryDocument`, NEVER hardcoded — see
 * `CLAUDE.md`'s "OIDC client" rule). Bearer-only, no client auth, no body,
 * matching every other platform consumer of this endpoint.
 *
 * NEVER throws/rejects — on ANY failure this resolves to `null`, which
 * every call site treats as "fall back to the JWT decode". The SDK must
 * never harder-fail a sign-in/getUser() call because the userinfo endpoint
 * hiccuped; the existing JWT-only read stays a fully-functional degraded
 * path (mirrors `revokeToken()`'s best-effort posture in `tokenExchange.ts`).
 */
export function fetchRichClaims(args: FetchRichClaimsArgs): Promise<RichClaims | null> {
  const cached = cache.get(args.accessToken);
  if (cached) {
    return cached;
  }

  const pending = fetchLive(args)
    .catch(() => null)
    .then((result) => {
      if (result === null) {
        // Don't pin a failure — let the next caller retry live.
        cache.delete(args.accessToken);
      }
      return result;
    });

  cache.set(args.accessToken, pending);
  return pending;
}

async function fetchLive(args: FetchRichClaimsArgs): Promise<RichClaims | null> {
  const discovery = await fetchDiscoveryDocument(args.tenant, args.issuerHost);
  const endpoint = discovery.userinfo_endpoint;
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    return null;
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { Authorization: `Bearer ${args.accessToken}` },
    credentials: "omit",
  });
  if (!response.ok) {
    return null;
  }

  const body: unknown = await response.json().catch(() => null);
  if (typeof body !== "object" || body === null) {
    return null;
  }
  return body as RichClaims;
}

/** Test-only escape hatch — clears the module-level cache between tests. */
export function __clearRichClaimsCacheForTests(): void {
  cache.clear();
}
