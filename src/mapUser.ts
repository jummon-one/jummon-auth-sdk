import type { User as OidcUser } from "oidc-client-ts";
import { decodeJwtPayload } from "./jwt";
import { fetchRichClaims, type RichClaims } from "./internal/richClaims";
import type { JummonUser } from "./types";

/**
 * Builds the public JummonUser from an oidc-client-ts User, PRIMARILY from
 * auth-engine's userinfo endpoint (`permissions`/`roles` survive there even
 * once the access-token JWT is slimmed — issue #8's "claim-placement
 * rework"), falling back to the local, unverified JWT decode only when
 * userinfo can't be reached. See `buildJummonUser`'s doc comment for the
 * exact claim-priority order and `internal/richClaims.ts` for the
 * never-throws/cached fetch. Async because of that network round trip —
 * called from the async user-load paths `RedirectEngine` already has
 * (`onUserLoaded`, `signInCallback()`, `getUser()`), never from a sync
 * getter.
 */
export async function mapOidcUser(oidcUser: OidcUser, tenant: string, issuerHost: string): Promise<JummonUser> {
  const idClaims = (oidcUser.profile ?? {}) as Record<string, unknown>;
  const accessClaims = decodeJwtPayload(oidcUser.access_token) ?? {};
  const richClaims = oidcUser.access_token
    ? await fetchRichClaims({ tenant, issuerHost, accessToken: oidcUser.access_token })
    : null;
  return buildJummonUser(idClaims, accessClaims, tenant, richClaims);
}

/**
 * Shared claim-merge logic behind every `JummonUser` this SDK produces,
 * regardless of which `AuthEngine` produced the underlying tokens —
 * `RedirectEngine` (via `mapOidcUser` above) and `HeadlessEngine` (direct
 * token exchange, `../internal/tokenExchange.ts`) both call this so the two
 * engines yield byte-identical `JummonUser` shapes
 * (`implementation-plan.md` §8 item 4).
 *
 * `richClaims` (optional 4th param, added for issue #8's SDK migration) is
 * auth-engine's userinfo response when the caller was able to fetch it —
 * `roles`/`permissions` prefer it over `accessClaims`/`idClaims` when
 * present, so this stays correct both before and after `permissions[]` is
 * eventually stripped from the access-token JWT. `undefined`/`null` (no
 * caller passed one, or the fetch failed — `fetchRichClaims()` never
 * throws, it resolves `null`) preserves the EXACT pre-migration behavior:
 * `accessClaims` first, then `idClaims`. This keeps `buildJummonUser`
 * itself synchronous and its public 3-arg call shape untouched — it is
 * exported from `@jummon/auth/core` (`core/index.ts`) as part of the
 * package's public API for platform adapters (e.g. a future
 * `@jummon/auth-react-native` HeadlessEngineCore caller) to build a
 * `JummonUser` straight off tokens they already hold.
 */
export function buildJummonUser(
  idClaims: Record<string, unknown>,
  accessClaims: Record<string, unknown>,
  tenant: string,
  richClaims?: RichClaims | null,
): JummonUser {
  return {
    sub: String(idClaims.sub ?? ""),
    email: asOptionalString(idClaims.email),
    emailVerified: asOptionalBoolean(idClaims.email_verified),
    name: asOptionalString(idClaims.name),
    tenant,
    roles: asStringArray(richClaims?.roles ?? accessClaims.roles ?? idClaims.roles),
    permissions: asStringArray(richClaims?.permissions ?? accessClaims.permissions ?? idClaims.permissions),
    raw: { ...accessClaims, ...idClaims, ...(richClaims ?? {}) },
  };
}

/**
 * Async counterpart of `buildJummonUser` for callers that hold raw
 * id/access claim sets rather than an `oidc-client-ts` `User` (i.e.
 * `HeadlessEngineCore.getUser()`, which decodes its own persisted session
 * JWTs — see `core/headlessEngineCore.ts`). Fetches userinfo the same way
 * `mapOidcUser` does; resolves to the identical fallback shape when
 * `accessToken` is absent or the fetch fails.
 */
export async function buildJummonUserAsync(
  idClaims: Record<string, unknown>,
  accessClaims: Record<string, unknown>,
  tenant: string,
  issuerHost: string,
  accessToken: string | undefined,
): Promise<JummonUser> {
  const richClaims = accessToken ? await fetchRichClaims({ tenant, issuerHost, accessToken }) : null;
  return buildJummonUser(idClaims, accessClaims, tenant, richClaims);
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string");
}

function asOptionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asOptionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}
