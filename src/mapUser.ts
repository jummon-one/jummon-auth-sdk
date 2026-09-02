import type { User as OidcUser } from "oidc-client-ts";
import { decodeJwtPayload } from "./jwt";
import type { JummonUser } from "./types";

/**
 * Builds the public JummonUser from an oidc-client-ts User.
 *
 * Jummon's roles[]/permissions[] claims ride the access_token (a JWT) today
 * and are not guaranteed on the id_token profile — this reads whichever
 * claim set actually carries them, id_token profile first (already parsed
 * by oidc-client-ts) falling back to a local, unverified decode of the
 * access_token. See `shared/platform.md` — "Claims are flat today".
 */
export function mapOidcUser(oidcUser: OidcUser, tenant: string): JummonUser {
  const idClaims = (oidcUser.profile ?? {}) as Record<string, unknown>;
  const accessClaims = decodeJwtPayload(oidcUser.access_token) ?? {};

  return {
    sub: String(idClaims.sub ?? ""),
    email: asOptionalString(idClaims.email),
    emailVerified: asOptionalBoolean(idClaims.email_verified),
    name: asOptionalString(idClaims.name),
    tenant,
    roles: asStringArray(accessClaims.roles ?? idClaims.roles),
    permissions: asStringArray(accessClaims.permissions ?? idClaims.permissions),
    raw: { ...accessClaims, ...idClaims },
  };
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
