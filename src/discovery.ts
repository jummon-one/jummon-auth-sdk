/**
 * Authority derivation — the ONLY place a Jummon host is assembled.
 *
 * Jummon's browser-facing OIDC surface is tenant-in-path:
 *   https://<issuerHost>/<tenant>/oidc/.well-known/openid-configuration
 * issuer = https://<issuerHost>/<tenant>/oidc
 *
 * oidc-client-ts resolves authorization_endpoint / token_endpoint / jwks_uri
 * / end_session_endpoint itself from this authority's discovery document at
 * runtime (never hardcoded here or anywhere downstream) — this file only
 * builds the `authority` (issuer) string oidc-client-ts starts from.
 *
 * `api.jummon.com` (the API gateway / data-plane host) is never valid here —
 * it does not serve tenant-in-path OIDC discovery.
 */

export const DEFAULT_ISSUER_HOST = "idm.jummon.com";

export function buildAuthority(tenant: string, issuerHost: string = DEFAULT_ISSUER_HOST): string {
  const cleanTenant = tenant.trim();
  const cleanHost = issuerHost.trim().replace(/\/+$/, "");
  return `https://${cleanHost}/${cleanTenant}/oidc`;
}
