import { buildAuthority } from "../discovery";
import { JummonAuthError, type JummonAuthErrorCode } from "../errors";

export interface DiscoveryDocument {
  issuer: string;
  token_endpoint: string;
  end_session_endpoint?: string;
  [key: string]: unknown;
}

const discoveryCache = new Map<string, Promise<DiscoveryDocument>>();

/**
 * `GET /<tenant>/oidc/.well-known/openid-configuration` — the only place
 * `HeadlessEngine`/`HeadlessAuthFlow` resolve an OIDC endpoint from. Never
 * hardcode `token_endpoint`/`end_session_endpoint` (`CLAUDE.md` "OIDC
 * client" rule). Cached per authority for the life of the page — mirrors
 * oidc-client-ts's own `MetadataService` caching so repeated silent
 * refreshes don't re-fetch the discovery doc every time.
 */
export function fetchDiscoveryDocument(tenant: string, issuerHost: string): Promise<DiscoveryDocument> {
  const authority = buildAuthority(tenant, issuerHost);
  const cached = discoveryCache.get(authority);
  if (cached) {
    return cached;
  }

  const promise = fetch(`${authority}/.well-known/openid-configuration`, { credentials: "omit" })
    .then((res) => {
      if (!res.ok) {
        throw new JummonAuthError(
          "discovery_unreachable",
          `Failed to fetch the OIDC discovery document for tenant "${tenant}" (HTTP ${res.status}).`,
        );
      }
      return res.json() as Promise<DiscoveryDocument>;
    })
    .catch((err: unknown) => {
      discoveryCache.delete(authority);
      throw err instanceof JummonAuthError
        ? err
        : new JummonAuthError("discovery_unreachable", "Could not reach the OIDC discovery document.", err);
    });

  discoveryCache.set(authority, promise);
  return promise;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

export interface ExchangeCodeArgs {
  tenant: string;
  issuerHost: string;
  clientId: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
}

/**
 * Standard OAuth 2.1 public-client authorization_code + PKCE exchange —
 * the same operation `RedirectEngine.signInCallback` performs via
 * oidc-client-ts's `UserManager` today, invoked directly here because
 * `HeadlessEngine` never navigates the browser away and back
 * (`implementation-plan.md` §8 item 4: "same token-exchange call
 * RedirectEngine.signInCallback makes"). `code_verifier` is generated
 * SDK-side (`../flow/headlessAuthFlow.ts`, via oidc-client-ts's
 * `SigninState.create`) and never sent anywhere but here.
 */
export async function exchangeAuthorizationCode(args: ExchangeCodeArgs): Promise<TokenResponse> {
  const discovery = await fetchDiscoveryDocument(args.tenant, args.issuerHost);
  return postTokenRequest(
    discovery.token_endpoint,
    {
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: args.redirectUri,
      client_id: args.clientId,
      code_verifier: args.codeVerifier,
    },
    "signin_failed",
  );
}

export interface RefreshArgs {
  tenant: string;
  issuerHost: string;
  clientId: string;
  refreshToken: string;
}

export async function refreshAccessToken(args: RefreshArgs): Promise<TokenResponse> {
  const discovery = await fetchDiscoveryDocument(args.tenant, args.issuerHost);
  return postTokenRequest(
    discovery.token_endpoint,
    {
      grant_type: "refresh_token",
      refresh_token: args.refreshToken,
      client_id: args.clientId,
    },
    "silent_renew_failed",
  );
}

async function postTokenRequest(
  tokenEndpoint: string,
  params: Record<string, string>,
  errorCode: JummonAuthErrorCode,
): Promise<TokenResponse> {
  let response: Response;
  try {
    response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params).toString(),
      credentials: "omit",
    });
  } catch (err) {
    throw new JummonAuthError("network_unreachable", "Could not reach the token endpoint.", err);
  }

  const body = (await response.json().catch(() => null)) as
    | (TokenResponse & { error?: string; error_description?: string })
    | null;

  if (!response.ok || !body || body.error) {
    throw new JummonAuthError(errorCode, body?.error_description ?? "Token exchange failed.", body);
  }
  return body;
}
