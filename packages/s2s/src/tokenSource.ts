/**
 * S2STokenSource — mints and caches a `client_credentials` access token for
 * one Jummon service-account client identity, using `private_key_jwt`
 * (RFC 7523) client-assertion signing (or, as a documented fallback,
 * `client_secret_post`).
 *
 * This is a generalized, publishable port of
 * `jummon-login-interface/src/server/services/internalauth/tokenSource.ts`
 * (which itself ports `jummon-pkg/pkg/internalauth`, ADR-0002) — same claim
 * shape (`buildAssertion`), same cache/refresh fraction (0.8 of TTL), same
 * fail-closed-unless-a-still-valid-stale-token-exists contract, same
 * single-flight mint coalescing. Reimplemented rather than imported for the
 * same reason the login-interface port gives: the wire contract (what
 * auth-engine's `private_key_jwt` verifier and
 * `ClientCredentialsTokenRequest` actually check) is the source of truth,
 * not any one language's source tree — and this package ships to customer
 * backends outside the jummon monorepo entirely, so it cannot import
 * `jummon-pkg` regardless.
 *
 * Zero external dependencies: Node's built-in `crypto` for RS256 signing,
 * global `fetch` (Node >= 18) for the token-endpoint call.
 */
import crypto, { type KeyObject } from "node:crypto";

import { S2SError } from "./errors";

/** `idm.jummon.com` — the tenant-in-path OIDC issuer host. Mirrors
 * `@jummon/auth`'s `DEFAULT_ISSUER_HOST` (../../../src/discovery.ts); kept
 * as an independent constant, not an import, per this package's zero
 * cross-package-runtime-dependency rule (see `index.ts`'s doc comment). */
export const DEFAULT_ISSUER_HOST = "idm.jummon.com";

// RFC 7523 §3(3): the client_assertion is single-use, not a standing
// credential — it only needs to live long enough to reach the token
// endpoint. Matches jummon-pkg's clientAssertionTTL.
const CLIENT_ASSERTION_TTL_SECONDS = 60;

// Proactive-refresh threshold: mint again once this fraction of the issued
// token's expires_in has elapsed, so a legitimate request never races an
// about-to-expire token. Matches jummon-pkg's tokenRefreshFraction.
const TOKEN_REFRESH_FRACTION = 0.8;

const DEFAULT_MINT_TIMEOUT_MS = 5000;

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

interface SigningKey {
  keyObject: KeyObject;
  kid?: string;
}

function base64url(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Accepts either a JSON JWK (preferred — carries its own `kid`, matching
 * what catalog-api's `credentials/jwt-keys` provisioning discloses) or a
 * raw PEM-encoded private key (PKCS8 or PKCS1 — Node's `createPrivateKey`
 * handles both transparently). Mirrors jummon-pkg's
 * `jwtsign.ParseSigningKey` / the login-interface port's `parseSigningKey`.
 */
function parseSigningKey(raw: string): SigningKey {
  const trimmed = raw.trim();
  try {
    if (trimmed.startsWith("{")) {
      const jwk = JSON.parse(trimmed) as Record<string, unknown>;
      return {
        keyObject: crypto.createPrivateKey({ key: jwk as unknown as crypto.JsonWebKeyInput["key"], format: "jwk" }),
        kid: typeof jwk.kid === "string" ? jwk.kid : undefined,
      };
    }
    return { keyObject: crypto.createPrivateKey(trimmed) };
  } catch (cause) {
    throw new S2SError("key_parse_failed", "privateKey is neither a valid JWK JSON nor a PEM-encoded key.", {
      cause,
    });
  }
}

/**
 * Strips an accidental scheme/trailing-slash so `buildAssertion` can
 * compose `https://<host>/<tenant>/oidc` unambiguously. Mirrors
 * jummon-pkg's `normalizeIssuerHost`.
 */
function normalizeIssuerHost(raw: string): string {
  return raw.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

export interface S2STokenSourceConfig {
  /** The service-account's `client_id` (provisioned via catalog-api /
   * `clients_provisionServiceAccount`). */
  clientId: string;
  /**
   * The service-account's `private_key_jwt` credential — JWK JSON (with its
   * `kid`) or PEM (PKCS8/PKCS1), exactly as returned once by
   * `POST /catalog/clients/{id}/credentials/jwt-keys`. Mutually exclusive
   * with `clientSecret`; provide exactly one.
   */
  privateKey?: string;
  /**
   * Fallback shared-secret credential (`client_secret_post`), documented as
   * a bridge for backends that can't yet sign a JWT assertion (Prummo
   * integration guide §8.1.1). Mutually exclusive with `privateKey` — do
   * not permanently downgrade a `private_key_jwt` client to this just for
   * convenience.
   */
  clientSecret?: string;
  /** The tenant slug this service-account lives in (e.g. `"prummo"`). */
  tenant: string;
  /** Tenant-in-path OIDC host. Defaults to {@link DEFAULT_ISSUER_HOST}
   * (production). Pass `"idm-dev.jummon.dev"` (or your dev host) in
   * non-prod. */
  issuerHost?: string;
  /** Token endpoint. Defaults to
   * `https://<issuerHost>/<tenant>/oidc/oauth/token`. */
  tokenUrl?: string;
  /** Optional `scope` form param forwarded on every mint. */
  scope?: string;
  /** Optional `audience` form param forwarded on every mint. */
  audience?: string;
  /** Abort a mint attempt after this many ms. Default 5000. */
  mintTimeoutMs?: number;
  /**
   * Called when a mint fails but a not-yet-hard-expired cached token is
   * served instead (fail-closed only when NOTHING usable is cached). No-op
   * by default — this package takes no logging dependency; wire this to
   * your own logger if you want visibility.
   */
  onStaleTokenServed?: (error: unknown) => void;
}

/**
 * Mints and caches a `client_credentials` access token for one fixed
 * service-account identity + scope/audience pair. Construct one instance
 * per (callee, scope) pair you call — never share one `S2STokenSource`
 * across two different audiences (ADR-0002 §Q4's rule, which this class
 * inherits structurally: `audience` is fixed at construction, not
 * per-call).
 */
export class S2STokenSource {
  private readonly clientId: string;
  private readonly signingKey?: SigningKey;
  private readonly clientSecret?: string;
  private readonly tokenUrl: string;
  private readonly issuerHost: string;
  private readonly tenant: string;
  private readonly scope?: string;
  private readonly audience?: string;
  private readonly mintTimeoutMs: number;
  private readonly onStaleTokenServed?: (error: unknown) => void;

  private accessToken?: string;
  private softExpiresAt = 0;
  private hardExpiresAt = 0;
  private mintPromise?: Promise<string>;

  constructor(config: S2STokenSourceConfig) {
    if (!config.clientId) {
      throw new S2SError("invalid_config", "clientId is required.");
    }
    if (!config.tenant) {
      throw new S2SError("invalid_config", "tenant is required.");
    }
    if (Boolean(config.privateKey) === Boolean(config.clientSecret)) {
      throw new S2SError("invalid_config", "Provide exactly one of privateKey or clientSecret, not both/neither.");
    }

    this.clientId = config.clientId;
    this.tenant = config.tenant;
    this.issuerHost = normalizeIssuerHost(config.issuerHost ?? DEFAULT_ISSUER_HOST);
    this.tokenUrl = config.tokenUrl ?? `https://${this.issuerHost}/${this.tenant}/oidc/oauth/token`;
    this.scope = config.scope;
    this.audience = config.audience;
    this.mintTimeoutMs = config.mintTimeoutMs ?? DEFAULT_MINT_TIMEOUT_MS;
    this.onStaleTokenServed = config.onStaleTokenServed;

    if (config.privateKey) {
      this.signingKey = parseSigningKey(config.privateKey);
    } else {
      this.clientSecret = config.clientSecret;
    }
  }

  /**
   * Returns a cached access token, minting a fresh one once the cache is
   * empty or past `TOKEN_REFRESH_FRACTION` of its lifetime.
   *
   * Fails closed only when there's NO usable cached token at all: if a
   * fresh mint fails but a previously issued token hasn't actually expired
   * yet (`hardExpiresAt`), that stale token is served instead of throwing.
   * Concurrent callers racing a cold/expired cache are coalesced into a
   * single in-flight mint (no thundering herd of client_credentials
   * requests).
   */
  async getToken(): Promise<string> {
    const now = Date.now();
    if (this.accessToken && now < this.softExpiresAt) {
      return this.accessToken;
    }
    if (!this.mintPromise) {
      this.mintPromise = this.mint(now).finally(() => {
        this.mintPromise = undefined;
      });
    }
    return this.mintPromise;
  }

  private async mint(now: number): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.mintTimeoutMs);
    try {
      const form = new URLSearchParams();
      form.set("grant_type", "client_credentials");
      if (this.scope) form.set("scope", this.scope);
      if (this.audience) form.set("audience", this.audience);

      if (this.signingKey) {
        form.set("client_assertion_type", CLIENT_ASSERTION_TYPE);
        form.set("client_assertion", this.buildAssertion(now));
      } else {
        form.set("client_id", this.clientId);
        form.set("client_secret", this.clientSecret as string);
      }

      let response: Response;
      try {
        response = await fetch(this.tokenUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            // auth-engine's hostResolverInterceptor composes the per-tenant
            // issuer from this header; omitting it 400s TENANT_ERROR before
            // the client_assertion/secret is ever inspected.
            "X-Tenant-Id": this.tenant,
          },
          body: form.toString(),
          signal: controller.signal,
        });
      } catch (cause) {
        if (controller.signal.aborted) {
          throw new S2SError("mint_timeout", `Token mint timed out after ${this.mintTimeoutMs}ms.`, { cause });
        }
        throw new S2SError("mint_failed", "Token endpoint request failed.", { cause });
      }

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        throw new S2SError("http_error", `Token endpoint returned ${response.status}: ${body}`, {
          status: response.status,
        });
      }

      const data = (await response.json().catch(() => ({}))) as {
        access_token?: string;
        expires_in?: number;
      };
      if (!data.access_token || !data.expires_in || data.expires_in <= 0) {
        throw new S2SError("invalid_response", "Token endpoint returned an incomplete response.");
      }

      const ttlMs = data.expires_in * 1000;
      this.accessToken = data.access_token;
      this.hardExpiresAt = now + ttlMs;
      this.softExpiresAt = now + ttlMs * TOKEN_REFRESH_FRACTION;
      return this.accessToken;
    } catch (error) {
      if (this.accessToken && now < this.hardExpiresAt) {
        this.onStaleTokenServed?.(error);
        return this.accessToken;
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Signs the `private_key_jwt` client assertion: `iss`/`sub` are this
   * client's own id, `aud` is the per-tenant OIDC ISSUER (NOT the literal
   * token endpoint URL — auth-engine's verifier checks `aud` against the
   * request's already-tenant-rewritten issuer, not the dial target).
   * Short-lived and single-use (`jti`).
   */
  private buildAssertion(now: number): string {
    const signingKey = this.signingKey as SigningKey;
    const header: Record<string, string> = { alg: "RS256", typ: "JWT" };
    if (signingKey.kid) header.kid = signingKey.kid;

    const iat = Math.floor(now / 1000);
    const payload = {
      iss: this.clientId,
      sub: this.clientId,
      aud: `https://${this.issuerHost}/${this.tenant}/oidc`,
      iat,
      exp: iat + CLIENT_ASSERTION_TTL_SECONDS,
      jti: crypto.randomUUID(),
    };

    const signingInput = `${base64url(Buffer.from(JSON.stringify(header)))}.${base64url(
      Buffer.from(JSON.stringify(payload)),
    )}`;
    const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), signingKey.keyObject);
    return `${signingInput}.${base64url(signature)}`;
  }
}
