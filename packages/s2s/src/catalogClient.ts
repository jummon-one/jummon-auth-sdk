/**
 * Thin catalog-api wrappers over an S2S service-account token — so an
 * integrator never has to guess a request-body shape again. Every field
 * name discrepancy here has burned an integrator before (Prummo guide
 * `initiatives/headless-embeddable-auth/PRUMMO-INTEGRATION-GUIDE.md` §8.1)
 * — most notably `personal_email` (NOT `email` — a bare `email` is
 * silently ignored by catalog-api's binder) and `client_id` being
 * REQUIRED for any non-interactive (service-account) caller.
 *
 * Confirmed against `catalog-api/internal/catalog/users/{dto/dto.go,
 * handler/handler.go}` — see the field-by-field comments below.
 */
import { S2SError } from "./errors";

/** `api.jummon.com` — the API-gateway host. Mirrors `@jummon/auth`'s
 * `DEFAULT_API_HOST` (../../../src/internal/passkeyEnrollment.ts); kept
 * independent, not imported, per this package's zero cross-package-
 * runtime-dependency rule. Use `"api.jummon.dev"` in dev. */
export const DEFAULT_API_HOST = "api.jummon.com";

/** Anything that can hand back a bearer token — `S2STokenSource` satisfies
 * this structurally. Kept as a narrow interface (not the concrete class)
 * so tests can inject a fake, and so a `client_secret_post`-only caller
 * (Prummo guide §8.1.1's fallback) can supply its own token provider
 * without going through `S2STokenSource` at all. */
export interface TokenProvider {
  getToken(): Promise<string>;
}

export interface JummonCatalogClientConfig {
  tokenSource: TokenProvider;
  /** API-gateway host. Defaults to {@link DEFAULT_API_HOST} (production).
   * Pass `"api.jummon.dev"` in non-prod. */
  apiHost?: string;
  /** Abort an API call after this many ms. Default 10000. */
  requestTimeoutMs?: number;
}

export interface CreateUserInput {
  /**
   * The OAuth client (your own business app, e.g. `"prummo-app"`) the
   * created user belongs to for onboarding purposes. REQUIRED for a
   * service-account caller — omitting it 400s `INVITE_CLIENT_ID_REQUIRED`;
   * pointing at a Jummon system-managed client (`b2b-portal`, `cockpit-ui`)
   * 403s `INVITE_TARGET_SYSTEM_CLIENT_FORBIDDEN`. This is `client_id` on
   * the wire, NEVER `onboarding_client_id` (that field doesn't exist).
   */
  clientId: string;
  kind?: "human" | "machine";
  firstName?: string;
  lastName?: string;
  /** Convenience alias for `personalEmail` — most integrators only have one
   * email per user. If both `email` and `personalEmail` are set,
   * `personalEmail` wins. */
  email?: string;
  /** Wire field `personal_email`. NOT `email` — catalog-api has no `email`
   * field on single-user create (only on bulk/import); a bare `email` is
   * silently dropped by the binder and the user is created with no
   * address at all. */
  personalEmail?: string;
  companyEmail?: string;
  username?: string;
  phone?: string;
  ddd?: string;
  ddi?: string;
  /**
   * Setting this creates the user WITH a password already set
   * (backend-proxied / password flow). Also sets `onboarding: "password"`
   * on the wire unless `onboarding` is explicitly overridden.
   */
  password?: string;
  /** Wire `oneof=magic_link password`. Defaults to `"password"` when
   * `password` is set, otherwise omitted (plain create, invite later via
   * {@link JummonCatalogClient.invite}). */
  onboarding?: "password" | "magic_link";
  /** Only meaningful with `onboarding: "magic_link"` — gates whether
   * catalog-api also emails the link. Defaults server-side to `true`. */
  sendEmail?: boolean;
  groupIds?: string[];
  roleIds?: string[];
  requiredActions?: string[];
  federationAlias?: string;
  federationSubject?: string;
}

export interface CatalogUser {
  id: string;
  kind: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  companyEmail?: string;
  personalEmail?: string;
  isBlocked: boolean;
  neverLogged: boolean;
  isEmailVerified: boolean;
  isPhoneVerified: boolean;
  /** catalog-api's `UserResponse` carries more fields than are worth
   * hand-typing here (block metadata, terms agreement, etc.) — anything not
   * listed above is still present on the raw response, just untyped. */
  [key: string]: unknown;
}

export interface MagicLink {
  url: string;
  expiresAt: string;
  tokenId: string;
}

export interface CreateUserResult {
  user: CatalogUser;
  magicLink?: MagicLink;
  emailSent?: boolean;
  emailError?: string;
  partialSuccess: boolean;
  completedSteps?: string[];
  failedSteps?: Array<{ step: string; error: string }>;
}

export interface InviteInput {
  userId: string;
  /** Same `client_id` requirement/semantics as {@link CreateUserInput.clientId}. */
  clientId: string;
  redirectTo?: string;
  /** `"passwordless-only"` (or omitted) is the right choice for a truly
   * passwordless onboarding — `"first-login"` and `"recover-password"`
   * both inject EXTRA required actions beyond what `requiredActions` below
   * controls (Prummo guide §8.3). */
  linkType?: "recover-account" | "first-login" | "passwordless-only" | "recover-password";
  durationSeconds?: number;
  /**
   * Omitted/empty (`[]` counts as empty too — catalog-api treats it the
   * same as "field omitted") falls back to the first-time onboarding set
   * (password + OTP + passkey nudge), NOT passwordless-only. To skip the
   * password screen, list explicitly e.g. `["configure-passwordless"]` —
   * note `otp-configure` is re-added server-side unconditionally as a
   * mandatory first-login floor (Prummo guide §8.2), so it will still
   * appear even if you don't list it.
   */
  requiredActions?: string[];
  sendEmail?: boolean;
  templateIdentifier?: string;
  emailBindings?: Record<string, unknown>;
}

export interface InviteResult {
  magicLink: MagicLink;
  emailSent?: boolean;
  emailError?: string;
}

function buildUrl(apiHost: string, path: string): string {
  return `https://${apiHost}${path}`;
}

/** Thin, typed wrappers over catalog-api's user-provisioning endpoints,
 * authenticated with a service-account bearer minted by a
 * {@link TokenProvider} (normally {@link import("./tokenSource").S2STokenSource}). */
export class JummonCatalogClient {
  private readonly tokenSource: TokenProvider;
  private readonly apiHost: string;
  private readonly requestTimeoutMs: number;

  constructor(config: JummonCatalogClientConfig) {
    this.tokenSource = config.tokenSource;
    this.apiHost = config.apiHost ?? DEFAULT_API_HOST;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 10_000;
  }

  /**
   * `POST /catalog/users` — create a user. Requires
   * `identity:users:create` on the service-account's token.
   */
  async createUser(input: CreateUserInput): Promise<CreateUserResult> {
    if (!input.clientId) {
      throw new S2SError(
        "invalid_config",
        "clientId is required for a service-account caller (catalog-api 400s INVITE_CLIENT_ID_REQUIRED without it).",
      );
    }

    const personalEmail = input.personalEmail ?? input.email;
    const body = {
      kind: input.kind ?? "human",
      first_name: input.firstName,
      last_name: input.lastName,
      personal_email: personalEmail,
      company_email: input.companyEmail,
      username: input.username,
      phone: input.phone,
      ddd: input.ddd,
      ddi: input.ddi,
      password: input.password,
      onboarding: input.onboarding ?? (input.password ? "password" : undefined),
      send_email: input.sendEmail,
      client_id: input.clientId,
      group_ids: input.groupIds,
      role_ids: input.roleIds,
      required_actions: input.requiredActions,
      federation_alias: input.federationAlias,
      federation_subject: input.federationSubject,
    };

    const raw = await this.post<{
      user: Record<string, unknown> & { id: string; kind: string };
      magic_link?: { url: string; expires_at: string; token_id: string };
      email_sent?: boolean;
      email_error?: string;
      partial_success: boolean;
      completed_steps?: string[];
      failed_steps?: Array<{ step: string; error: string }>;
    }>("/catalog/users", body);

    return {
      user: mapCatalogUser(raw.user),
      magicLink: raw.magic_link ? mapMagicLink(raw.magic_link) : undefined,
      emailSent: raw.email_sent,
      emailError: raw.email_error,
      partialSuccess: raw.partial_success,
      completedSteps: raw.completed_steps,
      failedSteps: raw.failed_steps,
    };
  }

  /**
   * `POST /catalog/users/{userId}/passwordless-invite` — issue a
   * one-time onboarding/recovery magic link. Requires the `MAGIC_LINK_CREATE`
   * operation on the service-account's token.
   */
  async invite(input: InviteInput): Promise<InviteResult> {
    if (!input.userId) {
      throw new S2SError("invalid_config", "userId is required.");
    }
    if (!input.clientId) {
      throw new S2SError(
        "invalid_config",
        "clientId is required for a service-account caller (catalog-api 400s INVITE_CLIENT_ID_REQUIRED without it).",
      );
    }

    const body = {
      client_id: input.clientId,
      redirect_to: input.redirectTo,
      link_type: input.linkType,
      duration_seconds: input.durationSeconds,
      required_actions: input.requiredActions,
      send_email: input.sendEmail,
      template_identifier: input.templateIdentifier,
      email_bindings: input.emailBindings,
    };

    const raw = await this.post<{
      magic_link: { url: string; expires_at: string; token_id: string };
      email_sent?: boolean;
      email_error?: string;
    }>(`/catalog/users/${encodeURIComponent(input.userId)}/passwordless-invite`, body);

    return {
      magicLink: mapMagicLink(raw.magic_link),
      emailSent: raw.email_sent,
      emailError: raw.email_error,
    };
  }

  /**
   * `POST /catalog/users/{userId}/credentials/password` — set (or reset) a
   * user's password directly, bypassing the onboarding-link flow. Requires
   * the `UserPasswordUpdate` operation on the service-account's token.
   *
   * catalog-api's `SetPasswordRequest` requires BOTH `password` and
   * `confirmation_password` (`dto.go:265-268`); this wrapper sends the same
   * value for both by default since a server-side caller only ever has one
   * value to set. Pass `confirmationPassword` explicitly only if your own
   * flow genuinely captured two independent inputs.
   */
  async setPassword(userId: string, password: string, confirmationPassword?: string): Promise<void> {
    if (!userId) {
      throw new S2SError("invalid_config", "userId is required.");
    }
    if (!password) {
      throw new S2SError("invalid_config", "password is required.");
    }

    await this.post<void>(`/catalog/users/${encodeURIComponent(userId)}/credentials/password`, {
      password,
      confirmation_password: confirmationPassword ?? password,
    });
  }

  private async post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    const token = await this.tokenSource.getToken();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);

    let response: Response;
    try {
      response = await fetch(buildUrl(this.apiHost, path), {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (cause) {
      if (controller.signal.aborted) {
        throw new S2SError("request_timeout", `Request to ${path} timed out after ${this.requestTimeoutMs}ms.`, {
          cause,
        });
      }
      throw new S2SError("http_error", `Request to ${path} failed.`, { cause });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new S2SError("http_error", `${path} returned ${response.status}: ${text}`, {
        status: response.status,
      });
    }

    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json().catch(() => {
      throw new S2SError("invalid_response", `${path} returned a non-JSON response.`);
    })) as T;
  }
}

function mapMagicLink(raw: { url: string; expires_at: string; token_id: string }): MagicLink {
  return { url: raw.url, expiresAt: raw.expires_at, tokenId: raw.token_id };
}

function mapCatalogUser(raw: Record<string, unknown> & { id: string; kind: string }): CatalogUser {
  return {
    ...raw,
    id: raw.id,
    kind: raw.kind,
    username: raw.username as string | undefined,
    firstName: raw.first_name as string | undefined,
    lastName: raw.last_name as string | undefined,
    companyEmail: raw.company_email as string | undefined,
    personalEmail: raw.personal_email as string | undefined,
    isBlocked: Boolean(raw.is_blocked),
    neverLogged: Boolean(raw.never_logged),
    isEmailVerified: Boolean(raw.is_email_verified),
    isPhoneVerified: Boolean(raw.is_phone_verified),
  };
}
