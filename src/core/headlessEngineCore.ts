import { DEFAULT_ISSUER_HOST } from "../discovery";
import { JummonAuthError, toJummonAuthError } from "../errors";
import { AuthStateEmitter } from "../internal/authStateEmitter";
import { fetchDiscoveryDocument, refreshAccessToken, revokeToken, type TokenResponse } from "../internal/tokenExchange";
import { decodeJwtPayload } from "../jwt";
import { buildJummonUser } from "../mapUser";
import type { AuthEngine, AuthState, JummonAuthOptions, JummonUser, SignInOptions, SignOutOptions } from "../types";
import type { PlatformAdapters } from "./platform/types";

/**
 * Prefix of the storage key `HeadlessEngineCore` persists the OIDC session
 * under (full key: `${HEADLESS_SESSION_STORAGE_PREFIX}${tenant}.${clientId}`,
 * see the constructor below). Exported so a platform adapter that routes
 * `PlatformStorage` reads/writes to different backing stores by key
 * (`@jummon/auth-react-native`'s composite storage — AsyncStorage for
 * `flowPersistence.ts`'s resume state, SecureStore/Keychain for these
 * long-lived tokens) can key off it instead of duplicating the literal.
 */
export const HEADLESS_SESSION_STORAGE_PREFIX = "jummon.headless.session.";

interface PersistedHeadlessSession {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  /** epoch seconds */
  expires_at: number;
}

/**
 * Platform-agnostic engine logic behind `HeadlessEngine`
 * (`../engines/headlessEngine.ts`). Extracted so the WEB engine class is a
 * thin wrapper that supplies browser adapters by default — this class itself
 * never touches `window`/`navigator`/DOM globals, only `adapters.storage` /
 * `adapters.navigation`, so a future RN engine can construct it directly
 * with its own adapters.
 *
 * `HeadlessSessionSink.completeSignIn()` stays SYNCHRONOUS (unchanged public
 * contract, see `../flow/headlessAuthFlow.ts`) — the in-memory
 * `cachedSession` is the source of truth once populated, so the storage
 * write it triggers is fire-and-forget; the very first `getUser()`/
 * `getAccessToken()` call after construction (before any write has happened)
 * is the only one that genuinely awaits the adapter's `getItem()`, to
 * restore a session across a page reload (web) or app relaunch (RN).
 */
export class HeadlessEngineCore implements AuthEngine {
  private readonly emitter = new AuthStateEmitter();
  private readonly tenant: string;
  private readonly clientId: string;
  private readonly issuerHost: string;
  private readonly storageKey: string;
  /** `undefined` = not yet loaded from `adapters.storage`; `null` = loaded, no session. */
  private cachedSession: PersistedHeadlessSession | null | undefined = undefined;

  constructor(
    options: JummonAuthOptions,
    private readonly adapters: PlatformAdapters,
  ) {
    this.tenant = options.tenant;
    this.clientId = options.clientId;
    this.issuerHost = options.issuerHost ?? DEFAULT_ISSUER_HOST;
    this.storageKey = `${HEADLESS_SESSION_STORAGE_PREFIX}${this.tenant}.${this.clientId}`;
  }

  async signIn(_opts?: SignInOptions): Promise<void> {
    throw new JummonAuthError(
      "headless_requires_flow",
      'mode: "headless" cannot express a multi-step login through signIn(). ' +
        'Call createJummonAuth({ ...options, mode: "headless" }).startAuthFlow() instead ' +
        "(see system-design.md §6 and the README's headless section).",
    );
  }

  async signInCallback(_url?: string): Promise<JummonUser> {
    throw new JummonAuthError(
      "headless_requires_flow",
      "Headless mode has no URL-based callback — the HeadlessAuthFlow object " +
        "returned by startAuthFlow() resolves the terminal `authenticated` state directly.",
    );
  }

  async signOut(opts?: SignOutOptions): Promise<void> {
    const session = await this.read();
    // Revoke BEFORE clearing local state — see revokeStolenableTokens()'s
    // doc comment for why this ordering matters and why it never blocks/
    // fails signOut. Runs unconditionally (even when `redirect: false`) —
    // revocation is server-side cleanup of a bearer credential, unrelated
    // to whether this call also does an RP-initiated (end_session_endpoint)
    // browser redirect.
    if (session) {
      await this.revokeStolenableTokens(session);
    }
    this.clear();
    this.emitter.emit({ status: "unauthenticated" });
    if (opts?.redirect === false || !session) {
      return;
    }
    try {
      const discovery = await fetchDiscoveryDocument(this.tenant, this.issuerHost);
      if (discovery.end_session_endpoint) {
        const url = new URL(discovery.end_session_endpoint);
        if (session.id_token) {
          url.searchParams.set("id_token_hint", session.id_token);
        }
        await this.adapters.navigation.redirect(url.toString());
      }
    } catch (err) {
      throw toJummonAuthError(err);
    }
  }

  async getUser(): Promise<JummonUser | null> {
    const session = await this.read();
    if (!session || isExpired(session)) {
      return null;
    }
    return this.mapSession(session);
  }

  async getAccessToken(): Promise<string | null> {
    const session = await this.read();
    if (!session) {
      return null;
    }
    if (!isExpired(session)) {
      return session.access_token;
    }
    if (!session.refresh_token) {
      throw new JummonAuthError(
        "silent_renew_failed",
        "Access token expired and no refresh_token is available; the user must sign in again.",
      );
    }
    try {
      const tokens = await refreshAccessToken({
        tenant: this.tenant,
        issuerHost: this.issuerHost,
        clientId: this.clientId,
        refreshToken: session.refresh_token,
      });
      const persisted = this.write(tokens);
      this.emitter.emit({ status: "authenticated", user: this.mapSession(persisted) });
      return persisted.access_token;
    } catch (err) {
      throw err instanceof JummonAuthError
        ? err
        : new JummonAuthError(
            "silent_renew_failed",
            "Silent token refresh failed; the user likely needs to sign in again.",
            err,
          );
    }
  }

  async isAuthenticated(): Promise<boolean> {
    return (await this.getUser()) !== null;
  }

  onAuthStateChanged(cb: (state: AuthState) => void): () => void {
    const unsubscribe = this.emitter.subscribe(cb);
    void this.getUser().then((user) => {
      cb(user ? { status: "authenticated", user } : { status: "unauthenticated" });
    });
    return unsubscribe;
  }

  dispose(): void {
    this.emitter.clear();
  }

  /**
   * `HeadlessSessionSink` — called by `HeadlessAuthFlow` once the terminal
   * `authenticated` envelope's `{code}` has been exchanged for tokens. This
   * is the convergence point: from here on, `getUser()`/`getAccessToken()`/
   * `onAuthStateChanged()` behave exactly as they would for `RedirectEngine`.
   */
  completeSignIn(tokens: TokenResponse): JummonUser {
    const persisted = this.write(tokens);
    const user = this.mapSession(persisted);
    this.emitter.emit({ status: "authenticated", user });
    return user;
  }

  /**
   * RFC 7009 revocation for the session's `refresh_token` — closes "a
   * stolen refresh_token survives signOut" (P1). Best-effort: `revokeToken()`
   * never throws, and this method never throws either, so a revoke failure
   * (network blip, revocation_endpoint temporarily down) never blocks or
   * fails `signOut()` — the caller always proceeds to clear local state
   * regardless of the outcome. Called BEFORE `this.clear()` purely so the
   * refresh_token value is still on hand to send; it does not affect
   * whether local state ends up cleared (that happens unconditionally
   * right after, in `signOut()`).
   *
   * Only the refresh_token is revoked, not the access_token — the
   * short-lived access_token expires on its own shortly regardless, and
   * revoking it separately would be a second network call for no
   * meaningful security gain here (RFC 7009 §2.1 permits revoking either;
   * the refresh_token is the one that "survives" signOut without this fix).
   */
  private async revokeStolenableTokens(session: PersistedHeadlessSession): Promise<void> {
    if (!session.refresh_token) {
      return;
    }
    try {
      await revokeToken({
        tenant: this.tenant,
        issuerHost: this.issuerHost,
        clientId: this.clientId,
        token: session.refresh_token,
        tokenTypeHint: "refresh_token",
      });
    } catch {
      // Defense-in-depth — `revokeToken()` itself never throws (see its own
      // doc comment), but `signOut()` must not depend on that holding true
      // forever: a revoke failure of any shape must never block/fail
      // signOut, never leave the user "stuck signed in".
    }
  }

  private mapSession(session: PersistedHeadlessSession): JummonUser {
    const idClaims = decodeJwtPayload(session.id_token) ?? {};
    const accessClaims = decodeJwtPayload(session.access_token) ?? {};
    return buildJummonUser(idClaims, accessClaims, this.tenant);
  }

  private async read(): Promise<PersistedHeadlessSession | null> {
    if (this.cachedSession !== undefined) {
      return this.cachedSession;
    }
    let raw: string | null;
    try {
      raw = await this.adapters.storage.getItem(this.storageKey);
    } catch {
      raw = null;
    }
    // A write()/clear() (completeSignIn()/signOut()) can land while this
    // read was in flight — that synchronous, in-memory mutation is now
    // authoritative; never let a slower, now-stale storage read stomp it.
    if (this.cachedSession !== undefined) {
      return this.cachedSession;
    }
    if (!raw) {
      this.cachedSession = null;
      return null;
    }
    try {
      this.cachedSession = JSON.parse(raw) as PersistedHeadlessSession;
    } catch {
      this.cachedSession = null;
    }
    return this.cachedSession;
  }

  private write(tokens: TokenResponse): PersistedHeadlessSession {
    const persisted: PersistedHeadlessSession = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      token_type: tokens.token_type,
      expires_at: Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 3600),
    };
    this.cachedSession = persisted;
    void this.adapters.storage.setItem(this.storageKey, JSON.stringify(persisted)).catch(() => {
      // Best-effort — the in-memory cache above is already the source of
      // truth for the lifetime of this engine instance; a failed write only
      // degrades cross-reload/relaunch session restoration.
    });
    return persisted;
  }

  private clear(): void {
    this.cachedSession = null;
    void this.adapters.storage.removeItem(this.storageKey).catch(() => {
      // best-effort, see write()'s doc comment.
    });
  }
}

function isExpired(session: PersistedHeadlessSession): boolean {
  return Math.floor(Date.now() / 1000) >= session.expires_at;
}
