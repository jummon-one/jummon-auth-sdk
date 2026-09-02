import { DEFAULT_ISSUER_HOST } from "../discovery";
import { JummonAuthError, toJummonAuthError } from "../errors";
import type { HeadlessSessionSink } from "../flow/headlessAuthFlow";
import { AuthStateEmitter } from "../internal/authStateEmitter";
import { resolveStorage } from "../internal/storage";
import { fetchDiscoveryDocument, refreshAccessToken, type TokenResponse } from "../internal/tokenExchange";
import { decodeJwtPayload } from "../jwt";
import { buildJummonUser } from "../mapUser";
import type { AuthEngine, AuthState, JummonAuthOptions, JummonUser, SignInOptions, SignOutOptions } from "../types";

interface PersistedHeadlessSession {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  /** epoch seconds */
  expires_at: number;
}

/**
 * `HeadlessEngine implements AuthEngine` (`implementation-plan.md` §8 item
 * 1). The 8 existing `AuthEngine` methods delegate to the same
 * storage/emit plumbing `RedirectEngine` uses (`../internal/storage`,
 * `../internal/authStateEmitter`) so `getUser()`/`getAccessToken()`/
 * `isAuthenticated()`/`onAuthStateChanged()`/`signOut()`/`dispose()`
 * behave identically once a session exists — the only divergence is how
 * that session is established (`HeadlessAuthFlow`, not a URL redirect).
 *
 * `signIn()`/`signInCallback()` cannot express a multi-step login with a
 * single call, so both fail loud with `headless_requires_flow` rather than
 * silently doing something surprising — `startAuthFlow()`
 * (`../client.ts`) is the real entrypoint.
 */
export class HeadlessEngine implements AuthEngine, HeadlessSessionSink {
  private readonly storage: Storage;
  private readonly emitter = new AuthStateEmitter();
  private readonly tenant: string;
  private readonly clientId: string;
  private readonly issuerHost: string;
  private readonly storageKey: string;

  constructor(options: JummonAuthOptions) {
    if (typeof window === "undefined") {
      throw new JummonAuthError(
        "ssr_unsupported",
        "createJummonAuth() must run in a browser context (window is undefined). " +
          "Call it from a client component / effect, not during server rendering.",
      );
    }
    this.tenant = options.tenant;
    this.clientId = options.clientId;
    this.issuerHost = options.issuerHost ?? DEFAULT_ISSUER_HOST;
    this.storage = resolveStorage(options.tokenStorage);
    this.storageKey = `jummon.headless.session.${this.tenant}.${this.clientId}`;
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
    const session = this.read();
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
        window.location.assign(url.toString());
      }
    } catch (err) {
      throw toJummonAuthError(err);
    }
  }

  async getUser(): Promise<JummonUser | null> {
    const session = this.read();
    if (!session || isExpired(session)) {
      return null;
    }
    return this.mapSession(session);
  }

  async getAccessToken(): Promise<string | null> {
    const session = this.read();
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
   * `authenticated` envelope's `{code}` has been exchanged for tokens
   * (`implementation-plan.md` §8 item 4). This is the convergence point:
   * from here on, `getUser()`/`getAccessToken()`/`onAuthStateChanged()`
   * behave exactly as they would for `RedirectEngine`.
   */
  completeSignIn(tokens: TokenResponse): JummonUser {
    const persisted = this.write(tokens);
    const user = this.mapSession(persisted);
    this.emitter.emit({ status: "authenticated", user });
    return user;
  }

  private mapSession(session: PersistedHeadlessSession): JummonUser {
    const idClaims = decodeJwtPayload(session.id_token) ?? {};
    const accessClaims = decodeJwtPayload(session.access_token) ?? {};
    return buildJummonUser(idClaims, accessClaims, this.tenant);
  }

  private read(): PersistedHeadlessSession | null {
    const raw = this.storage.getItem(this.storageKey);
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw) as PersistedHeadlessSession;
    } catch {
      return null;
    }
  }

  private write(tokens: TokenResponse): PersistedHeadlessSession {
    const persisted: PersistedHeadlessSession = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      id_token: tokens.id_token,
      token_type: tokens.token_type,
      expires_at: Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 3600),
    };
    this.storage.setItem(this.storageKey, JSON.stringify(persisted));
    return persisted;
  }

  private clear(): void {
    this.storage.removeItem(this.storageKey);
  }
}

function isExpired(session: PersistedHeadlessSession): boolean {
  return Math.floor(Date.now() / 1000) >= session.expires_at;
}
