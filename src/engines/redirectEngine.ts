import { UserManager, WebStorageStateStore, type User, type UserManagerSettings } from "oidc-client-ts";
import { buildAuthority } from "../discovery";
import { JummonAuthError, toJummonAuthError } from "../errors";
import { mapOidcUser } from "../mapUser";
import type {
  AuthEngine,
  AuthState,
  JummonAuthOptions,
  JummonUser,
  SignInOptions,
  SignOutOptions,
} from "../types";

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

/**
 * v1 engine: full-page authorization-code + PKCE redirect, wrapping
 * oidc-client-ts's UserManager. This is the only AuthEngine implementation
 * that ships today. It exists behind the AuthEngine interface (not
 * exported directly from the package root) so a future HeadlessEngine can
 * be dropped into `createJummonAuth()` without changing this file's public
 * surface — see ../../ROADMAP.md.
 */
export class RedirectEngine implements AuthEngine {
  private readonly userManager: UserManager;
  private readonly tenant: string;
  private readonly postLogoutRedirectUri: string;
  private readonly listeners = new Set<(state: AuthState) => void>();
  private readonly unsubscribeHandlers: Array<() => void> = [];

  constructor(options: JummonAuthOptions) {
    if (typeof window === "undefined") {
      throw new JummonAuthError(
        "ssr_unsupported",
        "createJummonAuth() must run in a browser context (window is undefined). " +
          "Call it from a client component / effect, not during server rendering.",
      );
    }

    this.tenant = options.tenant;
    this.postLogoutRedirectUri = options.postLogoutRedirectUri ?? options.redirectUri;

    const settings: UserManagerSettings = {
      authority: buildAuthority(options.tenant, options.issuerHost),
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      post_logout_redirect_uri: this.postLogoutRedirectUri,
      response_type: "code",
      scope: (options.scopes ?? DEFAULT_SCOPES).join(" "),
      automaticSilentRenew: options.automaticSilentRenew ?? true,
      loadUserInfo: false,
      userStore: new WebStorageStateStore({ store: resolveStorage(options.tokenStorage) }),
    };

    this.userManager = new UserManager(settings);

    const onUserLoaded = (oidcUser: User) => {
      this.emit({ status: "authenticated", user: mapOidcUser(oidcUser, this.tenant) });
    };
    const onSignedOut = () => this.emit({ status: "unauthenticated" });

    this.userManager.events.addUserLoaded(onUserLoaded);
    this.userManager.events.addUserUnloaded(onSignedOut);
    this.userManager.events.addUserSignedOut(onSignedOut);
    this.userManager.events.addSilentRenewError(onSignedOut);

    this.unsubscribeHandlers.push(
      () => this.userManager.events.removeUserLoaded(onUserLoaded),
      () => this.userManager.events.removeUserUnloaded(onSignedOut),
      () => this.userManager.events.removeUserSignedOut(onSignedOut),
      () => this.userManager.events.removeSilentRenewError(onSignedOut),
    );
  }

  async signIn(opts?: SignInOptions): Promise<void> {
    try {
      await this.userManager.signinRedirect({
        state: opts?.state,
        extraQueryParams: opts?.extraQueryParams,
        prompt: opts?.prompt,
      });
    } catch (err) {
      throw toJummonAuthError(err);
    }
  }

  async signInCallback(url?: string): Promise<JummonUser> {
    let oidcUser;
    try {
      oidcUser = await this.userManager.signinCallback(url);
    } catch (err) {
      this.emit({ status: "unauthenticated" });
      throw toJummonAuthError(err);
    }

    if (!oidcUser) {
      this.emit({ status: "unauthenticated" });
      throw new JummonAuthError(
        "callback_missing_params",
        "No authorization response (code/state) found on the current URL. " +
          "signInCallback() must run on the page redirectUri points at, after the IdP redirect.",
      );
    }

    const user = mapOidcUser(oidcUser, this.tenant);
    this.emit({ status: "authenticated", user });
    return user;
  }

  async signOut(opts?: SignOutOptions): Promise<void> {
    try {
      if (opts?.redirect === false) {
        await this.userManager.removeUser();
        this.emit({ status: "unauthenticated" });
        return;
      }
      await this.userManager.signoutRedirect({
        post_logout_redirect_uri: this.postLogoutRedirectUri,
      });
    } catch (err) {
      throw toJummonAuthError(err);
    }
  }

  async getUser(): Promise<JummonUser | null> {
    const oidcUser = await this.userManager.getUser();
    if (!oidcUser || oidcUser.expired) {
      return null;
    }
    return mapOidcUser(oidcUser, this.tenant);
  }

  async getAccessToken(): Promise<string | null> {
    const oidcUser = await this.userManager.getUser();
    if (!oidcUser) {
      return null;
    }
    if (!oidcUser.expired) {
      return oidcUser.access_token;
    }
    try {
      const refreshed = await this.userManager.signinSilent();
      return refreshed?.access_token ?? null;
    } catch (err) {
      throw new JummonAuthError(
        "silent_renew_failed",
        "Silent token refresh failed; the user likely needs to sign in again.",
        err,
      );
    }
  }

  async isAuthenticated(): Promise<boolean> {
    const user = await this.getUser();
    return user !== null;
  }

  onAuthStateChanged(cb: (state: AuthState) => void): () => void {
    this.listeners.add(cb);
    void this.getUser().then((user) => {
      cb(user ? { status: "authenticated", user } : { status: "unauthenticated" });
    });
    return () => {
      this.listeners.delete(cb);
    };
  }

  dispose(): void {
    for (const unsubscribe of this.unsubscribeHandlers) {
      unsubscribe();
    }
    this.listeners.clear();
    this.userManager.stopSilentRenew();
  }

  private emit(state: AuthState): void {
    for (const listener of this.listeners) {
      listener(state);
    }
  }
}

function resolveStorage(kind: JummonAuthOptions["tokenStorage"]): Storage {
  if (kind === "local") {
    return window.localStorage;
  }
  if (kind === "memory") {
    return new MemoryStorage();
  }
  return window.sessionStorage;
}

/**
 * In-memory Storage shim for `tokenStorage: "memory"`. Trades "survives a
 * full-page reload" for "nothing to steal via XSS reading storage" — see
 * README "Security / token storage" for when to pick this over the
 * session-storage default (which oidc-client-ts itself defaults to, and
 * which every redirect-flow SPA SDK relies on to survive the navigation
 * away from and back to the app during signInCallback()).
 */
class MemoryStorage implements Storage {
  private readonly data = new Map<string, string>();

  get length(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }

  getItem(key: string): string | null {
    return this.data.has(key) ? (this.data.get(key) as string) : null;
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}
