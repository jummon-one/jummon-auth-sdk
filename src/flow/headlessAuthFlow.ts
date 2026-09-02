import { SigninState } from "oidc-client-ts";
import { buildAuthority, DEFAULT_ISSUER_HOST } from "../discovery";
import { JummonAuthError } from "../errors";
import { exchangeAuthorizationCode } from "../internal/tokenExchange";
import type { JummonAuthOptions, JummonUser } from "../types";
import { clearStoredFlow, persistFlow, readStoredFlow, stripAuthParamsFromUrl } from "./persistence";
import { deriveState } from "./stepState";
import { HeadlessTransport } from "./transport";
import type {
  HeadlessAuthEnvelope,
  HeadlessFlowState,
  HeadlessThemeConfig,
  SocialLoginOption,
} from "./types";
import {
  decodeCredentialCreationOptions,
  decodeCredentialRequestOptions,
  encodeAssertionForWire,
  encodeAttestationForWire,
} from "./webauthn";

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

export interface HeadlessFlowSnapshot {
  status: HeadlessFlowState | "idle" | "loading";
  flowToken: string | null;
  stepRef: string | null;
  theme: HeadlessThemeConfig | null;
  /** Mirrors `HeadlessAuthEnvelope.passkey_origin_ok` — `true` only shows the passkey affordance. */
  passkeyOriginOk: boolean | null;
  /** Mirrors `HeadlessAuthEnvelope.available_social_logins`. */
  availableSocialLogins: SocialLoginOption[] | null;
  /** Mirrors `HeadlessAuthEnvelope.passwordless_available`. */
  passwordlessAvailable: boolean | null;
  data: Record<string, unknown>;
  error: JummonAuthError | null;
  user: JummonUser | null;
}

const IDLE_SNAPSHOT: HeadlessFlowSnapshot = {
  status: "idle",
  flowToken: null,
  stepRef: null,
  theme: null,
  passkeyOriginOk: null,
  availableSocialLogins: null,
  passwordlessAvailable: null,
  data: {},
  error: null,
  user: null,
};

/**
 * The multi-step entrypoint for `mode: "headless"`. `HeadlessEngine`'s
 * `signIn()` cannot express this (a single call can't model
 * `submitPassword` → maybe `needs_mfa` → `submitMfaCode` → `authenticated`);
 * this object is the real surface, obtained via
 * `createJummonAuth({ ...options, mode: "headless" }).startAuthFlow()`.
 */
export interface HeadlessAuthFlow {
  readonly state: HeadlessFlowSnapshot;
  start(): Promise<HeadlessFlowSnapshot>;
  submitPassword(username: string, password: string): Promise<HeadlessFlowSnapshot>;
  /** Two-phase passkey login: submits `{username}`, then immediately resolves `navigator.credentials.get()` and submits the assertion — no second click. */
  startPasskeyLogin(username: string): Promise<HeadlessFlowSnapshot>;
  /** Enrolls a new passkey during a `fido-registration` required action — resolves `navigator.credentials.create()` against the current step's challenge. */
  registerPasskey(): Promise<HeadlessFlowSnapshot>;
  /** Full-page redirect to the provider only — never an iframe/WebView. */
  startSocialLogin(provider: string): Promise<HeadlessFlowSnapshot>;
  submitMfaCode(code: string): Promise<HeadlessFlowSnapshot>;
  /** Generic escape hatch for any required-action step ref (`terms-agreement`, `confirm-phone`, …) so a new ref doesn't need an SDK major version. */
  submitRequiredAction(ref: string, data: Record<string, unknown>): Promise<HeadlessFlowSnapshot>;
  /** Re-fetches the current server-side state by flow_token. */
  poll(): Promise<HeadlessFlowSnapshot>;
  /**
   * Resumes a flow after a full-page social-provider redirect round trip
   * (wire-contract-v1.md §7.3). Call on mount of the page `redirectUri`
   * points at — reads the persisted `sessionStorage` entry + the current
   * page's `code`/`state`/`auth_resume` query params, verifies the OIDC
   * `state` against the value stored before the redirect (CSRF guard,
   * `state_mismatch` on mismatch), and either completes the PKCE exchange
   * directly or falls back to `poll()` if another step remains.
   */
  resume(): Promise<HeadlessFlowSnapshot>;
  onStateChange(cb: (snapshot: HeadlessFlowSnapshot) => void): () => void;
  dispose(): void;
}

/**
 * Package-private hand-off `HeadlessEngine` implements. On the terminal
 * `authenticated` envelope, this flow object exchanges `{code}` for tokens
 * itself (`../internal/tokenExchange.ts`) and calls back into the engine so
 * the resulting `JummonUser`/`AuthState` is emitted through the exact same
 * `onAuthStateChanged` listeners the 8-method `AuthEngine` surface already
 * defines — the point where `HeadlessEngine` and `RedirectEngine` converge
 * on identical behavior.
 */
export interface HeadlessSessionSink {
  completeSignIn(tokens: {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in?: number;
  }): JummonUser;
}

export function createHeadlessAuthFlow(options: JummonAuthOptions, sink: HeadlessSessionSink): HeadlessAuthFlow {
  return new HeadlessAuthFlowImpl(options, sink);
}

class HeadlessAuthFlowImpl implements HeadlessAuthFlow {
  private readonly transport: HeadlessTransport;
  private readonly tenant: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly issuerHost: string;
  private readonly scopes: string[];
  private readonly listeners = new Set<(snapshot: HeadlessFlowSnapshot) => void>();

  private snapshot: HeadlessFlowSnapshot = IDLE_SNAPSHOT;
  private codeVerifier: string | null = null;
  /** The `state` param sent at `start()` (`SigninState.id`) — round-tripped by the social hop, re-verified in `resume()`. */
  private oidcState: string | null = null;
  /**
   * Single-flight guard (double-click / React StrictMode double-invoke):
   * concurrent calls to any network-issuing method share the same in-flight
   * promise instead of firing a duplicate request against the same
   * flow_token.
   */
  private inFlight: Promise<HeadlessFlowSnapshot> | null = null;

  constructor(options: JummonAuthOptions, private readonly sink: HeadlessSessionSink) {
    if (typeof window === "undefined") {
      throw new JummonAuthError(
        "ssr_unsupported",
        "startAuthFlow() must run in a browser context (window is undefined).",
      );
    }
    this.tenant = options.tenant;
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.issuerHost = options.issuerHost ?? DEFAULT_ISSUER_HOST;
    this.scopes = options.scopes ?? DEFAULT_SCOPES;
    this.transport = new HeadlessTransport({
      tenant: this.tenant,
      clientId: this.clientId,
      issuerHost: this.issuerHost,
    });
  }

  get state(): HeadlessFlowSnapshot {
    return this.snapshot;
  }

  onStateChange(cb: (snapshot: HeadlessFlowSnapshot) => void): () => void {
    this.listeners.add(cb);
    cb(this.snapshot);
    return () => {
      this.listeners.delete(cb);
    };
  }

  dispose(): void {
    clearStoredFlow(this.tenant, this.clientId);
    this.listeners.clear();
  }

  start(): Promise<HeadlessFlowSnapshot> {
    return this.runExclusive(() => this.doStart());
  }

  submitPassword(username: string, password: string): Promise<HeadlessFlowSnapshot> {
    return this.submit({ username, password });
  }

  async startPasskeyLogin(username: string): Promise<HeadlessFlowSnapshot> {
    if (this.snapshot.passkeyOriginOk !== true) {
      return this.applyError(
        new JummonAuthError(
          "passkey_origin_unsupported",
          "Passkeys aren't set up for this app yet — this.state.passkeyOriginOk must be true before calling startPasskeyLogin().",
        ),
      );
    }

    const phase1 = await this.submit({ username });
    if (phase1.status !== "needs_passkey_assertion") {
      return phase1;
    }

    const optionsB64 = phase1.data.fido_login_options as string | undefined;
    if (!optionsB64) {
      return this.applyError(passkeyFailedError());
    }

    let assertion: PublicKeyCredential | null;
    try {
      assertion = (await navigator.credentials.get({
        publicKey: decodeCredentialRequestOptions(optionsB64),
      })) as PublicKeyCredential | null;
    } catch (err) {
      return this.applyError(passkeyFailedError(err));
    }
    if (!assertion) {
      return this.applyError(passkeyFailedError());
    }

    return this.submit({ username, fido_login_response: encodeAssertionForWire(assertion) });
  }

  async registerPasskey(): Promise<HeadlessFlowSnapshot> {
    const optionsB64 = this.snapshot.data.fido_registration_options as string | undefined;
    if (!optionsB64) {
      return this.applyError(
        new JummonAuthError(
          "passkey_failed",
          "No passkey registration challenge is available for the current step.",
        ),
      );
    }

    let credential: PublicKeyCredential | null;
    try {
      credential = (await navigator.credentials.create({
        publicKey: decodeCredentialCreationOptions(optionsB64),
      })) as PublicKeyCredential | null;
    } catch (err) {
      return this.applyError(passkeyFailedError(err));
    }
    if (!credential) {
      return this.applyError(passkeyFailedError());
    }

    return this.submit({ fido_registration_response: encodeAttestationForWire(credential) });
  }

  startSocialLogin(provider: string): Promise<HeadlessFlowSnapshot> {
    // The persist-then-navigate sequence lives centrally in applyEnvelope's
    // `needs_redirect` branch (also reached for legacy-SSO redirects
    // returned from submitRequiredAction) — never an in-app iframe/WebView.
    return this.submit({ social_login: provider });
  }

  submitMfaCode(code: string): Promise<HeadlessFlowSnapshot> {
    return this.submit({ code });
  }

  submitRequiredAction(ref: string, data: Record<string, unknown>): Promise<HeadlessFlowSnapshot> {
    return this.submit({ step_ref: ref, ...data });
  }

  poll(): Promise<HeadlessFlowSnapshot> {
    return this.runExclusive(() => this.doPoll());
  }

  resume(): Promise<HeadlessFlowSnapshot> {
    return this.runExclusive(() => this.doResume());
  }

  private submit(body: Record<string, unknown>): Promise<HeadlessFlowSnapshot> {
    return this.runExclusive(() => this.doSubmit(body));
  }

  /**
   * Ensures only one network-issuing operation is in flight at a time — a
   * second call while one is pending returns the SAME promise rather than
   * firing a duplicate request (blocker: double-click / React StrictMode).
   * Real integrator code always awaits one call before issuing the next, so
   * collapsing a genuinely out-of-order call onto the in-flight promise is
   * the safe default here.
   */
  private runExclusive(op: () => Promise<HeadlessFlowSnapshot>): Promise<HeadlessFlowSnapshot> {
    if (this.inFlight) {
      return this.inFlight;
    }
    const promise = op().finally(() => {
      if (this.inFlight === promise) {
        this.inFlight = null;
      }
    });
    this.inFlight = promise;
    return promise;
  }

  private async doStart(): Promise<HeadlessFlowSnapshot> {
    this.emit({ ...IDLE_SNAPSHOT, status: "loading" });

    const signinState = await SigninState.create({
      authority: buildAuthority(this.tenant, this.issuerHost),
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: this.scopes.join(" "),
      code_verifier: true,
      nonce: generateNonce(),
    });
    this.codeVerifier = signinState.code_verifier ?? null;
    this.oidcState = signinState.id;

    if (!signinState.code_challenge || !this.codeVerifier) {
      return this.applyError(
        new JummonAuthError("unknown", "Failed to generate a PKCE code_verifier/code_challenge pair."),
      );
    }

    try {
      const envelope = await this.transport.start({
        redirect_uri: this.redirectUri,
        code_challenge: signinState.code_challenge,
        code_challenge_method: "S256",
        // SDK MUST always send `state` — needed for resume()'s CSRF check.
        state: this.oidcState,
        nonce: signinState.nonce ?? undefined,
        // Singular, space-delimited — NOT `scopes: string[]`. This is what
        // gets `offline_access` (and thus a refresh_token) to the backend;
        // `authorize.ts`'s `input.scope || 'openid'` never read the old
        // array field at all.
        scope: this.scopes.join(" "),
      });
      // Persisted defensively on every successful start() (covers a tab
      // reload/close-reopen mid-flow, not just the social-redirect path).
      this.persistCurrentFlow(envelope.flow_token);
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  private async doSubmit(body: Record<string, unknown>): Promise<HeadlessFlowSnapshot> {
    if (!this.snapshot.flowToken) {
      return this.noFlowTokenError("submitting a step");
    }
    this.emit({ ...this.snapshot, status: "loading" });
    try {
      const envelope = await this.transport.submit(this.snapshot.flowToken, body);
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  private async doPoll(): Promise<HeadlessFlowSnapshot> {
    if (!this.snapshot.flowToken) {
      return this.noFlowTokenError("polling");
    }
    try {
      const envelope = await this.transport.poll(this.snapshot.flowToken);
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  /** wire-contract-v1.md §7.3. */
  private async doResume(): Promise<HeadlessFlowSnapshot> {
    const stored = readStoredFlow(this.tenant, this.clientId);
    if (!stored) {
      return this.applyError(
        new JummonAuthError(
          "flow_not_started",
          "resume() called with no pending headless auth flow in this browser tab.",
        ),
      );
    }
    this.codeVerifier = stored.codeVerifier;
    this.oidcState = stored.oidcState;

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const authResume = params.get("auth_resume");
    // Never leave code/state/auth_resume in the visible URL/history.
    stripAuthParamsFromUrl();

    if (code && state) {
      if (state !== stored.oidcState) {
        clearStoredFlow(this.tenant, this.clientId);
        return this.applyError(
          new JummonAuthError(
            "state_mismatch",
            "OIDC state returned by the social provider hop did not match the stored value.",
          ),
        );
      }
      clearStoredFlow(this.tenant, this.clientId);
      // completeAuthenticated() already does the PKCE exchange via
      // this.codeVerifier — same call RedirectEngine.signInCallback makes.
      return this.completeAuthenticated({
        flow_token: stored.flowToken,
        status: "authenticated",
        current_step: null,
        data: {},
        code,
        oidc_state: state,
      });
    }

    if (authResume) {
      // Social hop completed but another step remains (e.g. MFA required
      // even after social). JS is alive again — fall back to the normal
      // JSON poll() path.
      this.snapshot = { ...IDLE_SNAPSHOT, flowToken: stored.flowToken };
      return this.doPoll();
    }

    clearStoredFlow(this.tenant, this.clientId);
    return this.applyError(
      new JummonAuthError(
        "flow_not_started",
        "resume() called on a page with neither an OIDC code nor an auth_resume marker.",
      ),
    );
  }

  private noFlowTokenError(action: string): HeadlessFlowSnapshot {
    return this.applyError(
      new JummonAuthError("flow_not_started", `Call start() before ${action} — no flow_token yet.`),
    );
  }

  private persistCurrentFlow(flowToken: string): void {
    if (!this.codeVerifier || !this.oidcState) {
      // Shouldn't happen once start() has succeeded — defensive no-op.
      return;
    }
    persistFlow({
      flowToken,
      codeVerifier: this.codeVerifier,
      oidcState: this.oidcState,
      tenant: this.tenant,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      issuerHost: this.issuerHost,
      savedAt: Date.now(),
    });
  }

  private async applyEnvelope(envelope: HeadlessAuthEnvelope): Promise<HeadlessFlowSnapshot> {
    if (envelope.status === "authenticated") {
      return this.completeAuthenticated(envelope);
    }

    if (envelope.status === "unknown") {
      // Defensive fallback — session has no step and isn't authenticated.
      // Should not happen in steady state; never silently no-op.
      return this.applyError(
        new JummonAuthError(
          "unknown",
          "Auth API returned an unrecognized flow status; the session has no active step.",
        ),
      );
    }

    if (envelope.status === "needs_redirect") {
      const redirectUrl = typeof envelope.data?.redirect_url === "string" ? envelope.data.redirect_url : undefined;
      const next: HeadlessFlowSnapshot = {
        status: "needs_social_redirect",
        flowToken: envelope.flow_token,
        stepRef: null,
        theme: envelope.theme ?? this.snapshot.theme,
        passkeyOriginOk: envelope.passkey_origin_ok ?? this.snapshot.passkeyOriginOk,
        availableSocialLogins: envelope.available_social_logins ?? this.snapshot.availableSocialLogins,
        passwordlessAvailable: envelope.passwordless_available ?? this.snapshot.passwordlessAvailable,
        data: envelope.data ?? {},
        error: null,
        user: null,
      };
      if (redirectUrl) {
        // Persist right before navigating away — the JS realm (this
        // instance, this.codeVerifier) is gone the moment assign() runs.
        this.persistCurrentFlow(envelope.flow_token);
      }
      this.emit(next);
      if (redirectUrl) {
        // Full-page navigation to the provider — never an in-app iframe or
        // WebView (Google and others block embedded-WebView OAuth outright).
        window.location.assign(redirectUrl);
      }
      return next;
    }

    // status === "needs_input"
    const next: HeadlessFlowSnapshot = {
      status: deriveState(envelope.current_step, envelope.data ?? {}),
      flowToken: envelope.flow_token,
      stepRef: envelope.current_step?.ref ?? null,
      theme: envelope.theme ?? this.snapshot.theme,
      passkeyOriginOk: envelope.passkey_origin_ok ?? this.snapshot.passkeyOriginOk,
      availableSocialLogins: envelope.available_social_logins ?? this.snapshot.availableSocialLogins,
      passwordlessAvailable: envelope.passwordless_available ?? this.snapshot.passwordlessAvailable,
      data: envelope.data ?? {},
      error: null,
      user: null,
    };
    this.emit(next);
    return next;
  }

  private async completeAuthenticated(envelope: HeadlessAuthEnvelope): Promise<HeadlessFlowSnapshot> {
    if (!envelope.code) {
      return this.applyError(
        new JummonAuthError("unknown", "Auth API returned `authenticated` with no authorization code."),
      );
    }
    if (!this.codeVerifier) {
      // Distinct from "no code at all" above: we DID get a code, but this JS
      // realm lost the PKCE verifier — most likely a non-social page reload
      // mid-flow (the social-redirect path recovers via resume(), which
      // restores codeVerifier from sessionStorage before ever reaching here).
      return this.applyError(
        new JummonAuthError(
          "pkce_verifier_lost",
          "Received an authorization code but no PKCE code_verifier is available in this browser tab. " +
            "If this followed a social-provider redirect, call resume() on page load instead of relying " +
            "on the in-memory flow; otherwise restart with start().",
        ),
      );
    }
    try {
      const tokens = await exchangeAuthorizationCode({
        tenant: this.tenant,
        issuerHost: this.issuerHost,
        clientId: this.clientId,
        redirectUri: this.redirectUri,
        code: envelope.code,
        codeVerifier: this.codeVerifier,
      });
      const user = this.sink.completeSignIn(tokens);
      clearStoredFlow(this.tenant, this.clientId);
      const next: HeadlessFlowSnapshot = {
        status: "authenticated",
        flowToken: envelope.flow_token,
        stepRef: null,
        theme: envelope.theme ?? this.snapshot.theme,
        passkeyOriginOk: this.snapshot.passkeyOriginOk,
        availableSocialLogins: null,
        passwordlessAvailable: null,
        data: {},
        error: null,
        user,
      };
      this.emit(next);
      return next;
    } catch (err) {
      return this.applyError(err);
    }
  }

  private applyError(err: unknown): HeadlessFlowSnapshot {
    const authError =
      err instanceof JummonAuthError
        ? err
        : new JummonAuthError("unknown", err instanceof Error ? err.message : "Unknown error.", err);
    const next: HeadlessFlowSnapshot = { ...this.snapshot, status: "error", error: authError, data: {} };
    this.emit(next);
    return next;
  }

  private emit(next: HeadlessFlowSnapshot): void {
    this.snapshot = next;
    for (const listener of this.listeners) {
      listener(next);
    }
  }
}

function passkeyFailedError(cause?: unknown): JummonAuthError {
  return new JummonAuthError(
    "passkey_failed",
    "We couldn't complete the passkey sign-in. Try again or use your password.",
    cause,
  );
}

function generateNonce(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}
