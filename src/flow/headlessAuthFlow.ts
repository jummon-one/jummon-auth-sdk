import { SigninState } from "oidc-client-ts";
import { buildAuthority, DEFAULT_ISSUER_HOST } from "../discovery";
import { JummonAuthError } from "../errors";
import { exchangeAuthorizationCode } from "../internal/tokenExchange";
import type { JummonAuthOptions, JummonUser } from "../types";
import { HeadlessTransport } from "./transport";
import type { HeadlessAuthEnvelope, HeadlessFlowState, HeadlessThemeConfig } from "./types";
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
  /** Mirrors `HeadlessAuthEnvelope.passkey_origin_ok` — see `ux-spec-wave1.md` §4's visibility rules (`true` only shows the passkey affordance). */
  passkeyOriginOk: boolean | null;
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
  data: {},
  error: null,
  user: null,
};

/**
 * The multi-step entrypoint for `mode: "headless"` — `system-design.md` §6
 * / `implementation-plan.md` §8's `HeadlessAuthFlow`. `HeadlessEngine`'s
 * `signIn()` cannot express this (a single call can't model
 * `submitPassword` → maybe `needs_mfa` → `submitMfaCode` → `authenticated`);
 * this object is the real surface, obtained via
 * `createJummonAuth({ ...options, mode: "headless" }).startAuthFlow()`.
 */
export interface HeadlessAuthFlow {
  readonly state: HeadlessFlowSnapshot;
  start(): Promise<HeadlessFlowSnapshot>;
  submitPassword(username: string, password: string): Promise<HeadlessFlowSnapshot>;
  /** Two-phase passkey login (`system-design.md` §1.2/§7.2): submits `{username}`, then immediately resolves `navigator.credentials.get()` and submits the assertion — no second click. */
  startPasskeyLogin(username: string): Promise<HeadlessFlowSnapshot>;
  /** Enrolls a new passkey during a `fido-registration` required action — resolves `navigator.credentials.create()` against the current step's challenge. */
  registerPasskey(): Promise<HeadlessFlowSnapshot>;
  /** Full-page redirect to the provider only — never an iframe/WebView (`security-note.md` "Social redirect: system browser only"). */
  startSocialLogin(provider: string): Promise<HeadlessFlowSnapshot>;
  submitMfaCode(code: string): Promise<HeadlessFlowSnapshot>;
  /** Generic escape hatch for any required-action step ref (`terms-agreement`, `confirm-phone`, …) so a new ref doesn't need an SDK major version. */
  submitRequiredAction(ref: string, data: Record<string, unknown>): Promise<HeadlessFlowSnapshot>;
  /** Re-fetches the current server-side state by flow_token — needed after a full-page social-redirect round trip (`system-design.md` §7.3). */
  poll(): Promise<HeadlessFlowSnapshot>;
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
 * on identical behavior (`implementation-plan.md` §8 item 4).
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
    this.listeners.clear();
  }

  async start(): Promise<HeadlessFlowSnapshot> {
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
        state: signinState.id,
        nonce: signinState.nonce ?? "",
        scopes: this.scopes,
      });
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  submitPassword(username: string, password: string): Promise<HeadlessFlowSnapshot> {
    return this.submit({ username, password });
  }

  async startPasskeyLogin(username: string): Promise<HeadlessFlowSnapshot> {
    if (this.snapshot.passkeyOriginOk !== true) {
      throw new JummonAuthError(
        "passkey_origin_unsupported",
        "Passkeys aren't set up for this app yet — this.state.passkeyOriginOk must be true before calling startPasskeyLogin().",
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
      throw new JummonAuthError(
        "passkey_failed",
        "No passkey registration challenge is available for the current step.",
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

  async startSocialLogin(provider: string): Promise<HeadlessFlowSnapshot> {
    const next = await this.submit({ social_login: provider });
    if (next.status === "needs_social_redirect") {
      const redirectUrl = next.data.redirect_url as string | undefined;
      if (redirectUrl) {
        // Full-page navigation to the provider — never an in-app iframe or
        // WebView (`security-note.md` "Social redirect: system browser
        // only"; Google and others block embedded-WebView OAuth outright).
        window.location.assign(redirectUrl);
      }
    }
    return next;
  }

  submitMfaCode(code: string): Promise<HeadlessFlowSnapshot> {
    return this.submit({ code });
  }

  submitRequiredAction(ref: string, data: Record<string, unknown>): Promise<HeadlessFlowSnapshot> {
    return this.submit({ step_ref: ref, ...data });
  }

  async poll(): Promise<HeadlessFlowSnapshot> {
    this.requireFlowToken();
    try {
      const envelope = await this.transport.poll(this.snapshot.flowToken as string);
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  private async submit(body: Record<string, unknown>): Promise<HeadlessFlowSnapshot> {
    this.requireFlowToken();
    this.emit({ ...this.snapshot, status: "loading" });
    try {
      const envelope = await this.transport.submit(this.snapshot.flowToken as string, body);
      return await this.applyEnvelope(envelope);
    } catch (err) {
      return this.applyError(err);
    }
  }

  private requireFlowToken(): void {
    if (!this.snapshot.flowToken) {
      throw new JummonAuthError(
        "flow_not_started",
        "Call start() before submitting a step — no flow_token yet.",
      );
    }
  }

  private async applyEnvelope(envelope: HeadlessAuthEnvelope): Promise<HeadlessFlowSnapshot> {
    if (envelope.state === "authenticated") {
      return this.completeAuthenticated(envelope);
    }
    const next: HeadlessFlowSnapshot = {
      status: envelope.state,
      flowToken: envelope.flow_token,
      stepRef: envelope.step_ref,
      theme: envelope.theme ?? this.snapshot.theme,
      passkeyOriginOk: envelope.passkey_origin_ok ?? this.snapshot.passkeyOriginOk,
      data: envelope.data ?? {},
      error: null,
      user: null,
    };
    this.emit(next);
    return next;
  }

  private async completeAuthenticated(envelope: HeadlessAuthEnvelope): Promise<HeadlessFlowSnapshot> {
    if (!envelope.code || !this.codeVerifier) {
      return this.applyError(
        new JummonAuthError("unknown", "Auth API returned `authenticated` with no authorization code."),
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
      const next: HeadlessFlowSnapshot = {
        status: "authenticated",
        flowToken: envelope.flow_token,
        stepRef: null,
        theme: envelope.theme ?? this.snapshot.theme,
        passkeyOriginOk: this.snapshot.passkeyOriginOk,
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
