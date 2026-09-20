import {
  HeadlessAuthFlowCore,
  HeadlessEngineCore,
  HeadlessRecoveryFlowCore,
  JummonAuthError,
  beginOtpEnrollment,
  confirmOtpEnrollment,
  enrollPasskey,
  generateRecoveryCodesSelf,
  getRecoveryCodesSelfStatus,
  setPasswordSelfService,
  DEFAULT_API_HOST,
  type AuthState,
  type HeadlessAuthFlow,
  type HeadlessRecoveryFlowOptions,
  type JummonAuthOptions,
  type JummonUser,
  type OtpEnrollmentChallenge,
  type PasskeyRegistrationResult,
  type PlatformWebAuthn,
  type RecoveryCodesGenerated,
  type SignInOptions,
  type SignOutOptions,
} from "@jummon/auth/core";
import { createReactNativePlatformAdapters, type ReactNativePlatformDeps } from "./adapters";

/**
 * RN never has a "redirect to hosted login" mode — there is no addressable
 * URL bar to navigate away from and back to (`ROADMAP.md`'s Phase 2 item 5:
 * "RN never touches RedirectEngine"). `mode`/`tokenStorage` are dropped from
 * the options this package accepts: the client this factory returns is
 * ALWAYS headless, and storage is always the composite AsyncStorage/
 * SecureStore adapter (`./adapters/storage.ts`) — there is no "session vs.
 * local vs. memory" choice to make on a mobile app process.
 */
export type ReactNativeAuthOptions = Omit<JummonAuthOptions, "mode" | "tokenStorage">;

/**
 * The RN equivalent of `@jummon/auth`'s `HeadlessJummonAuthClient` — same
 * method surface (minus the two methods that only make sense with the
 * option to choose redirect mode), so it satisfies `@jummon/auth/react`'s
 * `JummonAuthProviderProps`'s `{ client }` shape unchanged:
 *
 * ```tsx
 * import { JummonAuthProvider, useHeadlessAuthFlow } from "@jummon/auth/react";
 * import { createJummonAuthReactNative } from "@jummon/auth-react-native";
 *
 * const client = createJummonAuthReactNative(options, nativeDeps);
 * <JummonAuthProvider client={client}>...</JummonAuthProvider>
 * ```
 *
 * `signIn`/`signInCallback` are kept (both throw `headless_requires_flow`,
 * delegated straight to `HeadlessEngineCore`) purely for that structural
 * compatibility with `@jummon/auth`'s `JummonAuthClient`/
 * `HeadlessJummonAuthClient` union — an RN app should never call them
 * directly, `startAuthFlow()` is the only real entrypoint.
 */
export interface JummonAuthReactNativeClient {
  startAuthFlow(): HeadlessAuthFlow;
  signIn(opts?: SignInOptions): Promise<void>;
  signInCallback(url?: string): Promise<JummonUser>;
  signOut(opts?: SignOutOptions): Promise<void>;
  getUser(): Promise<JummonUser | null>;
  getAccessToken(): Promise<string | null>;
  isAuthenticated(): Promise<boolean>;
  onAuthStateChanged(cb: (state: AuthState) => void): () => void;
  dispose(): void;
  /** Same standalone, post-login enrollment as the web client's `registerPasskey()` — requires `nativeDeps.passkey` to have been supplied to `createReactNativePlatformAdapters()`, or this throws `passkey_origin_unsupported`. */
  registerPasskey(name?: string): Promise<PasskeyRegistrationResult>;
  setPassword(password: string, confirmationPassword: string): Promise<void>;
  beginOtpEnroll(): Promise<OtpEnrollmentChallenge>;
  confirmOtpEnroll(otp: string): Promise<void>;
  /** Same standalone, post-login backup-code self-service as the web client's `generateRecoveryCodes()`/`hasUnredeemedRecoveryCodes()` — mobile parity item #5. ALWAYS replaces the caller's whole set (never "add codes"); see `@jummon/auth/core`'s `generateRecoveryCodesSelf` doc comment. */
  generateRecoveryCodes(): Promise<RecoveryCodesGenerated>;
  hasUnredeemedRecoveryCodes(): Promise<boolean>;
  /**
   * First-class RN entrypoint into the credential-type-aware account-
   * recovery journey (mobile parity item #4) — wires `HeadlessRecoveryFlowCore`
   * with this client's own RN adapters (`crypto` for the PKCE device-
   * binding pair, threat model §3.5 R13/R17; `webauthn` for {@link
   * HeadlessRecoveryFlowCore.enrollPasskey}, which throws
   * `passkey_origin_unsupported` at call time if `nativeDeps.passkey` was
   * never supplied — same posture as {@link registerPasskey}, never a
   * silent fallback to a browser-only WebAuthn implementation that would
   * crash on `navigator`).
   *
   * `options.baseHost` is still caller-supplied (unresolved
   * infra/gateway-routing question, `HeadlessRecoveryFlowCore`'s own doc
   * comment) — this method does not default it.
   *
   * Pair with `@jummon/auth-react-native`'s `createRecoveryReturnListener`
   * (`./adapters/navigation.ts`) for the R12 App-Link/Universal-Link-gated
   * deep-link return leg, if the tenant's recovery journey uses one
   * (today's `recover-account-credential-aware` journey drives entirely
   * through in-app step submission — no deep link leg exists yet, see that
   * function's own doc comment).
   */
  startRecoveryFlow(options: HeadlessRecoveryFlowOptions): HeadlessRecoveryFlowCore;
}

/**
 * The RN package's entrypoint — constructs one `HeadlessEngineCore` (session/
 * tokens) with RN adapters and hands out a fresh `HeadlessAuthFlowCore` per
 * `startAuthFlow()` call, exactly mirroring `@jummon/auth`'s
 * `createJummonAuth({ ...options, mode: "headless" })` /
 * `HeadlessEngine`/`createHeadlessAuthFlow()`
 * (`../../src/engines/headlessEngine.ts`, `../../src/flow/headlessAuthFlow.ts`)
 * — just wired to `./adapters` instead of `../../src/platform/browser/*`.
 * Never imports anything from `@jummon/auth`'s main entry (`.`) or
 * `platform/browser/*` — only from `@jummon/auth/core`, so this package
 * never touches `window`/`navigator`/`oidc-client-ts`.
 */
export function createJummonAuthReactNative(
  options: ReactNativeAuthOptions,
  nativeDeps: ReactNativePlatformDeps,
): JummonAuthReactNativeClient {
  validateOptions(options);
  const adapters = createReactNativePlatformAdapters(nativeDeps);
  const engine = new HeadlessEngineCore(options as JummonAuthOptions, adapters);

  return {
    startAuthFlow: () => new HeadlessAuthFlowCore(options as JummonAuthOptions, engine, adapters),
    signIn: (opts) => engine.signIn(opts),
    signInCallback: (url) => engine.signInCallback(url),
    signOut: (opts) => engine.signOut(opts),
    getUser: () => engine.getUser(),
    getAccessToken: () => engine.getAccessToken(),
    isAuthenticated: () => engine.isAuthenticated(),
    onAuthStateChanged: (cb) => engine.onAuthStateChanged(cb),
    dispose: () => engine.dispose(),
    registerPasskey: (name) => registerPasskeyViaEngine(engine, options, adapters.webauthn, name),
    setPassword: (password, confirmationPassword) =>
      setPasswordViaEngine(engine, options, password, confirmationPassword),
    beginOtpEnroll: () => beginOtpEnrollViaEngine(engine, options),
    confirmOtpEnroll: (otp) => confirmOtpEnrollViaEngine(engine, options, otp),
    generateRecoveryCodes: () => generateRecoveryCodesViaEngine(engine, options),
    hasUnredeemedRecoveryCodes: () => hasUnredeemedRecoveryCodesViaEngine(engine, options),
    startRecoveryFlow: (recoveryOptions) =>
      new HeadlessRecoveryFlowCore(recoveryOptions, adapters.webauthn ?? unsupportedWebAuthn(), adapters.crypto),
  };
}

/**
 * A `PlatformWebAuthn` that never touches `navigator` — safe to always
 * construct (unlike falling through to `HeadlessRecoveryFlowCore`'s own
 * `browserWebAuthn` default, which would crash reaching for `navigator.
 * credentials` on RN). Only `enrollPasskey()`'s `create()`/`get()` calls
 * ever reach this — every other recovery step (`init`/`current`/`submit`/
 * `redeemRecoveryCode`/`confirmPartial`) never touches `webauthn` at all,
 * so a tenant/app that never uses passkey-recovery is unaffected by not
 * configuring `nativeDeps.passkey`.
 */
function unsupportedWebAuthn(): PlatformWebAuthn {
  const fail = (): never => {
    throw new JummonAuthError(
      "passkey_origin_unsupported",
      "startRecoveryFlow().enrollPasskey() requires a `passkey` adapter — pass `passkey: createReactNativeWebAuthn(...)`-worthy " +
        "deps (a react-native-passkey-shaped object) to createReactNativePlatformAdapters()/createJummonAuthReactNative().",
    );
  };
  return { isSupported: () => false, create: () => fail(), get: () => fail() };
}

async function generateRecoveryCodesViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
): Promise<RecoveryCodesGenerated> {
  const accessToken = await requireAccessToken(engine, "generateRecoveryCodes()");
  return generateRecoveryCodesSelf(accessToken, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function hasUnredeemedRecoveryCodesViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
): Promise<boolean> {
  const accessToken = await requireAccessToken(engine, "hasUnredeemedRecoveryCodes()");
  return getRecoveryCodesSelfStatus(accessToken, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function registerPasskeyViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
  webauthn: ReturnType<typeof createReactNativePlatformAdapters>["webauthn"],
  name?: string,
): Promise<PasskeyRegistrationResult> {
  const accessToken = await requireAccessToken(engine, "registerPasskey()");
  if (!webauthn) {
    throw new JummonAuthError(
      "passkey_origin_unsupported",
      "registerPasskey() requires a `passkey` adapter — pass `passkey: createReactNativeWebAuthn(...)`-worthy " +
        "deps (a react-native-passkey-shaped object) to createReactNativePlatformAdapters()/createJummonAuthReactNative().",
    );
  }
  return enrollPasskey(accessToken, name, { apiHost: options.apiHost ?? DEFAULT_API_HOST }, webauthn);
}

async function setPasswordViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
  password: string,
  confirmationPassword: string,
): Promise<void> {
  const accessToken = await requireAccessToken(engine, "setPassword()");
  return setPasswordSelfService(accessToken, password, confirmationPassword, {
    apiHost: options.apiHost ?? DEFAULT_API_HOST,
  });
}

async function beginOtpEnrollViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
): Promise<OtpEnrollmentChallenge> {
  const accessToken = await requireAccessToken(engine, "beginOtpEnroll()");
  return beginOtpEnrollment(accessToken, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function confirmOtpEnrollViaEngine(
  engine: HeadlessEngineCore,
  options: ReactNativeAuthOptions,
  otp: string,
): Promise<void> {
  const accessToken = await requireAccessToken(engine, "confirmOtpEnroll()");
  return confirmOtpEnrollment(accessToken, otp, { apiHost: options.apiHost ?? DEFAULT_API_HOST });
}

async function requireAccessToken(engine: HeadlessEngineCore, action: string): Promise<string> {
  const accessToken = await engine.getAccessToken();
  if (!accessToken) {
    throw new JummonAuthError(
      "not_authenticated",
      `${action} requires a signed-in user — call it after getUser()/isAuthenticated() confirms an active session.`,
    );
  }
  return accessToken;
}

function validateOptions(options: ReactNativeAuthOptions): void {
  const missing = (["tenant", "clientId", "redirectUri"] as const).filter((key) => !options[key]);
  if (missing.length > 0) {
    throw new JummonAuthError(
      "invalid_options",
      `createJummonAuthReactNative: missing required option(s): ${missing.join(", ")}.`,
    );
  }
}
