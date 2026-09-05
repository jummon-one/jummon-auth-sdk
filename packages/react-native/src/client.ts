import {
  HeadlessAuthFlowCore,
  HeadlessEngineCore,
  JummonAuthError,
  beginOtpEnrollment,
  confirmOtpEnrollment,
  enrollPasskey,
  setPasswordSelfService,
  DEFAULT_API_HOST,
  type AuthState,
  type HeadlessAuthFlow,
  type JummonAuthOptions,
  type JummonUser,
  type OtpEnrollmentChallenge,
  type PasskeyRegistrationResult,
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
  };
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
