import * as React from "react";
import { createJummonAuth, type HeadlessJummonAuthClient, type JummonAuthClient } from "./client";
import type { HeadlessAuthFlow, HeadlessFlowSnapshot } from "./flow/headlessAuthFlow";
import type { AuthState, JummonAuthOptions, JummonUser, SignInOptions, SignOutOptions } from "./types";

function isHeadlessClient(client: JummonAuthClient | HeadlessJummonAuthClient): client is HeadlessJummonAuthClient {
  return typeof (client as Partial<HeadlessJummonAuthClient>).startAuthFlow === "function";
}

export interface JummonAuthContextValue {
  /** The underlying framework-agnostic client, for anything not covered by the hook helpers below. */
  client: JummonAuthClient | HeadlessJummonAuthClient;
  state: AuthState;
  /** Convenience: `state.status === "loading"`. */
  isLoading: boolean;
  /** Convenience: `state.status === "authenticated"`. */
  isAuthenticated: boolean;
  /** Convenience: `state.status === "authenticated" ? state.user : null`. */
  user: JummonUser | null;
  /** `true` when the provider's client is `mode: "headless"` — gates `startAuthFlow` below and is what `useHeadlessAuthFlow()` checks before throwing. */
  isHeadless: boolean;
  /**
   * The multi-step in-app login entrypoint (`mode: "headless"` only) —
   * `undefined` in `redirect` mode, same shape `HeadlessJummonAuthClient`
   * exposes at the client level (`./client.ts`). This is the fix for the
   * headless-binding gap: pre-refactor, `useJummonAuth()` had no way to
   * reach `startAuthFlow()` at all, so a headless React app had to bypass
   * this hook and call `createJummonAuth()` a second time itself. Prefer
   * `useHeadlessAuthFlow()` for a reactive, React-idiomatic wrapper around
   * the object this returns — call this directly only for the rare case
   * that needs the raw `HeadlessAuthFlow` (e.g. holding two concurrent
   * flows, which `useHeadlessAuthFlow()` deliberately does not support).
   */
  startAuthFlow?: () => HeadlessAuthFlow;
  /** v1 (redirect mode): full-page redirect to the hosted login. Throws `headless_requires_flow` in headless mode — use `startAuthFlow()`/`useHeadlessAuthFlow()` instead, same as the underlying client. */
  signIn: (opts?: SignInOptions) => Promise<void>;
  signOut: (opts?: SignOutOptions) => Promise<void>;
  /** Valid access token for calling your API, refreshed silently when expired. Null if signed out. */
  getAccessToken: () => Promise<string | null>;
}

const JummonAuthContext = React.createContext<JummonAuthContextValue | null>(null);

/**
 * Either the options `createJummonAuth()` itself takes (web convenience —
 * unchanged from before this rework), or a pre-built `client` — the seam a
 * platform package (`@jummon/auth-react-native`'s `createJummonAuthReactNative()`)
 * uses to plug its own RN-adapter-backed client into this SAME provider/hook
 * pair instead of forking them. Exactly one of the two shapes applies; passing
 * `client` makes every `JummonAuthOptions` field irrelevant (the client is
 * already fully constructed) — this provider never re-derives options from a
 * client or vice versa.
 */
export type JummonAuthProviderProps =
  | (JummonAuthOptions & { children: React.ReactNode })
  | { client: JummonAuthClient | HeadlessJummonAuthClient; children: React.ReactNode };

function isPreBuiltClientProps(
  props: JummonAuthProviderProps,
): props is { client: JummonAuthClient | HeadlessJummonAuthClient; children: React.ReactNode } {
  return "client" in props && props.client !== undefined;
}

/**
 * Mounts one JummonAuthClient for the lifetime of the app and exposes it +
 * live auth state via context. Options (or the pre-built `client`) are read
 * once, at mount — changing props across renders does not re-create the
 * client; unmount/remount (e.g. keyed by tenant) if you need that.
 */
export function JummonAuthProvider(props: JummonAuthProviderProps): React.ReactElement {
  const { children } = props;
  const propsRef = React.useRef(props);

  const clientRef = React.useRef<JummonAuthClient | HeadlessJummonAuthClient | null>(null);
  if (clientRef.current === null) {
    const initial = propsRef.current;
    clientRef.current = isPreBuiltClientProps(initial)
      ? initial.client
      : createJummonAuth(initial as JummonAuthOptions);
  }
  const client = clientRef.current;
  const headless = isHeadlessClient(client);

  const [state, setState] = React.useState<AuthState>({ status: "loading" });

  React.useEffect(() => {
    const unsubscribe = client.onAuthStateChanged(setState);
    return () => {
      unsubscribe();
    };
  }, [client]);

  React.useEffect(() => {
    return () => {
      client.dispose();
    };
  }, [client]);

  const signIn = React.useCallback((opts?: SignInOptions) => client.signIn(opts), [client]);
  const signOut = React.useCallback((opts?: SignOutOptions) => client.signOut(opts), [client]);
  const getAccessToken = React.useCallback(() => client.getAccessToken(), [client]);
  const startAuthFlow = React.useMemo(
    () => (headless ? () => (client as HeadlessJummonAuthClient).startAuthFlow() : undefined),
    [client, headless],
  );

  const value = React.useMemo<JummonAuthContextValue>(
    () => ({
      client,
      state,
      isLoading: state.status === "loading",
      isAuthenticated: state.status === "authenticated",
      user: state.status === "authenticated" ? state.user : null,
      isHeadless: headless,
      startAuthFlow,
      signIn,
      signOut,
      getAccessToken,
    }),
    [client, state, headless, startAuthFlow, signIn, signOut, getAccessToken],
  );

  return <JummonAuthContext.Provider value={value}>{children}</JummonAuthContext.Provider>;
}

export function useJummonAuth(): JummonAuthContextValue {
  const ctx = React.useContext(JummonAuthContext);
  if (ctx === null) {
    throw new Error("useJummonAuth() must be called from inside a <JummonAuthProvider>.");
  }
  return ctx;
}

/** Shorthand for `useJummonAuth().user`. */
export function useJummonUser(): JummonUser | null {
  return useJummonAuth().user;
}

/**
 * Reactive wrapper around one `HeadlessAuthFlow` (B3 fix — `./ROADMAP.md`'s
 * synthesis item B3): mirrors the raw object's step-machine snapshot as React
 * state and re-exposes every submit-step method so a headless login screen
 * never needs to call `flow.onStateChange()`/`setState` by hand. One flow per
 * mount — call this once at the top of your login screen component, not once
 * per render or per step; the underlying `HeadlessAuthFlow` is created lazily
 * (on first `start()`/`resume()` call, not on mount) so rendering this hook
 * has no side effect until the caller actually kicks off a flow.
 *
 * Works identically whether the provider was built from `JummonAuthOptions`
 * (web) or handed a pre-built RN client via the `client` prop — this hook
 * only talks to `JummonAuthContextValue.startAuthFlow`, never to a platform
 * adapter directly, so it serves both `@jummon/auth` and
 * `@jummon/auth-react-native` unchanged.
 *
 * Throws synchronously if the provider's client isn't `mode: "headless"` —
 * same fail-loud posture as `HeadlessEngineCore.signIn()`'s
 * `headless_requires_flow` (see `./errors.ts`), surfaced here at hook-call
 * time instead of at the first network call.
 */
export interface UseHeadlessAuthFlowResult {
  /** `null` until the first `start()`/`resume()` call resolves its first snapshot. */
  snapshot: HeadlessFlowSnapshot | null;
  start: () => Promise<HeadlessFlowSnapshot>;
  resume: () => Promise<HeadlessFlowSnapshot>;
  poll: () => Promise<HeadlessFlowSnapshot>;
  submitPassword: (username: string, password: string) => Promise<HeadlessFlowSnapshot>;
  setPassword: (password: string, confirmationPassword: string) => Promise<HeadlessFlowSnapshot>;
  startPasskeyLogin: (username: string) => Promise<HeadlessFlowSnapshot>;
  registerPasskey: () => Promise<HeadlessFlowSnapshot>;
  startSocialLogin: (provider: string) => Promise<HeadlessFlowSnapshot>;
  submitMfaCode: (code: string) => Promise<HeadlessFlowSnapshot>;
  confirmMfaSetup: (code: string) => Promise<HeadlessFlowSnapshot>;
  submitTermsAgreement: (
    accepted: boolean,
    opts?: { consentAccepted?: boolean; termsVersion?: string },
  ) => Promise<HeadlessFlowSnapshot>;
  submitDeviceConsent: (accepted: boolean) => Promise<HeadlessFlowSnapshot>;
  submitRequiredAction: (ref: string, data: Record<string, unknown>) => Promise<HeadlessFlowSnapshot>;
}

export function useHeadlessAuthFlow(): UseHeadlessAuthFlowResult {
  const { startAuthFlow, isHeadless } = useJummonAuth();
  if (!isHeadless || !startAuthFlow) {
    throw new Error(
      'useHeadlessAuthFlow() requires a <JummonAuthProvider mode="headless" ...> (or a headless `client` prop) — ' +
        "the current provider is in redirect mode. Use signIn()/useJummonAuth() for a redirect login instead.",
    );
  }

  const flowRef = React.useRef<HeadlessAuthFlow | null>(null);
  const [snapshot, setSnapshot] = React.useState<HeadlessFlowSnapshot | null>(null);

  const getFlow = React.useCallback((): HeadlessAuthFlow => {
    if (flowRef.current === null) {
      flowRef.current = startAuthFlow();
      flowRef.current.onStateChange(setSnapshot);
    }
    return flowRef.current;
  }, [startAuthFlow]);

  React.useEffect(() => {
    return () => {
      flowRef.current?.dispose();
      flowRef.current = null;
    };
  }, []);

  return React.useMemo<UseHeadlessAuthFlowResult>(
    () => ({
      snapshot,
      start: () => getFlow().start(),
      resume: () => getFlow().resume(),
      poll: () => getFlow().poll(),
      submitPassword: (username, password) => getFlow().submitPassword(username, password),
      setPassword: (password, confirmationPassword) => getFlow().setPassword(password, confirmationPassword),
      startPasskeyLogin: (username) => getFlow().startPasskeyLogin(username),
      registerPasskey: () => getFlow().registerPasskey(),
      startSocialLogin: (provider) => getFlow().startSocialLogin(provider),
      submitMfaCode: (code) => getFlow().submitMfaCode(code),
      confirmMfaSetup: (code) => getFlow().confirmMfaSetup(code),
      submitTermsAgreement: (accepted, opts) => getFlow().submitTermsAgreement(accepted, opts),
      submitDeviceConsent: (accepted) => getFlow().submitDeviceConsent(accepted),
      submitRequiredAction: (ref, data) => getFlow().submitRequiredAction(ref, data),
    }),
    [snapshot, getFlow],
  );
}
