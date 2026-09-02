import * as React from "react";
import { createJummonAuth, type JummonAuthClient } from "./client";
import type { AuthState, JummonAuthOptions, JummonUser, SignInOptions, SignOutOptions } from "./types";

export interface JummonAuthContextValue {
  /** The underlying framework-agnostic client, for anything not covered by the hook helpers below. */
  client: JummonAuthClient;
  state: AuthState;
  /** Convenience: `state.status === "loading"`. */
  isLoading: boolean;
  /** Convenience: `state.status === "authenticated"`. */
  isAuthenticated: boolean;
  /** Convenience: `state.status === "authenticated" ? state.user : null`. */
  user: JummonUser | null;
  signIn: (opts?: SignInOptions) => Promise<void>;
  signOut: (opts?: SignOutOptions) => Promise<void>;
  /** Valid access token for calling your API, refreshed silently when expired. Null if signed out. */
  getAccessToken: () => Promise<string | null>;
}

const JummonAuthContext = React.createContext<JummonAuthContextValue | null>(null);

export interface JummonAuthProviderProps extends JummonAuthOptions {
  children: React.ReactNode;
}

/**
 * Mounts one JummonAuthClient for the lifetime of the app and exposes it +
 * live auth state via context. Options are read once, at mount — changing
 * `tenant`/`clientId`/etc. across renders does not re-create the client;
 * unmount/remount (e.g. keyed by tenant) if you need that.
 */
export function JummonAuthProvider(props: JummonAuthProviderProps): React.ReactElement {
  const { children, ...options } = props;
  const optionsRef = React.useRef(options);

  const clientRef = React.useRef<JummonAuthClient | null>(null);
  if (clientRef.current === null) {
    clientRef.current = createJummonAuth(optionsRef.current);
  }
  const client = clientRef.current;

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

  const value = React.useMemo<JummonAuthContextValue>(
    () => ({
      client,
      state,
      isLoading: state.status === "loading",
      isAuthenticated: state.status === "authenticated",
      user: state.status === "authenticated" ? state.user : null,
      signIn,
      signOut,
      getAccessToken,
    }),
    [client, state, signIn, signOut, getAccessToken],
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
