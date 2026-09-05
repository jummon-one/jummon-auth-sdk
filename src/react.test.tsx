import { act, render, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./client", () => ({ createJummonAuth: vi.fn() }));

import { createJummonAuth, type HeadlessJummonAuthClient, type JummonAuthClient } from "./client";
import type { HeadlessAuthFlow, HeadlessFlowSnapshot } from "./flow/headlessAuthFlow";
import { JummonAuthProvider, useHeadlessAuthFlow, useJummonAuth, useJummonUser } from "./react";
import type { AuthState } from "./types";

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
};

function makeRedirectClient(): JummonAuthClient {
  return {
    signIn: vi.fn().mockResolvedValue(undefined),
    signInCallback: vi.fn(),
    signOut: vi.fn().mockResolvedValue(undefined),
    getUser: vi.fn().mockResolvedValue(null),
    getAccessToken: vi.fn().mockResolvedValue(null),
    isAuthenticated: vi.fn().mockResolvedValue(false),
    onAuthStateChanged: vi.fn((cb: (state: AuthState) => void) => {
      cb({ status: "unauthenticated" });
      return () => {};
    }),
    dispose: vi.fn(),
    registerPasskey: vi.fn(),
    setPassword: vi.fn(),
    beginOtpEnroll: vi.fn(),
    confirmOtpEnroll: vi.fn(),
  };
}

function makeFakeFlow(): HeadlessAuthFlow {
  const listeners = new Set<(s: HeadlessFlowSnapshot) => void>();
  const snapshot: HeadlessFlowSnapshot = {
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
  const emit = (next: Partial<HeadlessFlowSnapshot>) => {
    const merged = { ...snapshot, ...next };
    for (const l of listeners) l(merged);
  };
  return {
    get state() {
      return snapshot;
    },
    start: vi.fn().mockImplementation(async () => {
      emit({ status: "needs_credentials", flowToken: "ft-1", stepRef: "username-password-form" });
      return snapshot;
    }),
    submitPassword: vi.fn().mockResolvedValue(snapshot),
    setPassword: vi.fn().mockResolvedValue(snapshot),
    startPasskeyLogin: vi.fn().mockResolvedValue(snapshot),
    registerPasskey: vi.fn().mockResolvedValue(snapshot),
    startSocialLogin: vi.fn().mockResolvedValue(snapshot),
    submitMfaCode: vi.fn().mockResolvedValue(snapshot),
    confirmMfaSetup: vi.fn().mockResolvedValue(snapshot),
    submitTermsAgreement: vi.fn().mockResolvedValue(snapshot),
    submitRequiredAction: vi.fn().mockResolvedValue(snapshot),
    poll: vi.fn().mockResolvedValue(snapshot),
    resume: vi.fn().mockResolvedValue(snapshot),
    onStateChange: vi.fn((cb: (s: HeadlessFlowSnapshot) => void) => {
      listeners.add(cb);
      cb(snapshot);
      return () => listeners.delete(cb);
    }),
    dispose: vi.fn(),
  };
}

function makeHeadlessClient(flow: HeadlessAuthFlow = makeFakeFlow()): HeadlessJummonAuthClient {
  return { ...makeRedirectClient(), startAuthFlow: vi.fn().mockReturnValue(flow) };
}

describe("JummonAuthProvider / useJummonAuth", () => {
  beforeEach(() => {
    vi.mocked(createJummonAuth).mockReset();
  });

  it("redirect mode: isHeadless is false and startAuthFlow is undefined (no regression to the existing surface)", async () => {
    const client = makeRedirectClient();
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result } = renderHook(() => useJummonAuth(), {
      wrapper: ({ children }) => <JummonAuthProvider {...OPTIONS}>{children}</JummonAuthProvider>,
    });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.isHeadless).toBe(false);
    expect(result.current.startAuthFlow).toBeUndefined();
    expect(result.current.client).toBe(client);
    expect(createJummonAuth).toHaveBeenCalledWith(expect.objectContaining(OPTIONS));
  });

  it("headless mode: isHeadless is true and startAuthFlow() delegates to the client (B3 fix)", async () => {
    const flow = makeFakeFlow();
    const client = makeHeadlessClient(flow);
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result } = renderHook(() => useJummonAuth(), {
      wrapper: ({ children }) => (
        <JummonAuthProvider {...OPTIONS} mode="headless">
          {children}
        </JummonAuthProvider>
      ),
    });

    await waitFor(() => expect(result.current.isHeadless).toBe(true));
    expect(result.current.startAuthFlow).toBeTypeOf("function");
    const returned = result.current.startAuthFlow?.();
    expect(client.startAuthFlow).toHaveBeenCalledTimes(1);
    expect(returned).toBe(flow);
  });

  it("accepts a pre-built `client` prop (the seam @jummon/auth-react-native plugs into) without calling createJummonAuth", async () => {
    const client = makeHeadlessClient();

    const { result } = renderHook(() => useJummonAuth(), {
      wrapper: ({ children }) => <JummonAuthProvider client={client}>{children}</JummonAuthProvider>,
    });

    await waitFor(() => expect(result.current.isHeadless).toBe(true));
    expect(result.current.client).toBe(client);
    expect(createJummonAuth).not.toHaveBeenCalled();
  });

  it("useJummonAuth() throws outside a provider", () => {
    expect(() => renderHook(() => useJummonAuth())).toThrow(/JummonAuthProvider/);
  });

  it("useJummonUser() reflects the authenticated user once onAuthStateChanged fires", async () => {
    const user = { sub: "u1", tenant: "acme", roles: [], permissions: [], raw: {} };
    const client = makeRedirectClient();
    vi.mocked(client.onAuthStateChanged).mockImplementation((cb) => {
      cb({ status: "authenticated", user });
      return () => {};
    });
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result } = renderHook(() => useJummonUser(), {
      wrapper: ({ children }) => <JummonAuthProvider {...OPTIONS}>{children}</JummonAuthProvider>,
    });

    await waitFor(() => expect(result.current).toEqual(user));
  });

  it("disposes the client on unmount", async () => {
    const client = makeRedirectClient();
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { unmount } = render(<JummonAuthProvider {...OPTIONS}>{null}</JummonAuthProvider>);
    unmount();

    expect(client.dispose).toHaveBeenCalledTimes(1);
  });
});

describe("useHeadlessAuthFlow", () => {
  beforeEach(() => {
    vi.mocked(createJummonAuth).mockReset();
  });

  it("throws when the provider is in redirect mode (fail loud, not a silent no-op)", () => {
    const client = makeRedirectClient();
    vi.mocked(createJummonAuth).mockReturnValue(client);

    expect(() =>
      renderHook(() => useHeadlessAuthFlow(), {
        wrapper: ({ children }) => <JummonAuthProvider {...OPTIONS}>{children}</JummonAuthProvider>,
      }),
    ).toThrow(/headless/i);
  });

  it("lazily creates ONE flow (client.startAuthFlow called once) across multiple method calls, and mirrors onStateChange as `snapshot`", async () => {
    const flow = makeFakeFlow();
    const client = makeHeadlessClient(flow);
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result } = renderHook(() => useHeadlessAuthFlow(), {
      wrapper: ({ children }) => (
        <JummonAuthProvider {...OPTIONS} mode="headless">
          {children}
        </JummonAuthProvider>
      ),
    });

    expect(client.startAuthFlow).not.toHaveBeenCalled();
    expect(result.current.snapshot).toBeNull();

    await act(async () => {
      await result.current.start();
    });

    expect(client.startAuthFlow).toHaveBeenCalledTimes(1);
    expect(result.current.snapshot?.status).toBe("needs_credentials");

    await act(async () => {
      await result.current.submitPassword("jane@example.com", "hunter2");
    });

    expect(flow.submitPassword).toHaveBeenCalledWith("jane@example.com", "hunter2");
    // still exactly one flow/one client.startAuthFlow() call across both operations.
    expect(client.startAuthFlow).toHaveBeenCalledTimes(1);
  });

  it("exposes confirmMfaSetup and submitTermsAgreement (step-payload fold)", async () => {
    const flow = makeFakeFlow();
    const client = makeHeadlessClient(flow);
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result } = renderHook(() => useHeadlessAuthFlow(), {
      wrapper: ({ children }) => (
        <JummonAuthProvider {...OPTIONS} mode="headless">
          {children}
        </JummonAuthProvider>
      ),
    });

    await act(async () => {
      await result.current.confirmMfaSetup("123456");
    });
    expect(flow.confirmMfaSetup).toHaveBeenCalledWith("123456");

    await act(async () => {
      await result.current.submitTermsAgreement(true, { consentAccepted: true, termsVersion: "v1" });
    });
    expect(flow.submitTermsAgreement).toHaveBeenCalledWith(true, { consentAccepted: true, termsVersion: "v1" });
  });

  it("disposes the flow on unmount", async () => {
    const flow = makeFakeFlow();
    const client = makeHeadlessClient(flow);
    vi.mocked(createJummonAuth).mockReturnValue(client);

    const { result, unmount } = renderHook(() => useHeadlessAuthFlow(), {
      wrapper: ({ children }) => (
        <JummonAuthProvider {...OPTIONS} mode="headless">
          {children}
        </JummonAuthProvider>
      ),
    });

    await act(async () => {
      await result.current.start();
    });
    unmount();

    expect(flow.dispose).toHaveBeenCalledTimes(1);
  });
});
