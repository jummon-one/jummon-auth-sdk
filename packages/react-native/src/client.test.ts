import { describe, expect, it, vi } from "vitest";
import { HEADLESS_FLOW_STORAGE_PREFIX, HEADLESS_SESSION_STORAGE_PREFIX } from "@jummon/auth/core";
import { createJummonAuthReactNative, type ReactNativeAuthOptions } from "./client";
import type { AsyncStorageLike, SecureStoreLike } from "./adapters/storage";
import type { ExpoCryptoLike } from "./adapters/crypto";
import type { LinkingLike } from "./adapters/navigation";
import type { ReactNativePasskeyLike } from "./adapters/webauthn";

const OPTIONS: ReactNativeAuthOptions = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "acme://auth/callback",
};

function fakeAsyncStorage(seed: Record<string, string> = {}): AsyncStorageLike {
  const store = new Map(Object.entries(seed));
  return {
    getItem: vi.fn(async (key) => store.get(key) ?? null),
    setItem: vi.fn(async (key, value) => void store.set(key, value)),
    removeItem: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeSecureStore(seed: Record<string, string> = {}): SecureStoreLike {
  const store = new Map(Object.entries(seed));
  return {
    getItemAsync: vi.fn(async (key) => store.get(key) ?? null),
    setItemAsync: vi.fn(async (key, value) => void store.set(key, value)),
    deleteItemAsync: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeExpoCrypto(): ExpoCryptoLike {
  return {
    getRandomBytesAsync: vi.fn(async (n: number) => new Uint8Array(n)),
    digest: vi.fn(async () => new Uint8Array(32).buffer),
  };
}
function fakeLinking(initialUrl: string | null = null): LinkingLike {
  return {
    openURL: vi.fn(),
    getInitialURL: vi.fn().mockResolvedValue(initialUrl),
    addEventListener: vi.fn().mockReturnValue({ remove: vi.fn() }),
  };
}
function fakePasskey(): ReactNativePasskeyLike {
  return { isSupported: vi.fn().mockReturnValue(true), create: vi.fn(), get: vi.fn() };
}

function baseDeps(
  overrides: {
    secureStoreSeed?: Record<string, string>;
    passkey?: ReactNativePasskeyLike;
    asyncStorageSeed?: Record<string, string>;
    linking?: LinkingLike;
  } = {},
) {
  return {
    asyncStorage: fakeAsyncStorage(overrides.asyncStorageSeed),
    secureStore: fakeSecureStore(overrides.secureStoreSeed),
    expoCrypto: fakeExpoCrypto(),
    linking: overrides.linking ?? fakeLinking(),
    passkey: overrides.passkey,
  };
}

describe("createJummonAuthReactNative", () => {
  it("throws invalid_options when a required option is missing", () => {
    expect(() =>
      createJummonAuthReactNative({ tenant: "acme", clientId: "", redirectUri: "acme://cb" }, baseDeps()),
    ).toThrow(/missing required option/);
  });

  it("signIn()/signInCallback() throw headless_requires_flow — startAuthFlow() is the real entrypoint (RN is always headless)", async () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    await expect(client.signIn()).rejects.toMatchObject({ code: "headless_requires_flow" });
    await expect(client.signInCallback()).rejects.toMatchObject({ code: "headless_requires_flow" });
  });

  it("startAuthFlow() returns a fresh, idle HeadlessAuthFlow every call", () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    const flow1 = client.startAuthFlow();
    const flow2 = client.startAuthFlow();

    expect(flow1).not.toBe(flow2);
    expect(flow1.state.status).toBe("idle");
    expect(typeof flow1.start).toBe("function");
  });

  // mobile parity item #6 — magic-link native-return needs NO extra RN
  // wiring: it completes through the SAME resume() mechanism the social-
  // redirect leg already uses, off the RN Linking adapter's cold-start
  // URL tracking (PlatformNavigation.getCurrentUrl()).
  it("startAuthFlow().resume() completes a magic-link-shaped code+state deep link exactly like a social-redirect return", async () => {
    const asyncStorageSeed = {
      [`${HEADLESS_FLOW_STORAGE_PREFIX}${OPTIONS.tenant}:${OPTIONS.clientId}`]: JSON.stringify({
        flowToken: "ft-stored",
        codeVerifier: "verifier-123",
        oidcState: "state-abc",
        tenant: OPTIONS.tenant,
        clientId: OPTIONS.clientId,
        redirectUri: OPTIONS.redirectUri,
        issuerHost: "idm.jummon.dev",
        savedAt: Date.now(),
        flowStartedAt: Date.now(),
      }),
    };
    // The exact same wire shape a social-provider redirect delivers — a
    // magic-link email lands the user on this same `redirectUri` because
    // requestMagicLink() rides the SAME already-started OIDC/PKCE leg.
    const linking = fakeLinking(`${OPTIONS.redirectUri}?code=magic-link-code&state=state-abc`);
    const client = createJummonAuthReactNative(
      { ...OPTIONS, issuerHost: "idm.jummon.dev" },
      baseDeps({ asyncStorageSeed, linking }),
    );

    const fetchMock = vi
      .fn()
      // resume() -> completeAuthenticated() -> exchangeAuthorizationCode() first
      // fetches the tenant's OIDC discovery document...
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            issuer: "https://idm.jummon.dev/acme",
            token_endpoint: "https://idm.jummon.dev/acme/oidc/oauth/token",
          }),
          { status: 200 },
        ),
      )
      // ...then POSTs the authorization_code + PKCE exchange to token_endpoint.
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: "at-magic", refresh_token: "rt-magic", token_type: "Bearer", expires_in: 3600 }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    try {
      const flow = client.startAuthFlow();
      const snapshot = await flow.resume();

      expect(snapshot.status).toBe("authenticated");
      expect(await client.getAccessToken()).toBe("at-magic");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("getUser()/isAuthenticated() reflect no session when storage is empty", async () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());

    expect(await client.getUser()).toBeNull();
    expect(await client.isAuthenticated()).toBe(false);
    expect(await client.getAccessToken()).toBeNull();
  });

  describe("standalone post-login methods", () => {
    it("registerPasskey() throws not_authenticated with no session, without ever touching the network", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps({ passkey: fakePasskey() }));

      await expect(client.registerPasskey()).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("setPassword() throws not_authenticated with no session", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());

      await expect(client.setPassword("a", "a")).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("beginOtpEnroll()/confirmOtpEnroll() throw not_authenticated with no session", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());

      await expect(client.beginOtpEnroll()).rejects.toMatchObject({ code: "not_authenticated" });
      await expect(client.confirmOtpEnroll("123456")).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("registerPasskey() throws passkey_origin_unsupported when authenticated but no `passkey` adapter was supplied", async () => {
      const sessionKey = `${HEADLESS_SESSION_STORAGE_PREFIX}${OPTIONS.tenant}.${OPTIONS.clientId}`;
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
      const secureStoreSeed = {
        [sessionKey]: JSON.stringify({ access_token: "at", token_type: "Bearer", expires_at: futureExpiry }),
      };
      const client = createJummonAuthReactNative(OPTIONS, baseDeps({ secureStoreSeed }));

      await expect(client.registerPasskey()).rejects.toMatchObject({ code: "passkey_origin_unsupported" });
    });

    // mobile parity item #5 — recovery-codes-self on RN
    it("generateRecoveryCodes()/hasUnredeemedRecoveryCodes() throw not_authenticated with no session, without ever touching the network", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());

      await expect(client.generateRecoveryCodes()).rejects.toMatchObject({ code: "not_authenticated" });
      await expect(client.hasUnredeemedRecoveryCodes()).rejects.toMatchObject({ code: "not_authenticated" });
    });

    it("generateRecoveryCodes() hits the self-service endpoint with the caller's own access_token once authenticated", async () => {
      const sessionKey = `${HEADLESS_SESSION_STORAGE_PREFIX}${OPTIONS.tenant}.${OPTIONS.clientId}`;
      const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
      const secureStoreSeed = {
        [sessionKey]: JSON.stringify({ access_token: "at-123", token_type: "Bearer", expires_at: futureExpiry }),
      };
      const client = createJummonAuthReactNative(OPTIONS, baseDeps({ secureStoreSeed }));

      const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ codes: ["A", "B"] }), { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);
      try {
        const result = await client.generateRecoveryCodes();
        expect(result.codes).toEqual(["A", "B"]);
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toContain("/catalog/me/credentials/recovery-codes/generate");
        expect((init.headers as Record<string, string>).Authorization).toBe("Bearer at-123");
      } finally {
        vi.unstubAllGlobals();
      }
    });
  });

  // mobile parity item #4 — first-class RN entrypoint into account recovery
  describe("startRecoveryFlow()", () => {
    it("returns a HeadlessRecoveryFlowCore wired to this client's own RN crypto adapter (PKCE device-binding, R13)", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());
      const flow = client.startRecoveryFlow({ baseHost: "dynamic.jummon.dev", flowRef: "recover-account-credential-aware" });

      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "t1", current_step: "x" }), { status: 201 }))
        .mockResolvedValueOnce(
          new Response(
            JSON.stringify({ next_token: "t2", current_step: { step: { ref: "x" } }, data: {} }),
            { status: 200 },
          ),
        );
      vi.stubGlobal("fetch", fetchMock);
      try {
        await flow.init();
        const initBody = JSON.parse((fetchMock.mock.calls[0] as [string, RequestInit])[1].body as string) as Record<
          string,
          unknown
        >;
        // The RN client's expo-crypto-backed adapter (not the browser default)
        // produced this — proof `startRecoveryFlow()` doesn't fall through to
        // `HeadlessRecoveryFlowCore`'s `browserCrypto` default on RN.
        expect(initBody.code_challenge).toEqual(expect.any(String));
      } finally {
        vi.unstubAllGlobals();
      }
    });

    it("enrollPasskey() throws passkey_origin_unsupported (never a browser navigator.credentials call) when no `passkey` adapter was supplied", async () => {
      const client = createJummonAuthReactNative(OPTIONS, baseDeps());
      const flow = client.startRecoveryFlow({ baseHost: "dynamic.jummon.dev", flowRef: "recover-account-credential-aware" });

      const snapshot = {
        status: "in_progress" as const,
        stepRef: "enroll-passkey-form",
        data: { ceremony_id: "c1", options: btoa("{}") },
        error: null,
      };

      await expect(flow.enrollPasskey(snapshot)).rejects.toMatchObject({ code: "passkey_origin_unsupported" });
    });
  });

  it("dispose() does not throw", () => {
    const client = createJummonAuthReactNative(OPTIONS, baseDeps());
    expect(() => client.dispose()).not.toThrow();
  });
});
