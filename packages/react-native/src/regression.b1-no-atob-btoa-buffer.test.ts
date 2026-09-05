import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bytesToBase64Url } from "@jummon/auth/core";
import { createJummonAuthReactNative, type ReactNativeAuthOptions } from "./client";
import type { AsyncStorageLike, SecureStoreLike } from "./adapters/storage";
import type { ExpoCryptoLike } from "./adapters/crypto";
import type { LinkingLike } from "./adapters/navigation";

/**
 * B1/B4 regression (RN launch blocker): the SDK's base64 codec used to
 * assume `atob`/`btoa` with a `Buffer.from(...)` fallback — none of which
 * are guaranteed globals on Hermes, RN's default JS engine. That path was
 * reached on EVERY RN operation via PKCE generation (`start()`), WebAuthn
 * encoding, and JWT payload decode (`getUser()`), so on stock Expo it threw
 * `ReferenceError: Buffer is not defined` and left the flow stuck in a
 * permanent `status: "error"`.
 *
 * This test simulates that exact Hermes condition — `atob`/`btoa`/`Buffer`
 * all deleted from `globalThis` — and drives a REAL headless
 * `start()` → `submitPassword()` → `authenticated` flow through
 * `createJummonAuthReactNative()`, then decodes the resulting session via
 * `getUser()`. Both are real call sites that used to reach the broken
 * codec: `start()` via `generatePkcePair()` → `bytesToBase64Url()`,
 * `getUser()` via `HeadlessEngineCore.mapSession()` → `decodeJwtPayload()`
 * → `base64UrlToBytes()`.
 *
 * This test FAILS against the pre-B1 `base64url.ts` (`generatePkcePair()`
 * throws inside `doStart()`'s try/catch, so `start()` resolves to
 * `status: "error"` instead of a real step; JWT decode silently swallows
 * the same error internally and returns incomplete/undefined claims) and
 * PASSES after B1 (the shared, dependency-free `src/internal/base64.ts`
 * used by every consumer, including this package via the `@jummon/auth/core`
 * re-export).
 */

const OPTIONS: ReactNativeAuthOptions = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "acme://auth/callback",
};

function fakeAsyncStorage(): AsyncStorageLike {
  const store = new Map<string, string>();
  return {
    getItem: vi.fn(async (key) => store.get(key) ?? null),
    setItem: vi.fn(async (key, value) => void store.set(key, value)),
    removeItem: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeSecureStore(): SecureStoreLike {
  const store = new Map<string, string>();
  return {
    getItemAsync: vi.fn(async (key) => store.get(key) ?? null),
    setItemAsync: vi.fn(async (key, value) => void store.set(key, value)),
    deleteItemAsync: vi.fn(async (key) => void store.delete(key)),
  };
}
function fakeExpoCrypto(): ExpoCryptoLike {
  return {
    getRandomBytesAsync: vi.fn(async (n: number) => new Uint8Array(n).map((_, i) => (i + 1) % 256)),
    digest: vi.fn(async () => new Uint8Array(32).fill(7).buffer),
  };
}
function fakeLinking(): LinkingLike {
  return {
    openURL: vi.fn(),
    getInitialURL: vi.fn().mockResolvedValue(null),
    addEventListener: vi.fn().mockReturnValue({ remove: vi.fn() }),
  };
}

/** Builds a fake JWT using ONLY the dependency-free codec under test — never `btoa`, which is deleted for this test anyway. */
function fakeJwt(claims: Record<string, unknown>): string {
  const segment = (payload: Record<string, unknown>) =>
    bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  return `${segment({ alg: "none" })}.${segment(claims)}.sig`;
}

/**
 * A minimal fake `Response` — NOT Node's real `Response`/`fetch` (undici),
 * which internally leans on `Buffer` for its body-stream plumbing and would
 * itself throw once `Buffer` is deleted below, for reasons that have
 * nothing to do with the SDK code this test actually exercises. RN's own
 * `fetch` global is a native-bridge implementation, not undici, so a real
 * `Response` object was never representative of the RN runtime anyway —
 * `HeadlessTransport`/`exchangeAuthorizationCode`/`fetchDiscoveryDocument`
 * only ever call `.ok`/`.status`/`.json()` on what `fetch()` resolves to.
 */
function jsonResponse(literal: unknown, status = 200): { ok: boolean; status: number; json: () => Promise<unknown> } {
  return { ok: status >= 200 && status < 300, status, json: async () => literal };
}

describe("B1/B4 regression: SDK works with atob/btoa/Buffer all absent (simulated Hermes)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let originalAtob: unknown;
  let originalBtoa: unknown;
  let originalBuffer: unknown;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    originalAtob = (globalThis as { atob?: unknown }).atob;
    originalBtoa = (globalThis as { btoa?: unknown }).btoa;
    originalBuffer = (globalThis as { Buffer?: unknown }).Buffer;
    // Simulate Hermes: none of these exist. Vitest's RN package runs under
    // environment:"node" (Node has had all three since v16), which is
    // EXACTLY the gap that let B1 ship undetected — no test previously
    // removed them before exercising a real flow.
    // @ts-expect-error -- deliberately deleting a global for this regression test
    delete globalThis.atob;
    // @ts-expect-error -- see above
    delete globalThis.btoa;
    // @ts-expect-error -- see above
    delete globalThis.Buffer;
  });

  afterEach(() => {
    (globalThis as { atob?: unknown }).atob = originalAtob;
    (globalThis as { btoa?: unknown }).btoa = originalBtoa;
    (globalThis as { Buffer?: unknown }).Buffer = originalBuffer;
    vi.unstubAllGlobals();
  });

  it("start() reaches a real step (not status:error) and getUser() correctly decodes the JWT after sign-in", async () => {
    const idToken = fakeJwt({ sub: "user-1", email: "jane@example.com" });
    const accessToken = fakeJwt({ sub: "user-1", roles: ["Admin"], permissions: ["catalog:roles:create"] });

    fetchMock
      // POST /start
      .mockResolvedValueOnce(
        jsonResponse({
          flow_token: "ft-1",
          status: "needs_input",
          current_step: { ref: "username-password-form" },
          data: {},
        }),
      )
      // POST /submit (submitPassword)
      .mockResolvedValueOnce(
        jsonResponse({
          flow_token: "ft-1",
          status: "authenticated",
          code: "auth-code-1",
          oidc_state: "state-1",
        }),
      )
      // GET .well-known/openid-configuration (exchangeAuthorizationCode's discovery lookup)
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.com/acme/oidc",
          token_endpoint: "https://idm.jummon.com/acme/oidc/oauth/token",
        }),
      )
      // POST token_endpoint
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: accessToken,
          id_token: idToken,
          refresh_token: "rt-1",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      );

    const client = createJummonAuthReactNative(OPTIONS, {
      asyncStorage: fakeAsyncStorage(),
      secureStore: fakeSecureStore(),
      expoCrypto: fakeExpoCrypto(),
      linking: fakeLinking(),
    });

    const flow = client.startAuthFlow();

    // --- PKCE generation path (generatePkcePair -> bytesToBase64Url) ---
    const startSnapshot = await flow.start();
    expect(startSnapshot.status).not.toBe("error");
    expect(startSnapshot.error).toBeNull();
    expect(startSnapshot.status).toBe("needs_credentials");

    // --- Terminal authenticated path (token exchange + completeSignIn) ---
    const finalSnapshot = await flow.submitPassword("jane@example.com", "hunter2");
    expect(finalSnapshot.status).not.toBe("error");
    expect(finalSnapshot.status).toBe("authenticated");
    expect(finalSnapshot.error).toBeNull();

    // --- JWT decode path (HeadlessEngineCore.mapSession -> decodeJwtPayload -> base64UrlToBytes) ---
    const user = await client.getUser();
    expect(user).not.toBeNull();
    expect(user?.sub).toBe("user-1");
    expect(user?.email).toBe("jane@example.com");
    expect(user?.roles).toEqual(["Admin"]);
    expect(user?.permissions).toEqual(["catalog:roles:create"]);
  });
});
