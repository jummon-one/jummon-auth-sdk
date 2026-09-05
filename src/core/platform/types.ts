/**
 * Platform-adapter interfaces — the seam between the agnostic core
 * (`../headlessEngineCore.ts`, `../headlessAuthFlowCore.ts`, `./pkce.ts`) and
 * whatever runtime actually hosts the SDK. The core NEVER touches `window`,
 * `document`, `navigator`, or `crypto.subtle` directly — every such access
 * goes through one of these four interfaces, injected at construction time.
 *
 * `../../platform/browser/*` is the concrete implementation the WEB package
 * (`@jummon/auth`'s default `createJummonAuth()`) wires by default — see that
 * directory's doc comments for the browser-specific behavior each adapter
 * reproduces byte-for-byte from the pre-refactor code.
 *
 * A React Native adapter (`@jummon/auth-react-native`, Phase 2 — not built in
 * this pass) supplies its own implementations of these same four interfaces
 * (AsyncStorage, `expo-crypto`/`react-native-quick-crypto`, `Linking`,
 * `react-native-passkey`) and constructs the agnostic core directly — see
 * `../../../ROADMAP.md`'s "Phase 2: React Native" section for exactly what
 * each adapter must implement.
 */

/**
 * Key-value persistence for the OIDC/headless session and the in-flight
 * headless-flow resume state (`../headlessAuthFlowCore.ts`'s
 * `StoredHeadlessFlow`). Deliberately ASYNC — a sync `Storage`-shaped
 * interface (what the browser's `localStorage`/`sessionStorage` already are)
 * cannot represent React Native's `AsyncStorage`, which is Promise-based by
 * design. The browser adapter (`../../platform/browser/storage.ts`) wraps
 * the synchronous Web Storage API in a resolved Promise — no behavior change,
 * since an `async` function with no internal `await` still runs its body
 * synchronously before yielding.
 */
export interface PlatformStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

/**
 * The one piece `oidc-client-ts`'s `SigninState`/`CryptoUtils` used to hide
 * from this SDK — PKCE (RFC 7636) needs cryptographically-secure random
 * bytes (the `code_verifier`'s entropy source) and a SHA-256 digest (the
 * S256 `code_challenge` transform). `../pkce.ts`'s `generatePkcePair()` is
 * the only caller; nothing else in the core needs raw crypto.
 */
export interface PlatformCrypto {
  /**
   * `length` cryptographically-secure random bytes. MUST use a CSPRNG
   * (`crypto.getRandomValues` on web, `expo-crypto`'s `getRandomBytesAsync`
   * on RN) — never `Math.random()`.
   *
   * `Uint8Array | Promise<Uint8Array>` (not plain sync `Uint8Array`) —
   * the browser adapter returns synchronously (`crypto.getRandomValues` is
   * sync), but RN's native-bridge CSPRNG (`expo-crypto`) is inherently
   * async, so the interface has to accommodate both without forcing the web
   * adapter to wrap a genuinely-sync call in an unnecessary microtask. Every
   * caller (`../platform/pkce.ts`) already `await`s the result either way.
   */
  randomBytes(length: number): Uint8Array | Promise<Uint8Array>;
  /** SHA-256 digest of `data`, per RFC 7636 §4.2's `S256` transform (`code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))` — the BASE64URL half is done by the caller, this only computes the digest). */
  sha256(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Full-page/system-browser navigation — the social-login kickoff
 * (`startSocialLogin`), the `end_session_endpoint` redirect
 * (`HeadlessEngine.signOut()`), and reading/clearing the one-shot
 * `code`/`state`/`auth_resume` query params after that round trip
 * (`HeadlessAuthFlow.resume()`, wire-contract-v1.md §7.3).
 *
 * On web this is `window.location`/`window.history`. On React Native there
 * is no addressable URL bar — `redirect()` opens the system browser (e.g.
 * `Linking.openURL` + `expo-web-browser`) and `getCurrentUrl()` returns the
 * deep-link URL that reopened the app (supplied by the RN adapter's own
 * `Linking` listener, not read from a browser API); `clearAuthParams()` is a
 * no-op there — nothing to strip from history.
 */
export interface PlatformNavigation {
  /** Navigates away from the app to `url` — full-page redirect on web, system-browser/`Linking.openURL` on RN. Never an in-app iframe/WebView (Google and other IdPs block embedded-WebView OAuth outright — same rule `startSocialLogin`'s doc comment states). */
  redirect(url: string): void | Promise<void>;
  /** The current page/deep-link URL, or `null` if none is available. */
  getCurrentUrl(): string | null;
  /** Strips one-shot auth query params (`code`/`state`/`auth_resume`) from the current URL/history without triggering a navigation. No-op on a platform with no addressable URL bar. */
  clearAuthParams(): void;
}

/**
 * WebAuthn/passkey ceremony — deliberately OPTIONAL on `PlatformAdapters`
 * (`webauthn?:`) so a platform without a passkey story yet (or where the
 * caller hasn't wired one) degrades cleanly: `HeadlessAuthFlow.startPasskeyLogin()`/
 * `registerPasskey()` and the standalone `JummonAuthClient.registerPasskey()`
 * (`../../internal/passkeyEnrollment.ts`) all resolve to `passkey_failed`/
 * `passkey_origin_unsupported` instead of a raw `undefined.get is not a
 * function` crash.
 *
 * Shaped after `navigator.credentials`'s two verbs rather than a bespoke
 * shape — RN's `react-native-passkey` returns a structurally-compatible
 * result (`id`/`rawId`/`type`/`response.*`), so the DOM `PublicKeyCredential`
 * type here is a type-level convenience (this package already depends on
 * `lib.dom` for the browser build), not a runtime browser requirement.
 */
export interface PlatformWebAuthn {
  /** Client-side capability check — "can this origin/platform even attempt a ceremony" (secure context + API present), not "has an admin configured this tenant's passwordless_config". */
  isSupported(): boolean;
  create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null>;
  get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential | null>;
}

/**
 * Client risk-signal collection (initiative #85,
 * `engineering-team/initiatives/risk-signal-collector/README.md`) —
 * deliberately OPTIONAL on `PlatformAdapters` (`riskSignals?:`) and
 * deliberately NARROW: this is the ENTIRE platform-specific surface the
 * collector needs, three synchronous, coarse, allowlisted lookups. Every
 * other allowlisted key (`device_id`, `flow_ms`, `schema`) is computed by
 * the agnostic core itself (`../deviceId.ts`, `../headlessAuthFlowCore.ts`)
 * and needs no platform adapter at all.
 *
 * The allowlist in the spec above is a HARD constraint, not a suggestion —
 * this interface exists to make it structurally impossible to accidentally
 * collect anything off it: there is no method here that could return a
 * canvas/WebGL/audio/font fingerprint, a keystroke/mouse biometric, an IP
 * address, or precise geolocation, because none of those has a method. Omit
 * this adapter entirely on a platform with no implementation yet — the
 * collector (`HeadlessAuthFlowCore`'s `buildRiskSignals()`) degrades to
 * sending `device_id`/`flow_ms`/`schema` only, never a crash, and ONLY when
 * the app opts in via `JummonAuthOptions.collectRiskSignals: true` in the
 * first place (default OFF — no adapter call happens at all otherwise).
 */
export interface PlatformRiskSignals {
  /** Coarse IANA timezone (e.g. `"America/Sao_Paulo"`) — a locale setting, never a coordinate/precise-geolocation lookup. `null` if unavailable. */
  getTimezone(): string | null;
  /** Primary language tag (e.g. `"pt-BR"`). `null` if unavailable. */
  getLanguage(): string | null;
  /** Coarse device class only — UA-Client-Hints-level granularity, never a full User-Agent string or any fingerprint-grade signal. `null` if undeterminable. */
  getDeviceClass(): "mobile" | "tablet" | "desktop" | null;
}

/** The full adapter bag the agnostic core is constructed with. */
export interface PlatformAdapters {
  storage: PlatformStorage;
  crypto: PlatformCrypto;
  navigation: PlatformNavigation;
  /** Omit (or supply `{ isSupported: () => false, ... }`) on a platform with no passkey story yet — see `PlatformWebAuthn`'s doc comment. */
  webauthn?: PlatformWebAuthn;
  /** Omit on a platform with no risk-signal implementation yet — see `PlatformRiskSignals`'s doc comment. Independent of `collectRiskSignals`: the option gates whether the collector runs at all, this adapter only supplies the platform-specific fields once it does. */
  riskSignals?: PlatformRiskSignals;
}
