# Roadmap

## v1 — hosted redirect (this release)

Full-page authorization-code + PKCE redirect to Jummon's hosted login
(`jummon-login-interface`, at `idm.jummon.com/<tenant>/oidc/...`), wrapping
`oidc-client-ts`. Silent refresh via `refresh_token` (`offline_access`
scope). React binding (`@jummon/auth/react`). This is the fix for
`signinPopup()` breaking on mobile — see `MIGRATION-from-popup.md`.

The public API (`createJummonAuth`, `signIn`, `signInCallback`, `signOut`,
`getUser`, `getAccessToken`, `isAuthenticated`, `onAuthStateChanged`) is
deliberately the full surface v2 needs too — internally it's implemented
against an `AuthEngine` interface (`src/types.ts`), with `RedirectEngine`
(`src/engines/redirectEngine.ts`) as the only concrete engine today.

## v2 — headless / embeddable auth

Tracked by the **`headless-embeddable-auth`** initiative:
`engineering-team/initiatives/headless-embeddable-auth/README.md`.

**Wave 1 (PWA/web) — SDK-side code is dev-ready.** `HeadlessEngine`
(`src/engines/headlessEngine.ts`) and `HeadlessAuthFlow`
(`src/flow/headlessAuthFlow.ts`, `src/flow/transport.ts`,
`src/flow/webauthn.ts`, `src/flow/types.ts`) ship in this package. The
backend Auth API this SDK talks to (`jummon-login-interface`'s
`POST /api/v1/auth/:tenant/:clientId/{start,submit}` /
`GET .../poll`) is a **separate, not-yet-shipped dispatch** —
`implementation-plan.md` §7. **`src/flow/types.ts`'s `HeadlessAuthEnvelope`
is this SDK's own resolution of the wire contract** `system-design.md` §3.3
and `implementation-plan.md` §11 open question 5 explicitly left unfrozen
(most notably: `tenant`/`client_id` as URL path segments, never a JSON body
field, and separate `code`/`oidc_state` fields on the terminal envelope
instead of the plan's own ambiguous `{state: "authenticated", ..., state}`
example) — align the backend route to that file before wiring this SDK
against a live tenant, don't silently reconcile against a drifted route.
Do not point `mode: "headless"` at a production tenant until (a) that
route ships and (b) the tenant has `headless_embeddable_auth` enabled
(feature flag, default OFF — `tenant-management-api`).

Shape shipped in this SDK:

- Email+password rendered **in-app** (`HeadlessAuthFlow.submitPassword` —
  **not** ROPC; it drives a multi-step state machine over the Auth API,
  never a direct call to `/oauth/token` with a raw password — see
  `ADR-0001-headless-auth-api-not-ropc.md`).
- Browser WebAuthn passkey **in-app** (`startPasskeyLogin`/
  `registerPasskey`; `src/flow/webauthn.ts` wraps
  `navigator.credentials.get`/`.create` directly, same two-phase wire
  contract `jummon-login-interface/src/pages/login/index.tsx` already
  implements against auth-engine's go-webauthn server). The passkey
  affordance is gated on `snapshot.passkeyOriginOk === true` — never offer
  a button that will always fail.
- Standalone, **post-login** passkey enrollment (`JummonAuthClient.registerPasskey(name?)`,
  `src/internal/passkeyEnrollment.ts`) — the opt-in "enable biometric
  sign-in" nudge, distinct from `HeadlessAuthFlow.registerPasskey()` above
  (that one answers a `fido-registration` step *during* login). Works in
  both `redirect` and `headless` mode since it only needs an already-signed-in
  session's access_token; talks to the API gateway (`apiHost`, `POST
  /catalog/me/credentials/passkeys/{begin,finish}`), never the Auth API.
  Gated the same way, via the exported `isPasskeySupported()` client-side
  capability check (no per-tenant `passkeyOriginOk` signal exists outside a
  headless login `start()`).
- Standalone, **post-login** password self-service
  (`JummonAuthClient.setPassword(password, confirmationPassword)`,
  `src/internal/passwordSelfService.ts`) — same shape as the passkey nudge
  above: distinct from `HeadlessAuthFlow.setPassword()` (answers
  `create-password-form` *during* login), works in both `redirect` and
  `headless` mode, talks to the API gateway (`apiHost`, `POST
  /catalog/me/credentials/password`), never the Auth API.
- Standalone, **post-login** TOTP (authenticator app) enrollment
  (`JummonAuthClient.beginOtpEnroll()` + `confirmOtpEnroll(otp)`,
  `src/internal/otpEnrollment.ts`) — distinct from the in-login
  `otp-configure-form` required-action step (`HeadlessFlowState`'s
  `needs_mfa_configure`, unchanged). Two calls rather than one
  begin→browser-API→finish round trip (there is no WebAuthn-style browser
  API here — a human reads a QR code and types back a code, an inherently
  async UI step the caller drives): `beginOtpEnroll()` mints a secret +
  `otpauth://` provisioning URI (`POST
  /catalog/me/credentials/otp/enroll/begin`, disclosed exactly once) to
  render as a QR code, then `confirmOtpEnroll(otp)` submits the first code
  the app generated (`POST /catalog/me/credentials/otp/enroll/finish`).
  Deliberately takes NO secret parameter — jummon-user-management validates
  against the secret it minted and persisted server-side at `begin`, never a
  client-supplied one (a prior version of this contract took `secret` and
  trusted it as validation authority with no server-side binding, an
  MFA-takeover hole; fixed by moving the secret to a server-side
  pending-enrollment record). Works in both `redirect` and `headless` mode;
  federation-guarded (`access_denied`) same as
  `setPassword()`/`registerPasskey()`.
- Social login still redirected — but to the social provider directly
  (`startSocialLogin`, full-page `window.location.assign`, never an
  iframe/WebView), not to `jummon-login-interface`.
- PKCE stays SDK-side (`oidc-client-ts`'s `SigninState.create`, never
  server-brokered). On the terminal `authenticated` state, this SDK
  exchanges `{code}` for tokens itself against
  `/<tenant>/oidc/oauth/token` (`src/internal/tokenExchange.ts`) — the same
  operation `RedirectEngine.signInCallback` performs via `oidc-client-ts`,
  just invoked directly since `HeadlessEngine` never navigates the browser.
  `HeadlessEngine` and `RedirectEngine` converge on identical
  `JummonUser`/`AuthState` output from there (`src/mapUser.ts`'s shared
  `buildJummonUser`).
- **Wave 2 (true-native):** iOS/Android platform passkey APIs
  (`ASAuthorizationPlatformPublicKeyCredentialProvider` / Android
  `CredentialManager`), associated-domain verification (AASA /
  `assetlinks.json`), and system-browser handoff for social
  (`ASWebAuthenticationSession` / Chrome Custom Tabs). Out of scope for
  this JS/TS package; would inform native (Swift/Kotlin) SDK work.
- **Wave 3 (optional drop-in UI):** prebuilt login/passkey UI components on
  top of the Wave 1/2 primitives, for customers who don't want to build
  their own form — mirroring the relationship `jummon-b2b-ui` has to
  `catalog-api` today, but for auth screens.

### Why the API is stable across this boundary

`HeadlessEngine implements AuthEngine` — the same interface `RedirectEngine`
does:

```ts
interface AuthEngine {
  signIn(opts?: SignInOptions): Promise<void>;
  signInCallback(url?: string): Promise<JummonUser>;
  signOut(opts?: SignOutOptions): Promise<void>;
  getUser(): Promise<JummonUser | null>;
  getAccessToken(): Promise<string | null>;
  isAuthenticated(): Promise<boolean>;
  onAuthStateChanged(cb: (state: AuthState) => void): () => void;
  dispose(): void;
}
```

A consumer who integrated against `createJummonAuth()` / `useJummonAuth()`
for v1 does not need to change their code to adopt headless mode's `getUser`/
`getAccessToken`/`onAuthStateChanged`/`signOut`/`isAuthenticated`/`dispose` —
only `mode: "headless"` plus the new `startAuthFlow()` entrypoint for the
actual multi-step login (`signIn()`/`signInCallback()` throw
`headless_requires_flow` in this mode; a single call can't express
`submitPassword` → maybe `needs_mfa` → `submitMfaCode` → `authenticated`).

### Shipped: standalone OTP (TOTP) enrollment (backend gap closed)

Previously blocked — `catalog-api` had no standalone (post-login)
OTP-enroll begin/finish REST endpoint, only a fire-and-forget
`POST /catalog/me/credentials/otp/reset` (delete-the-factor, no
secret/QR/confirm) and the in-login-only `otp-configure-form` step. That
gap is now closed: `catalog-api` shipped
`RegisterOtpBegin`/`RegisterOtpFinish`
(`internal/catalog/me/handler/handler.go:259-326`,
`internal/catalog/me/dto/dto.go:79-102`) — same self-service, no-RBAC,
federation-guarded (`FEDERATED_OTP_SET_FORBIDDEN`) shape as
`RegisterPasskeyBegin`/`Finish`. This SDK wires to it as
`JummonAuthClient.beginOtpEnroll()` / `confirmOtpEnroll(otp)` (see above).

Wire contract (verified against the real DTOs, not inferred):
- `POST /catalog/me/credentials/otp/enroll/begin` → `200
  {otp_secret, otp_url}` (`dto.RegisterOtpBeginResponse`) — `otp_secret`
  disclosed EXACTLY ONCE (a fresh `begin` mints a brand-new secret,
  invalidating the previous one) for the caller's own QR/manual-entry
  display. jummon-user-management ALSO persists this exact secret
  server-side (short TTL) as the pending enrollment `finish` validates
  against.
- `POST /catalog/me/credentials/otp/enroll/finish` → body `{otp}`
  (`dto.RegisterOtpFinishRequest`, `validate:"required"`) → `204`.
  Deliberately no `otp_secret` field: jummon-user-management validates the
  code against the secret ITS OWN `begin` call minted and persisted, never a
  client-supplied one. A prior version of this contract took an
  `otp_secret` field and trusted it as validation authority with no
  server-side binding to what `begin` actually minted — any caller holding
  a valid access_token could submit an attacker-chosen secret and silently
  disable/replace a working OTP factor (MFA-takeover, fixed).

### Explicitly not planned

- No Resource Owner Password Credentials (ROPC) grant against the OIDC
  token endpoint — rejected in the initiative's ADR-0001. The in-app
  password form (`HeadlessAuthFlow.submitPassword`) talks to the headless
  Auth API's step contract, not directly to `/oauth/token` with a raw
  password.
- No new credential storage — passwords/FIDO credentials/OTP secrets stay
  exactly where they live today (`jummon-auth-engine` /
  `jummon-user-management`).
- `jummon-login-interface` is not being replaced. It remains the default
  for tenants that don't embed, and stays mandatory for `is_system_managed`
  console clients (`b2b-portal`, `cockpit-ui`), which are out of scope for
  this SDK entirely.

## Platform-agnostic core (Phase 1 of React Native support — this refactor)

The next customer app is RN/Expo; pre-refactor, `HeadlessEngine`/
`HeadlessAuthFlow` threw `window is not defined` at construct time in RN
(`typeof window === "undefined"` guards) and depended on `oidc-client-ts`
(inherently browser/DOM-based) for PKCE. **Phase 1** (done, this pass)
extracted an agnostic core with ZERO behavior/API change for web:

- **Layout chosen**: `src/core/` (agnostic logic + `Platform*` interfaces)
  + `src/platform/browser/` (concrete browser adapters), NOT a
  `packages/core` + `packages/web` workspace split. The repo has no
  workspace tooling today (no `"workspaces"` field, no
  `pnpm-workspace.yaml` — `packages/s2s` is a fully independent npm project
  with its own lockfile, not a linked workspace member), and `@jummon/auth`
  is a LIVE, published, in-use-by-a-real-customer (Prummo) package —
  migrating its own root files into `packages/web` would be the invasive
  path for zero additional benefit in this phase. The chosen layout is
  purely additive: the root package's name/entry/exports/`createJummonAuth`
  behavior are untouched; `./core` is a new, optional subpath
  (`@jummon/auth/core`) a future platform package can import from.
- **Interfaces** (`src/core/platform/types.ts`): `PlatformStorage` (async
  get/set/remove — async so RN's `AsyncStorage` fits; the browser adapter
  wraps synchronous `Storage` in a resolved Promise, zero behavior change),
  `PlatformCrypto` (`randomBytes`/`sha256` — PKCE moved off
  `oidc-client-ts`'s `SigninState` onto `src/core/platform/pkce.ts`,
  computed directly per RFC 7636 §4.2 so it's injectable), `PlatformNavigation`
  (`redirect`/`getCurrentUrl`/`clearAuthParams` — the social-redirect +
  `resume()` dance), `PlatformWebAuthn` (`isSupported`/`create`/`get`,
  **optional** on `PlatformAdapters` so a platform with no passkey story
  yet degrades to `passkey_failed`/`passkey_origin_unsupported` instead of
  crashing).
- **Moved to core**: `HeadlessEngineCore` (was `engines/headlessEngine.ts`),
  `HeadlessAuthFlowCore` (was `flow/headlessAuthFlow.ts`), the flow-resume
  persistence (was `flow/persistence.ts`, now `core/flowPersistence.ts`,
  storage-adapter-backed). Neither core class imports `oidc-client-ts` or
  touches `window`/`document`/`navigator`/`crypto.subtle` — every such
  access goes through an injected adapter, and only when actually invoked
  (never at import/construct time), so a platform without a working
  `window` never hits one.
- **Web wiring**: `engines/headlessEngine.ts` and `flow/headlessAuthFlow.ts`
  are now thin wrappers — `new HeadlessEngine(options)` /
  `createHeadlessAuthFlow(options, sink)` default their adapter argument to
  `createBrowserPlatformAdapters(options)` (`platform/browser/index.ts`),
  which is the ONLY place left that checks `typeof window === "undefined"`
  and throws `ssr_unsupported` — same synchronous, construct-time throw as
  before, just relocated one level so the agnostic core itself never does
  it. `RedirectEngine` (v1, wraps `oidc-client-ts`) is UNCHANGED and stays
  browser-only by design — `oidc-client-ts` itself is fundamentally
  DOM-based (iframes for silent renew, `window.location` for the redirect);
  it is not part of the agnostic-core promise and Phase 2 does not attempt
  to port it.
- **Zero web regression, verified**: all 119 pre-existing tests pass
  unmodified except one (`engines/headlessEngine.test.ts`'s
  `onAuthStateChanged fires authenticated once completeSignIn() runs`),
  updated (not weakened) to reflect an inherent, unavoidable consequence of
  `PlatformStorage` being genuinely async: a `completeSignIn()` call issued
  synchronously right after `onAuthStateChanged()` subscribes now always
  wins the race against the (now-async) initial storage read — before, both
  happened to interleave around a purely synchronous `Storage` read. Both
  emissions still converge on the correct `authenticated` state; nothing
  observes a wrong value, only a timing nuance in a same-tick
  subscribe-then-immediately-sign-in edge case. `typecheck`/`build`/`test`
  all pass; `createJummonAuth`'s public API, defaults, and
  `tokenStorage`/`apiHost`/`issuerHost` semantics are byte-identical.

### Phase 2 — React Native (SHIPPED — `packages/react-native`)

Built as `@jummon/auth-react-native`, a new npm-workspaces member
(`"workspaces": ["packages/*"]` added at the root — `packages/s2s` is now a
real workspace member too, not a standalone project). Every adapter takes
its native dependency by constructor injection against a LOCAL structural
interface (`AsyncStorageLike`, `SecureStoreLike`/`SecureStorageLike`,
`ExpoCryptoLike`, `LinkingLike`, `ReactNativePasskeyLike`) — this package
never `import`s `@react-native-async-storage/async-storage`/`expo-secure-store`/
`expo-crypto`/`expo-linking`/`react-native-passkey`/`react-native` itself, so
none of them are hard dependencies (all peer, all `optional: true` — see
that package's `package.json`); it typechecks/builds/tests with plain mocked
objects, no RN runtime needed. What actually shipped, one-for-one against
the plan below:

1. **Storage** (`adapters/storage.ts`) — a COMPOSITE `PlatformStorage` that
   routes by key prefix rather than exposing two storages to the core:
   `HEADLESS_SESSION_STORAGE_PREFIX` keys (long-lived tokens) → the secure
   backend (`expo-secure-store`-shaped, OR an `AsyncStorage`-shaped keychain
   fallback for bare-RN `react-native-keychain` — the "keychain fallback
   interface" from the synthesis); everything else (flow-resume state,
   `HEADLESS_FLOW_STORAGE_PREFIX`) → plain `AsyncStorage`. Both prefix
   constants are now exported from `@jummon/auth/core`
   (`headlessEngineCore.ts`/`flowPersistence.ts`) instead of being private
   literals, specifically so this adapter can key off them without
   duplicating a magic string.
2. **Crypto** (`adapters/crypto.ts`) — `expo-crypto`'s `getRandomBytesAsync`
   + `digest("SHA-256", ...)`. This required widening the core's own
   `PlatformCrypto.randomBytes` return type from a plain sync `Uint8Array` to
   `Uint8Array | Promise<Uint8Array>` (`core/platform/types.ts`,
   `core/platform/pkce.ts`) — RN's native-bridge CSPRNG is inherently async,
   unlike `crypto.getRandomValues`. The browser adapter is unaffected (still
   returns synchronously; the union just means every caller `await`s either
   way — `generatePkcePair`/`generateOpaqueId` both do now).
3. **Navigation** (`adapters/navigation.ts`) — RN's/`expo-linking`'s
   `Linking`. `redirect()` → `Linking.openURL()` (system browser, never a
   WebView). `getCurrentUrl()` stays SYNCHRONOUS per the core's contract by
   keeping its own mutable `lastUrl`, seeded once via `getInitialURL()`
   (cold-start deep link) and kept current via the `'url'` event listener
   (warm relaunch) — `resume()` reads whatever it holds at call time.
   `clearAuthParams()` is a no-op (no URL bar/history on this platform).
4. **WebAuthn** (`adapters/webauthn.ts`) — `react-native-passkey`. Its
   request/response objects are JSON (every binary field already a
   base64url string), unlike the DOM's `ArrayBuffer`-based
   `PublicKeyCredential` the core speaks — this adapter is the translation
   layer both ways, using a dependency-free base64/base64url codec
   (`internal/base64.ts`, no `atob`/`btoa`/`Buffer` assumption — none is
   guaranteed present on Hermes). `passkey` is optional on
   `createReactNativePlatformAdapters()`, same optionality as
   `PlatformAdapters.webauthn` itself.
5. **Client** (`client.ts`) — `createJummonAuthReactNative(options, nativeDeps)`
   constructs `HeadlessEngineCore`/`HeadlessAuthFlowCore` (imported from
   `@jummon/auth/core`) directly, never touching `RedirectEngine`,
   `engines/headlessEngine.ts`, `flow/headlessAuthFlow.ts`, or
   `platform/browser/*` — RN is HEADLESS-ONLY (no `mode` option; there's no
   addressable URL bar to redirect to a hosted page and back). Also reuses
   `@jummon/auth/core`'s newly-exported `enrollPasskey`/`setPasswordSelfService`/
   `beginOtpEnrollment`/`confirmOtpEnrollment` (all pure `fetch`, no
   platform coupling — item 7 below, now actually wired instead of just
   noted as possible) for full parity with the web client's standalone
   post-login methods.
6. **React binding** — reused UNCHANGED. `@jummon/auth/react`'s
   `JummonAuthProvider` now accepts a pre-built `client` prop (in addition
   to `JummonAuthOptions`), which is the seam
   `createJummonAuthReactNative()`'s return value plugs into; `useJummonAuth()`/
   `useHeadlessAuthFlow()` are 100% platform-agnostic (see the B3 fix below)
   and serve RN unchanged — no RN-specific React code exists anywhere.
7. `internal/passkeyEnrollment.ts`/`otpEnrollment.ts`/`passwordSelfService.ts`
   needed no RN-specific changes, confirmed — now re-exported from
   `@jummon/auth/core` (with `enrollPasskey`/`isPasskeySupported` wrapped to
   make the `webauthn` argument REQUIRED there, vs. defaulting to the
   browser adapter on the main entry) so the RN package never imports
   anything under `platform/browser/`.

Verified: 30 new tests in `packages/react-native` (mocked natives — no RN
runtime available in this environment, matching the "compiles as TS,
adapters satisfy the interfaces, unit tests pass" bar), zero regression to
the 120 pre-existing web tests (141 after the React-binding rework below),
`typecheck`/`build` green in all three workspace packages.

### B3 fix — headless-aware React binding (SHIPPED)

`useJummonAuth()` previously had no way to reach `startAuthFlow()` — a
headless React app had to call `createJummonAuth()` a second time itself,
bypassing the binding entirely. Fixed in `src/react.tsx`:
- `JummonAuthContextValue` gained `isHeadless`/`startAuthFlow` (the latter
  `undefined` in redirect mode).
- `JummonAuthProviderProps` is now a union: the existing
  `JummonAuthOptions & {children}` shape (unchanged behavior, zero
  regression), OR `{client, children}` — a pre-built client, the seam
  `@jummon/auth-react-native` uses to plug an RN client into this SAME
  provider/hook pair.
- New `useHeadlessAuthFlow()` hook: lazily creates ONE `HeadlessAuthFlow` on
  first use, mirrors its `onStateChange` snapshot as React state, and
  re-exposes every submit-step method (`start`/`resume`/`poll`/
  `submitPassword`/`setPassword`/`startPasskeyLogin`/`registerPasskey`/
  `startSocialLogin`/`submitMfaCode`/`confirmMfaSetup`/`submitTermsAgreement`/
  `submitRequiredAction`) so a login screen never hand-writes
  `flow.onStateChange()`/`setState` wiring. Disposes the flow on unmount.

### Step-payload knowledge fold (B/P1, SHIPPED — scoped)

`needs_required_action` collapses 6+ distinct steps into one status; the
wire-quirk knowledge for each previously lived only in
`engineering-team/initiatives/headless-embeddable-auth/PRUMMO-INTEGRATION-GUIDE.md`.
Folded into `src/flow/stepPayloads.ts` + three `HeadlessAuthFlow` methods
(`confirmMfaSetup` for `otp-configure-form`, `submitTermsAgreement` for
`terms-agreement`, `submitDeviceConsent` for `device-consent-form` —
`create-password-form` already had `setPassword`).
`verify-email-form`/`validate-phone-form` are typed for documentation only
(no dedicated method — the masked-value round-trip/resend-cooldown UX
deserved more design than fit this pass). See the README's "Required-action
step payloads" section for the full table.

**`device-consent-form` — CLOSED (was blocked on backend item B4, now
shipped).** `services-auth.ts` used to read `consent_accepted` off the URL
query string instead of the JSON body for this one step; fixed backend-side
(body-first, query fallback, `jummon-login-interface` commit `a7487e0`).
`buildDeviceConsentSubmit()`/`HeadlessAuthFlow.submitDeviceConsent(accepted)`
now send `{consent_accepted}` in the body like every other required-action
step — no different from `submitTermsAgreement`'s shape/rationale, minus
the LGPD consent-gating (this step has no separate consent field).

### signOut() token revocation (P1, SHIPPED)

`HeadlessEngineCore.signOut()` (`src/core/headlessEngineCore.ts`'s
`revokeStolenableTokens()`) now POSTs the session's `refresh_token` to the
discovery doc's `revocation_endpoint` (RFC 7009,
`src/internal/tokenExchange.ts`'s `revokeToken()`) BEFORE clearing local
state — confirmed against a parallel auth-engine review that
`revocation_endpoint` is already live in prod (zitadel/oidc mounts
`/revoke` and advertises it). Endpoint read off the discovery doc, never
hardcoded. Runs unconditionally (even `signOut({redirect:false})`), and is
strictly best-effort/non-blocking at TWO layers of defense — `revokeToken()`
itself catches every failure and returns `false` rather than throwing, and
`revokeStolenableTokens()` wraps that call in a `try/catch` anyway so a
future change to `revokeToken()`'s contract can't silently turn a revoke
failure into a broken `signOut()`. Client auth is `client_id` only, matching
every other token-endpoint call this SDK makes — this SDK only supports
public (PKCE-only, no secret) clients today, so there's no private_key_jwt/
secret-client auth path to add here.

Shared by web and React Native — this lives in the agnostic core, not a
platform adapter, so `@jummon/auth-react-native`'s `signOut()` gets the same
fix with zero RN-specific code.

**CLOSED (item #9, founder-gate follow-up):** `RedirectEngine`
(`mode: "redirect"`, wraps `oidc-client-ts`)'s own `signOut({redirect:
false})` fast path used to skip revocation entirely (only
`userManager.removeUser()`, local storage only) — this was the one
`signOut` path the original fix didn't cover, since it was scoped to "the
core signOut path... adapter-agnostic" and `RedirectEngine` is explicitly
NOT part of the agnostic core. Now fixed directly in
`src/engines/redirectEngine.ts`: reads the stored `refresh_token` via
`UserManager.getUser()` before `removeUser()` clears it, revokes via the
same `revokeToken()` helper `HeadlessEngineCore` uses (best-effort,
try/catch-wrapped, never blocks/fails signOut), then proceeds unchanged.
The default (`redirect: true`) hosted end-session path is untouched — it
already invalidates the IdP session server-side via the
`end_session_endpoint` redirect itself. 5 new tests in the new
`src/engines/redirectEngine.test.ts` (revoke called with the
refresh_token, no session ⇒ no revoke call, signOut still completes when
revoke rejects, no token value ever logged, default redirect:true path
untouched/never calls revoke).

**Disclosed residual risk (item D1):** revocation is best-effort by
design — a signOut whose revoke call fails (offline device,
`revocation_endpoint` down) leaves that `refresh_token` valid server-side
for its normal TTL. Documented in the README right under this section as
an explicit, registered trade-off (same disclosure posture as the
`sessionStorage`-default exception) rather than an implicit gap behind the
"closes P1" claim.

### #85 client risk-signal collector (SHIPPED — dev-ready, flag-OFF by default)

`engineering-team/initiatives/risk-signal-collector/README.md`'s
allowlist/bans, implemented end to end:

- **New injectable**: `PlatformRiskSignals` (`core/platform/types.ts`) —
  three synchronous, coarse lookups (`getTimezone`/`getLanguage`/
  `getDeviceClass`), optional on `PlatformAdapters` like `webauthn`. There
  is structurally no method on this interface that could return a canvas/
  WebGL/audio/font fingerprint, a keystroke/mouse biometric, an IP, or
  precise geolocation — the bans are enforced by absence, not a filter.
  Browser adapter: `platform/browser/riskSignals.ts` (`Intl` for tz,
  `navigator.language` for lang, a UA-Client-Hints-coarse-boolean-or-
  viewport-width heuristic for device_class — never a full UA string
  parse). RN adapter: `packages/react-native/src/adapters/riskSignals.ts`
  (`createReactNativeRiskSignals`) — `Intl` fallback for tz (works out of
  the box on modern Hermes), `lang`/`device_class` need an app-supplied
  callback (no first-party RN API for either), every callback defensively
  wrapped so a missing dep or a throw degrades to `null`, never a crash.
- **`device_id`/`flow_ms`/`schema` need no platform adapter** — computed by
  the core itself. `core/deviceId.ts`'s `getOrCreateDeviceId()`/
  `rotateDeviceId()` persist a per-`(tenant,client)` opaque random id via
  the existing `PlatformStorage`+`PlatformCrypto` adapters (same
  `generateOpaqueId()` PKCE already uses), shared between
  `HeadlessEngineCore` (which rotates it) and `HeadlessAuthFlowCore` (which
  reads it) so there is one source of truth regardless of how many flow
  instances a caller creates. `flow_ms` = `Date.now()` at `start()` (stored
  in `StoredHeadlessFlow.flowStartedAt` — distinct from `savedAt`, which
  gets refreshed on every re-persist including right before a social
  redirect — so a resumed flow still measures from the ORIGINAL start)
  minus `Date.now()` at the current submit.
- **Opt-in, default OFF**: `JummonAuthOptions.collectRiskSignals` (default
  `false`) — `HeadlessAuthFlowCore.buildRiskSignals()` returns `undefined`
  (no field at all, not an empty object) unless this is `true`.
- **Attachment point**: `HeadlessAuthFlowCore.doSubmit()` — the single
  choke point every public submit-style method funnels through
  (`submitPassword`/`setPassword`/`submitMfaCode`/`confirmMfaSetup`/
  `submitTermsAgreement`/`submitDeviceConsent`/`submitRequiredAction`/the
  second phase of `startPasskeyLogin`/`registerPasskey`/
  `startSocialLogin`). `start()`/`poll()` never carry it — `flow_ms` is
  only meaningful relative to a submit, and the spec's own wording is
  "submit-step body". Merged additively (`{...body, risk_signals}`),
  never replacing the caller's own fields.
- **Rotation on signOut**: `HeadlessEngineCore.signOut()` calls
  `rotateDeviceId()` unconditionally (even `redirect:false`, even with no
  active session) — same best-effort posture as the revocation fix above.

Verified: 6 tests in `core/deviceId.test.ts` (mint/persist/stable/
namespaced-by-tenant+client/rotate/best-effort-on-storage-failure), 4 in
`flow/headlessAuthFlow.test.ts` (absent by default, absent when explicitly
`false`, allowlist-only keys present when `true`, device_id stable across
two submits in one flow), 1 end-to-end integration test
(`core/riskSignals.integration.test.ts`, real browser storage/crypto +
mocked network) proving device_id survives across two submits and then
CHANGES after `HeadlessEngine.signOut()`, 5 in
`packages/react-native/src/adapters/riskSignals.test.ts` + 2 in that
package's `adapters/index.test.ts` (mocked natives, no RN runtime).

### RN launch blockers — founder's final gate (SHIPPED)

Four blockers the founder's gate found before clearing `@jummon/auth-react-native`
for a real launch, all fixed in this pass:

- **B1 — `atob`/`btoa`/`Buffer` leak in the core (CRITICAL).**
  `src/internal/base64url.ts` used `atob`/`btoa` with a `Buffer.from(...)`
  fallback — none of which are Hermes/RN globals — and it was reached on
  EVERY RN operation via PKCE generation (`core/platform/pkce.ts`, every
  `start()`), WebAuthn encoding (`flow/webauthn.ts`), and JWT decode
  (`jwt.ts`, `HeadlessEngineCore.mapSession()` on every `getUser()`). On
  stock Expo this threw `ReferenceError: Buffer is not defined` and left
  the flow permanently stuck at `status: "error"`. Fixed by moving the RN
  team's already-correct dependency-free bit-manipulation codec (previously
  vendored separately at `packages/react-native/src/internal/base64.ts`)
  into the shared `src/internal/base64.ts` — now THE one codec, re-exported
  from `@jummon/auth/core` so the RN package's own `adapters/webauthn.ts`
  imports the identical implementation instead of a second copy. The old
  `base64url.ts` (and the RN package's duplicate `internal/base64.ts`) are
  deleted — there is exactly one base64/base64url implementation in the
  entire monorepo now.
- **B4 — the test gap that hid B1.** RN's vitest config runs under
  `environment: "node"` (Node has had `atob`/`btoa`/`Buffer` since v16), and
  no existing test drove a real `.start()`/`.startPasskeyLogin()` end to
  end — so the broken path never executed in CI. New regression test,
  `packages/react-native/src/regression.b1-no-atob-btoa-buffer.test.ts`:
  deletes `atob`/`btoa`/`Buffer` from `globalThis` (simulating Hermes) and
  drives a REAL `createJummonAuthReactNative()` flow —
  `start()` → `submitPassword()` → `authenticated` → `getUser()` — asserting
  no `ReferenceError` and correct decoded JWT claims. Verified this test
  FAILS with `ReferenceError: Buffer is not defined` against the pre-B1
  codec and PASSES after the fix (checked by hand during this pass, not
  just asserted).
- **B2 — Metro package-exports fallback.** `@jummon/auth/core` and `/react`
  resolved ONLY via the `exports` map; Metro only honors that map with
  `unstable_enablePackageExports` enabled, which isn't default across the
  declared `react-native >=0.70` peer range. Fixed with root-level static
  proxy files — `core.js`/`core.d.ts`/`react.js`/`react.d.ts` at the
  `@jummon/auth` package root, each a one-line `export * from "./dist/..."`
  — so Metro's pre-`exports` resolution (`<package>/<subpath>.js`, ignoring
  `package.json` for subpaths entirely) finds them regardless of the
  Metro/RN version. Added to `package.json`'s `files` array so they ship;
  `tsup`'s `clean: true` only wipes `dist/`, so these survive every build.
- **B3 — the `file:../..` dev-only dependency shipped in the tarball.**
  `packages/react-native/package.json` had `"@jummon/auth": "file:../.."`
  — npm workspaces does NOT rewrite that specifier at publish time, so
  `npm install @jummon/auth-react-native` would fail for every external
  user (their filesystem has no `../..` relative to their own
  `node_modules`). Changed to `"^0.4.0"` — npm workspaces still symlinks
  the local copy when the range is satisfied (confirmed:
  `node_modules/@jummon/auth` stayed a symlink to the repo root after
  `npm install`). New `packages/react-native/scripts/verify-no-file-deps.cjs`,
  wired as this package's `prepack` script (runs automatically before
  `npm pack`/`npm publish`), fails the pack if ANY dependency/
  devDependency/peerDependency has a `file:` specifier.

**B3 verification (real `npm pack`, not `--dry-run`):** packed BOTH
`@jummon/auth@0.4.0` and `@jummon/auth-react-native@0.1.0` to real
`.tgz` files, extracted the RN tarball and confirmed
`package.json`'s `dependencies["@jummon/auth"]` is `"^0.4.0"` (no `file:`
anywhere), then — critically — `npm install`ed BOTH tarballs by path into a
throwaway, non-workspace scratch project (no symlinking, no workspace
context at all — exactly an external user's install). It succeeded
cleanly; `@jummon/auth-react-native` landed as a real directory (not a
broken symlink), `require("@jummon/auth-react-native")` worked, and the B2
proxy files (`core.js`/`react.js`) were present and load-bearing —
`require("@jummon/auth/core.js")` and (after installing the `react` peer)
`require("@jummon/auth/react.js")` both resolved and exposed the expected
exports (`HeadlessEngineCore`, `JummonAuthProvider`, `useHeadlessAuthFlow`).
Also re-verified the `verify-no-file-deps.cjs` guard actually blocks a
regression: temporarily reintroduced `file:../..`, confirmed the script
exits non-zero with a clear message, then restored the fix.

## Follow-ups filed, not built in this pass

- **Typed submit builders for `verify-email-form`/`validate-phone-form`** —
  types exist (`VerifyEmailSubmit`/`ValidatePhoneSubmit` in
  `src/flow/stepPayloads.ts`), no dedicated `HeadlessAuthFlow` method yet.
  Needs a UX decision on resend-cooldown handling before adding one (both
  steps have a `resend_available_at` timestamp a real method should probably
  surface/gate on, not just pass through) — scoped out to avoid guessing at
  that UX. Escalate to `design`/`product` before picking this up.
- **B5's npm Trusted Publisher setup for the two new packages** — a founder/
  npm-org-access, one-time, per-package step (`npmjs.com` UI), not something
  this repo's code/CI can do for itself. See the README's "Publishing"
  section for the exact steps; `@jummon/auth-react-native`/`@jummon/s2s`'s
  first release-triggered publish will fail with an auth error until it's
  done — expected, not a regression.
