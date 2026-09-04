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
