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

## v2 — headless / embeddable auth (planned, not started)

Tracked by the **`headless-embeddable-auth`** initiative:
`engineering-team/initiatives/headless-embeddable-auth/README.md` (status:
proposed / request-for-analysis as of this writing — system design and ADR
are not written yet; read that folder before starting v2 work, not this
file, for the authoritative scope and boundaries).

Planned shape, per that initiative's three waves:

- **Wave 1 (PWA/web):** email+password rendered **in-app** (no redirect, no
  popup), browser WebAuthn passkey **in-app**, social login still
  redirected — but to the social provider directly, not to
  `jummon-login-interface`. Backed by a new public **headless Auth API**
  (a state machine) that is a second client of the *same* step contract
  `jummon-login-interface` already consumes (`dynamic-flows` handlers +
  steptype registry / the auth-engine's classic step engine) — not a
  reimplementation of password checking, lockout, FIDO ceremonies, or risk
  scoring. This SDK's `HeadlessEngine` would call that Auth API instead of
  redirecting.
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

`createJummonAuth({ ...options, mode: "headless" })` is already reserved in
`JummonAuthOptions.mode` (currently throws `engine_not_implemented` — see
`src/client.ts`). When `HeadlessEngine` ships, it implements the same
`AuthEngine` interface `RedirectEngine` does today:

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
for v1 does not need to change their code to adopt v2 — only the
`mode` option (and, for the in-app password/passkey UI, new
consumer-rendered form components calling `signIn({ credentials })` or
similar, to be specced alongside the headless Auth API's actual request
shape once `system-design.md` exists in the initiative).

### Explicitly not planned

- No Resource Owner Password Credentials (ROPC) grant against the OIDC
  token endpoint — rejected in the initiative's ADR-0001. The in-app
  password form talks to the headless Auth API's step contract, not
  directly to `/oauth/token` with a raw password.
- No new credential storage — passwords/FIDO credentials/OTP secrets stay
  exactly where they live today (`jummon-auth-engine` /
  `jummon-user-management`).
- `jummon-login-interface` is not being replaced. It remains the default
  for tenants that don't embed, and stays mandatory for `is_system_managed`
  console clients (`b2b-portal`, `cockpit-ui`), which are out of scope for
  this SDK entirely.
