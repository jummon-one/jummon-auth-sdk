# @jummon/auth

Official Jummon browser auth SDK for customer apps. Wraps the standard
OIDC **authorization-code + PKCE redirect flow** against your tenant's
Jummon IdP, with silent (refresh_token) renewal and a thin React binding.

- **`mode: "redirect"` (default): hosted redirect.** The browser navigates
  to Jummon's hosted login (`idm.jummon.com/<tenant>/oidc/...`), then back
  to your app. Full-page redirect — no popups, works everywhere popups
  don't (mobile Safari, in-app WebViews, PWAs).
- **`mode: "headless"` (dev-ready, PWA/web — Wave 1): in-app login.** Your
  own app renders the login form (email+password, passkey, social) while
  Jummon stays the OIDC IdP underneath — see
  [Headless / embeddable mode](#headless--embeddable-mode-mode-headless)
  below and [`ROADMAP.md`](./ROADMAP.md).
- The base 8-method public API (`createJummonAuth`, `signIn`,
  `signInCallback`, `signOut`, `getUser`, `getAccessToken`,
  `onAuthStateChanged`, `isAuthenticated`) is identical across both modes —
  switching later is a `mode` option change, not a rewrite.
- **React Native / Expo?** This package is browser-only (`window`,
  `localStorage`, `crypto.subtle`) — use
  [`@jummon/auth-react-native`](./packages/react-native/README.md) instead,
  built on the same agnostic core (`@jummon/auth/core`) and headless-only
  (no hosted-redirect mode on RN).

If you're migrating off `oidc-client-ts`'s `signinPopup()`, read
[`MIGRATION-from-popup.md`](./MIGRATION-from-popup.md) first — it's a
line-by-line before/after.

## Install

```bash
npm install @jummon/auth
# React apps also want the peer dependency:
npm install react react-dom
```

## Quickstart — Acme integration (copy-paste)

This is the exact configuration for the `acme` tenant's `acme-app`
client (a **public** client — no secret, PKCE only).

`redirectUri` must be an **exact match** of one of the redirect URIs
registered for `acme-app` in Jummon (today: `https://app.example.com/auth/callback`).
If it doesn't match, the IdP will not redirect back to your app —
double-check with whoever manages the client in Jummon before debugging
anything else. See "Errors" below for how a scope/redirect mismatch
surfaces.

### 1. Wrap your app

```tsx
// src/main.tsx
import { JummonAuthProvider } from "@jummon/auth/react";

export function App() {
  return (
    <JummonAuthProvider
      tenant="acme"
      clientId="acme-app"
      redirectUri="https://app.example.com/auth/callback"
      scopes={["openid", "profile", "email", "offline_access"]}
    >
      <YourRoutes />
    </JummonAuthProvider>
  );
}
```

`offline_access` is what makes Jummon issue a `refresh_token` — without it,
`getAccessToken()` cannot silently refresh once the access token expires and
the user will be bounced back to `signIn()`.

### 2. Sign-in button

```tsx
import { useJummonAuth } from "@jummon/auth/react";

export function LoginButton() {
  const { signIn, isAuthenticated, isLoading } = useJummonAuth();

  if (isLoading) return null;
  if (isAuthenticated) return null;

  return <button onClick={() => signIn()}>Log in</button>;
}
```

`signIn()` navigates the whole page away — it does not return a value you
render around. There is no popup to manage and nothing to poll.

### 3. Callback route

Register a route at your `redirectUri`'s path (`/auth/callback`) that runs
this on mount, once:

```tsx
// src/routes/AuthCallback.tsx
import { useEffect, useState } from "react";
import { useJummonAuth } from "@jummon/auth/react";
import { JummonAuthError } from "@jummon/auth";

export function AuthCallback() {
  const { client } = useJummonAuth();
  const [error, setError] = useState<JummonAuthError | null>(null);

  useEffect(() => {
    client
      .signInCallback()
      .then(() => {
        window.location.replace("/"); // or your post-login route
      })
      .catch((err: JummonAuthError) => {
        setError(err);
      });
  }, [client]);

  if (error) {
    return <p data-error-code={error.code}>{errorCodeToMessage(error.code)}</p>;
  }
  return <p>Signing you in…</p>;
}

function errorCodeToMessage(code: string): string {
  switch (code) {
    case "access_denied":
      return "You cancelled sign-in.";
    case "login_required":
      return "Your session expired — please sign in again.";
    default:
      return "We couldn't sign you in. Please try again.";
  }
}
```

Per Jummon's front-end convention, the friendly message is derived from
`error.code`, and the raw code stays available via `data-error-code` for
QA/support — never render `error.message` directly to end users.

### 4. Read the user / call your API

```tsx
import { useJummonAuth } from "@jummon/auth/react";

export function Profile() {
  const { user, getAccessToken } = useJummonAuth();

  async function callApi() {
    const token = await getAccessToken(); // silently refreshed if expired
    if (!token) return; // signed out
    await fetch("https://api.example.com/v1/orders", {
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  if (!user) return null;
  return <p>Signed in as {user.email}</p>;
}
```

`user.roles` / `user.permissions` come straight off the token's claims. Per
Jummon convention, never render raw permission strings — map them through
your own UI copy if you display them at all.

### Framework-agnostic (no React)

```ts
import { createJummonAuth } from "@jummon/auth";

const auth = createJummonAuth({
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.example.com/auth/callback",
  scopes: ["openid", "profile", "email", "offline_access"],
});

// on your login page:
await auth.signIn();

// on /auth/callback:
const user = await auth.signInCallback();

// anywhere you need to call your API:
const token = await auth.getAccessToken();

// react to sign-in/sign-out anywhere:
const unsubscribe = auth.onAuthStateChanged((state) => {
  if (state.status === "authenticated") console.log(state.user);
});
```

## Headless / embeddable mode (`mode: "headless"`)

**Status: the backend Auth API this mode talks to
(`jummon-login-interface`'s `/api/v1/auth/*` namespace) is LIVE in
production** (Wave 1, since 2026-09-04) — see
`engineering-team/initiatives/headless-embeddable-auth/`. It is **per-tenant
flag-gated** (`headless_embeddable_auth`), currently enabled via
tenant-override for a single production tenant (`prummo` / client
`prummo-app`); every other tenant gets a `404 not_found` on `/api/v1/auth/*`
until it is explicitly opted in — this is not yet a general-availability
rollout. Confirm with the Jummon team that your tenant has the flag enabled
before pointing this at production.

Your app renders its own sign-in form — email+password, passkey (WebAuthn),
and social (redirect-to-provider) — instead of navigating to Jummon's
hosted page. **This is not Resource Owner Password Credentials (ROPC):**
`submitPassword()` never talks to the OIDC token endpoint directly; it goes
through a stateful step machine that is the *same* rate-limited,
risk-detected, audited code path the hosted login uses
(`ADR-0001-headless-auth-api-not-ropc.md`).

```ts
import { createJummonAuth } from "@jummon/auth";

const auth = createJummonAuth({
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  mode: "headless",
});

const flow = auth.startAuthFlow();

const unsubscribe = flow.onStateChange((snapshot) => {
  // snapshot.status: "idle" | "loading" | "needs_credentials" |
  //   "needs_passkey_assertion" | "needs_password" | "needs_mfa" |
  //   "needs_mfa_configure" | "needs_social_redirect" |
  //   "needs_required_action" | "authenticated" | "error"
  renderYourOwnUiFor(snapshot);
});

await flow.start(); // mints the flow + returns branding tokens (snapshot.theme)
// snapshot.theme, snapshot.availableSocialLogins and
// snapshot.passwordlessAvailable are already fully resolved server-side —
// if the tenant has configured a PER-CLIENT branding/social override for
// this app ("white-label per app, tenant fallback"), you get the merged
// result automatically; a client with no override renders the tenant's own
// theme unchanged. There is nothing else to call — the SDK never merges
// these itself.

// user submits your own form:
await flow.submitPassword(email, password);

// passkey (only offer the button when snapshot.passkeyOriginOk === true):
await flow.startPasskeyLogin(email); // resolves navigator.credentials.get() internally

// social (full-page redirect to the provider, never an iframe). The SDK
// persists {flowToken, codeVerifier, oidcState} to sessionStorage right
// before navigating away, since this JS realm doesn't survive the round trip:
await flow.startSocialLogin("google");

// On the redirectUri page's mount (after the provider round-trip lands the
// browser back here), call resume() instead of start() — it reconstructs the
// flow from sessionStorage + the code/state (or auth_resume=1) query params:
// const flow = auth.startAuthFlow();
// await flow.resume();

// MFA / any required-action step:
await flow.submitMfaCode(code);
await flow.submitRequiredAction("terms-agreement", { accepted: true });

// Onboarding/recovery's create-password-form (snapshot.status === "needs_password"):
await flow.setPassword(newPassword, newPassword);

// once snapshot.status === "authenticated", auth.getUser()/getAccessToken()
// behave exactly as they do in redirect mode — this SDK already exchanged
// the code for tokens for you.
```

`auth.signIn()` / `auth.signInCallback()` both throw
`headless_requires_flow` in this mode — `startAuthFlow()` is the real
entrypoint, because a single call can't express a multi-step login.

### React binding for headless mode (`useHeadlessAuthFlow`)

`useJummonAuth()` now exposes `isHeadless`/`startAuthFlow` directly (fixed a
gap where a headless React app had no way to reach `startAuthFlow()` through
the hook at all and had to bypass the binding entirely). For a login screen,
prefer `useHeadlessAuthFlow()` — it manages one `HeadlessAuthFlow`'s lifecycle
for you and mirrors its snapshot as React state:

```tsx
import { JummonAuthProvider, useHeadlessAuthFlow } from "@jummon/auth/react";

export function App() {
  return (
    <JummonAuthProvider tenant="acme" clientId="acme-app" redirectUri="https://app.example.com/auth/callback" mode="headless">
      <LoginScreen />
    </JummonAuthProvider>
  );
}

function LoginScreen() {
  const { snapshot, start, submitPassword, startPasskeyLogin, startSocialLogin, submitMfaCode } = useHeadlessAuthFlow();

  useEffect(() => {
    start();
  }, []);

  // render your own UI off `snapshot.status`, same state machine as the
  // framework-agnostic example above.
}
```

`useHeadlessAuthFlow()` throws synchronously if the provider isn't
`mode: "headless"` — same fail-loud posture as the underlying client's
`signIn()`. This same hook works unchanged for React Native — see
[`@jummon/auth-react-native`](./packages/react-native/README.md) below;
`<JummonAuthProvider client={...}>` accepts a pre-built client instead of
`JummonAuthOptions`, which is the seam the RN package plugs into.

**Handled automatically (on by default, opt-out via `createJummonAuth` options):**
- **Internal steps** (`check-session-id`, `ip-blocklist`, `ip-allowlist`) — the
  Auth API interleaves these with no UI of their own; the SDK auto-submits
  `{}` and never surfaces them as `current_step` (`autoAdvanceInternalSteps`,
  default `true`).
- **`otp-input-form`'s wire field** — `submitMfaCode(code)` always sends
  `{ otp: code }`, the field the backend actually reads.
- **`create-password-form`'s wire fields** — `flow.setPassword(password,
  confirmationPassword)` always sends `{ password, confirmation_password }`,
  the exact fields `jummon-auth-engine`'s `SubmitStepData` reads.
- **`flow_expired`** (flow_token TTL ~5min) — the SDK transparently calls
  `start()` again (same tenant/client/redirectUri/scope, fresh PKCE) and
  re-emits from the first step (`autoRestartOnExpiry`, default `true`). The
  one snapshot right after a restart carries `restartedAfterExpiry: true` so
  you can react in one line, e.g. `if (snapshot.restartedAfterExpiry) resetMyForm();`.

Full state/method reference:
`engineering-team/initiatives/headless-embeddable-auth/design/system-design.md`
§3.1/§6 and `design/ux-spec-wave1.md` (reference-screen contract, copy
deck, error/microcopy table, passkey-affordance visibility rules).

### Required-action step payloads (`needs_required_action`)

`needs_required_action` is one wire status covering several distinct steps —
the table below is the wire-quirk knowledge that used to live only in an
internal integration guide, folded into the SDK itself so a new integration
doesn't need it as tribal knowledge. **Every boolean-shaped field on this
wire is a STRING (`"true"`/`"false"`), never a native JSON boolean** — the
backend reads them via Go's `strconv.ParseBool`, and a native `true` is
silently dropped, not rejected.

| `current_step.ref` | Dedicated method | Wire body |
|---|---|---|
| `create-password-form` | `flow.setPassword(password, confirmationPassword)` | `{password, confirmation_password}` |
| `otp-configure-form` (initial TOTP setup) | `flow.confirmMfaSetup(code)` | `{otp: code}` — same field `submitMfaCode` uses, distinct method for the distinct step |
| `terms-agreement` (LGPD terms + consent) | `flow.submitTermsAgreement(accepted, {consentAccepted, termsVersion})` | `{terms_agreed, consent_accepted, terms_version}` on accept, `{terms_agreed: "false"}` on decline — throws synchronously if `accepted` is `true` without `consentAccepted: true` (LGPD requires a separate, explicit consent) |
| `device-consent-form` (OIDC device-code consent) | `flow.submitDeviceConsent(accepted)` | `{consent_accepted}` in the JSON body — like every other step now that item B4 (below) shipped |

`buildTermsAgreementSubmit`/`buildDeviceConsentSubmit` and the
`TermsAgreementSubmit`/`DeviceConsentSubmit`/`OtpConfigureSubmit`/
`CreatePasswordSubmit`/`CreatePasswordStepData` types are exported from the
package root and from `@jummon/auth/core` (`src/flow/stepPayloads.ts`) if you
want to type your own form state against them directly.

> **Item B4, closed:** `device-consent-form` used to read `consent_accepted`
> off the URL query string instead of the JSON body in the headless
> namespace (`jummon-login-interface`'s `services-auth.ts`) — the SDK
> deliberately left this ref typed-only rather than bake a workaround for a
> backend bug into the public API. Fixed backend-side (body-first, query
> fallback, commit `a7487e0`); `submitDeviceConsent()` now sends body-only
> like every other step.

**Typed for documentation only (no dedicated method yet — use
`flow.submitRequiredAction(ref, data)`):**

| `current_step.ref` | Type | Why no dedicated method yet |
|---|---|---|
| `verify-email-form` | `VerifyEmailSubmit`/`VerifyEmailStepData` | `email` is always the MASKED value from `data.email`, round-tripped verbatim — the shape is simple but the "which value goes back" semantics deserve a UI-facing helper (e.g. resend cooldown handling) that wasn't in scope for this pass |
| `validate-phone-form` | `ValidatePhoneSubmit`/`ValidatePhoneStepData` | Same shape/reasoning as email; note the SMS code is **4 digits**, not 6 like TOTP/email |

Any other `ref` not in either table: render a generic "action required" UI
and call `flow.submitRequiredAction(ref, data)` — never ignore an unknown
`ref` silently, that leaves the user stuck with no explanation.

### Post-login passkey enrollment (opt-in "Enable biometric sign-in" nudge)

`registerPasskey(name?)` is a **different** method from
`flow.registerPasskey()` above — that one answers a `fido-registration`
required-action step *during* login (headless mode only). This one runs
**after** the user is already signed in, in either mode, and is what you call
from a settings screen or a post-login nudge ("Enable biometric sign-in?"):

```ts
import { createJummonAuth, isPasskeySupported } from "@jummon/auth";

const auth = createJummonAuth({ tenant: "acme", clientId: "acme-app", redirectUri });

// Gate the nudge button — no point rendering it on an unsupported browser/origin.
if (isPasskeySupported()) {
  showEnableButton();
}

// On click:
try {
  const { credentialId, name } = await auth.registerPasskey("My phone");
} catch (err) {
  // err.code: "passkey_origin_unsupported" | "passkey_failed" | "not_authenticated" | "network_unreachable"
  showRetryNudge();
}
```

Requires an active session — throws `not_authenticated` if
`getAccessToken()` resolves to `null` (call it after login, not before).
Talks to the API gateway (`apiHost`, `POST /catalog/me/credentials/
passkeys/{begin,finish}` — self-service, no RBAC), never the Auth API
(`issuerHost`).

### Post-login password self-service ("Change my password")

`setPassword(password, confirmationPassword)` is a **different** method
from `flow.setPassword()` above — that one answers the `create-password-form`
required-action step *during* login (headless mode only). This one runs
**after** the user is already signed in, in either mode:

```ts
const auth = createJummonAuth({ tenant: "acme", clientId: "acme-app", redirectUri });

try {
  await auth.setPassword(newPassword, newPassword);
} catch (err) {
  // err.code: "not_authenticated" | "access_denied" (federated identity —
  //   catalog-api's FEDERATED_PASSWORD_SET_FORBIDDEN) | "invalid_password"
  //   (tenant password policy rejected it) | "network_unreachable"
}
```

Requires an active session — throws `not_authenticated` if
`getAccessToken()` resolves to `null`. Talks to the API gateway (`apiHost`,
`POST /catalog/me/credentials/password` — self-service, no RBAC), never the
Auth API (`issuerHost`).

### Post-login TOTP (authenticator app) enrollment

`beginOtpEnroll()` / `confirmOtpEnroll(otp)` are a **different** pair of
methods from the in-login `otp-configure-form` required-action step
(`flow.submitRequiredAction("otp-configure-form", ...)`,
`snapshot.status === "needs_mfa_configure"`) — those answer enrollment
*during* login. This pair runs **after** the user is already signed in, in
either mode, and is what you call from a settings screen ("Enable an
authenticator app?"). Unlike `registerPasskey()`, there is no browser API
round trip — enrollment is inherently two calls with a human step (scan a
QR code, type back a code) in between:

```ts
const auth = createJummonAuth({ tenant: "acme", clientId: "acme-app", redirectUri });

// Step 1 — mint the secret + provisioning URI, render it as a QR code:
const { otpUrl, secret } = await auth.beginOtpEnroll();
renderQrCode(otpUrl); // e.g. via a QR-code library — otpUrl is an otpauth:// URI
// `secret` is the same value encoded in otpUrl — show it as a "can't scan?
// enter this code" manual-entry fallback. DISPLAY ONLY: it is never sent to
// confirmOtpEnroll(); the server validates the code against the secret IT
// minted and persisted at beginOtpEnroll(), not a client-supplied one.
// Never log it, never persist it.

// Step 2 — once the user reads the code their authenticator app generated:
try {
  await auth.confirmOtpEnroll(code);
} catch (err) {
  // err.code: "not_authenticated" | "access_denied" (federated identity —
  //   catalog-api's FEDERATED_OTP_SET_FORBIDDEN) | "otp_enrollment_failed"
  //   (wrong/expired code, or beginOtpEnroll() was never called / its
  //   window lapsed) | "network_unreachable"
}
```

Both require an active session — throw `not_authenticated` if
`getAccessToken()` resolves to `null`. Talk to the API gateway (`apiHost`,
`POST /catalog/me/credentials/otp/enroll/{begin,finish}` — self-service, no
RBAC), never the Auth API (`issuerHost`).

## API

| Function | Notes |
|---|---|
| `createJummonAuth(options)` | Creates the client. Browser-only (throws `ssr_unsupported` under SSR — call it from a client component/effect). |
| `signIn(opts?)` | v1: full-page redirect to the hosted login. `opts.prompt`, `opts.state`, `opts.extraQueryParams`. |
| `signInCallback(url?)` | Call once on the `redirectUri` page. Exchanges the code for tokens, returns the `JummonUser`. |
| `signOut(opts?)` | Full IdP logout by default. `{ redirect: false }` clears the local session only. |
| `getUser()` | Current user or `null`, from the cached session — no network call. |
| `getAccessToken()` | Current access token, silently refreshed via `refresh_token` if expired. `null` if signed out. |
| `isAuthenticated()` | `boolean`, convenience over `getUser()`. |
| `onAuthStateChanged(cb)` | Subscribes to `{status:"loading"\|"authenticated"\|"unauthenticated"}`. Fires once immediately. Returns an unsubscribe function. |
| `registerPasskey(name?)` | Standalone, **post-login** passkey enrollment (works in both `redirect` and `headless` mode — see below). |
| `setPassword(password, confirmationPassword)` | Standalone, **post-login** "change my password" (works in both `redirect` and `headless` mode — see below). |
| `beginOtpEnroll()` | Standalone, **post-login** TOTP enrollment, step 1/2 — mints `{otpUrl, secret}` (works in both `redirect` and `headless` mode — see below). |
| `confirmOtpEnroll(otp)` | Standalone, **post-login** TOTP enrollment, step 2/2 — submits the first code. No `secret` parameter: the server validates against the secret it minted and persisted at `beginOtpEnroll()`. |

`createJummonAuth(options)`:

| Option | Required | Default | Notes |
|---|---|---|---|
| `tenant` | yes | — | Tenant slug (`"acme"`), never the tenant UUID. |
| `clientId` | yes | — | Public OIDC client id (`"acme-app"`). Never pass a client secret — this SDK never accepts one. |
| `redirectUri` | yes | — | Must exactly match a registered `redirect_uri` on the client. |
| `scopes` | no | `["openid","profile","email","offline_access"]` | Drop `offline_access` only if you don't need silent refresh. |
| `postLogoutRedirectUri` | no | `redirectUri` | Where the browser lands after `signOut()`. |
| `issuerHost` | no | `"idm.jummon.com"` | `"idm.jummon.dev"` for the dev environment. Never hardcode a full OIDC URL — this is the only host you configure; every endpoint is resolved from the tenant's discovery document. |
| `apiHost` | no | `"api.jummon.com"` | `"api.jummon.dev"` for the dev environment. Used by `registerPasskey()` (`POST /catalog/me/credentials/passkeys/*`), `setPassword()` (`POST /catalog/me/credentials/password`), and `beginOtpEnroll()`/`confirmOtpEnroll()` (`POST /catalog/me/credentials/otp/enroll/*`) — all API-gateway routes — **never the same host as `issuerHost`**, which is OIDC/discovery-only. |
| `tokenStorage` | no | `"session"` | `"session" \| "local" \| "memory"` — see Security below. |
| `automaticSilentRenew` | no | `true` | Background renewal before the access token expires. |
| `autoAdvanceInternalSteps` | no | `true` | Headless only. Auto-submits `{}` past input-less internal steps (`check-session-id`, `ip-blocklist`, `ip-allowlist`) instead of surfacing them as `current_step`. |
| `autoRestartOnExpiry` | no | `true` | Headless only. Transparently restarts the flow on `flow_expired` instead of surfacing the error — see above. |

React (`@jummon/auth/react`): `JummonAuthProvider` (props = the options
above + `children`), `useJummonAuth()` (returns `{ client, state, user,
isAuthenticated, isLoading, signIn, signOut, getAccessToken }`), and
`useJummonUser()` (shorthand for `useJummonAuth().user`).

## Errors

Every rejected promise is a `JummonAuthError` with a stable `.code` —
switch on `code`, never on `.message` (free to change). Common codes:
`login_required`, `access_denied`, `interaction_required`,
`consent_required`, `invalid_redirect_uri`, `state_mismatch`,
`silent_renew_failed`, `callback_missing_params`, `ssr_unsupported`,
`invalid_options`, `not_authenticated` (`registerPasskey()` called with no
active session).

`registerPasskey()` can also throw `passkey_origin_unsupported` (browser/
origin has no WebAuthn — check `isPasskeySupported()` first),
`passkey_failed` (ceremony cancelled or rejected by the server — catalog-api
collapses several distinct upstream failures into this single code; the
right UX is always "try again"), and `network_unreachable`.

`setPassword()` can also throw `access_denied` (federated identity —
catalog-api's `FEDERATED_PASSWORD_SET_FORBIDDEN`; a federated user's
password is managed by their IdP, never Jummon), `invalid_password` (the
tenant's password policy rejected it — the body carries the upstream
message), and `network_unreachable`.

`beginOtpEnroll()`/`confirmOtpEnroll()` can also throw `access_denied`
(federated identity — catalog-api's `FEDERATED_OTP_SET_FORBIDDEN`),
`otp_enrollment_failed` (`confirmOtpEnroll()` only — wrong/expired code, or
`beginOtpEnroll()` was never called first / its enrollment window lapsed —
there is no client-supplied secret to fall back on, by design), and
`network_unreachable`.

Headless-mode-specific codes (`HeadlessAuthFlow` snapshots also carry these
on `snapshot.error`, so you rarely need a `try/catch` around every call):
`headless_requires_flow`, `flow_not_started`, `flow_expired`,
`invalid_credentials` (deliberately the *same* code for "wrong password"
and "no such user" — never distinguish these in your own UI either, it's
an enumeration leak), `invalid_mfa_code`, `rate_limited`, `passkey_failed`,
`passkey_origin_unsupported`, `social_login_failed`,
`cors_origin_rejected`, `network_unreachable`, `state_mismatch` (also used
by `resume()`'s social-hop CSRF check), `pkce_verifier_lost` (an
`authenticated` response arrived but this tab's PKCE `code_verifier` is
gone — call `resume()` on the `redirectUri` page instead of relying on the
in-memory flow, or restart with `start()`).

`invalid_redirect_uri` is special: if the auth-engine cannot recognize your
`redirect_uri` at all, it often cannot redirect the browser *back* to you
with that error code — you'll instead see an error page rendered on
`idm.jummon.com` itself. Treat any full-page hang on the IdP domain during
sign-in as the first thing to check against the client's registered
`redirect_uris`.

## Security / token storage

This SDK targets **third-party customer apps** (a public SPA/PWA client
with no backend of its own) — the classic OAuth 2.0 "browser-based app"
shape (RFC-in-progress BCP for public clients). By default it persists the
OIDC session in `sessionStorage`, the same default `oidc-client-ts` and
most SPA OIDC SDKs ship, and the minimum needed for the PKCE `code_verifier`
and `state` to survive the full-page navigation to the IdP and back.

This is a deliberate, narrower exception to Jummon's own front-end rule
("never store tokens in `localStorage`/`sessionStorage`; use httpOnly
cookies via the login-interface proxy") — that rule assumes a backend
(`jummon-login-interface`'s Express server) capable of setting httpOnly
cookies, which Jummon's *own* products (`jummon-ui`, the login-interface
itself) have and a third-party customer SPA does not. If your app **does**
have a backend, consider a BFF token-exchange pattern instead of this SDK
holding tokens client-side at all — that's a legitimate v2/headless-era
direction, not something v1 tries to solve.

Options, in increasing XSS-resistance / decreasing convenience:

- `tokenStorage: "session"` (default) — survives reloads within the tab,
  cleared on tab close.
- `tokenStorage: "local"` — survives browser restarts. Wider XSS exposure
  window; only pick this if you specifically need "stay logged in" across
  sessions and accept the trade-off.
- `tokenStorage: "memory"` — nothing persisted; an XSS payload reading
  storage finds nothing. Trade-off: a full page reload loses the session
  (the user has to `signIn()` again), and the redirect flow's `code_verifier`
  cannot survive the mid-flow navigation either — pick this only if your app
  never does a full reload while signed in (e.g., a single-page shell).

Regardless of `tokenStorage`, this SDK never persists a `client_secret`
(none exists — `acme-app` is a public client) and every token exchange
uses PKCE (`S256`).

### `signOut()` revokes the `refresh_token` (headless mode)

In `mode: "headless"`, `signOut()` POSTs the session's `refresh_token` to
the discovery doc's `revocation_endpoint` (RFC 7009, `token_type_hint:
"refresh_token"`) BEFORE clearing local state — closing the "a stolen
refresh_token survives signOut" gap. The endpoint is read from
`GET /<tenant>/oidc/.well-known/openid-configuration`, never hardcoded.
This runs unconditionally, including `signOut({ redirect: false })` — it's
server-side credential cleanup, independent of whether that call also does
an RP-initiated (`end_session_endpoint`) browser redirect.

Revocation is strictly **best-effort and non-blocking**: a network failure,
a `revocation_endpoint` that's temporarily down, or any non-2xx response
never blocks or fails `signOut()` — local state is always cleared and
`signOut()` always completes regardless of the outcome. (RFC 7009 §2.2
already returns `200` for an unknown/already-invalidated token, so a
failure here is a genuine transport/config problem, not "already logged
out" — but even a genuine failure must never leave the user stuck signed
in locally with a token the server side never actually invalidated.)

## Requirements

- A modern browser (`window`, `crypto.subtle`, `fetch`). No SSR — call
  `createJummonAuth()` / mount `JummonAuthProvider` from a client
  component or effect.
- Your OIDC client must be registered in Jummon as a public client with
  your `redirectUri` in its `redirect_uris` list. This SDK cannot create or
  modify that registration — talk to whoever manages your Jummon tenant's
  clients.

## Monorepo (for Jummon engineering)

This repo is an **npm workspaces monorepo** (`"workspaces": ["packages/*"]`):

| Package | Path | What |
|---|---|---|
| `@jummon/auth` | repo root | Web SDK — agnostic core + browser adapters (this README). |
| `@jummon/auth/core` | `src/core/` (subpath of the same package) | Agnostic step-machine/PKCE/tokens, `Platform*` injectable interfaces. Not a separate npm package — imported by platform packages via `@jummon/auth/core`. |
| `@jummon/auth-react-native` | `packages/react-native/` | RN/Expo adapters — see [its README](./packages/react-native/README.md). |
| `@jummon/s2s` | `packages/s2s/` | Server-side (private_key_jwt minting, catalog-api wrappers) — unrelated to the client-side auth flow above. |

The root package stays at the repo root (not `packages/web`) deliberately —
it's a **live, published, in-production package** (Prummo depends on it);
moving it would be all-cost, no-benefit churn. `packages/react-native`
depends on it via `file:../..` (not a semver range) because npm workspaces
only auto-links dependencies BETWEEN listed workspace members
(`packages/*`) — the root project itself isn't one, so `file:` is the
correct local-link mechanism here, not a workaround.

`npm ci` at the root resolves every package's dependencies in one pass.
Per-package scripts (`typecheck`/`test`/`build`) also run from the root via
`npm run <script> --workspaces --if-present` (see `.github/workflows/ci.yml`).

## Publishing (for Jummon engineering)

**Public npm, trusted-publisher OIDC (tokenless) — no `NPM_TOKEN` anywhere,
for any of the three packages.** `.github/workflows/publish.yml` triggers on
a GitHub Release; **the Release is the human approval gate**, not a separate
CI decision — a local `npm publish` fails by design (no OIDC id-token
outside that workflow's runner).

Which package gets published is resolved from the **release tag**, one
release = one package (same model `@jummon/auth` already used before the
monorepo split, extended with a prefix for the two newer packages so their
tags don't collide with the root's):

| Tag pattern | Publishes |
|---|---|
| `v0.4.0` | `@jummon/auth` (repo root) |
| `auth-react-native-v0.1.0` | `@jummon/auth-react-native` |
| `s2s-v0.1.0` | `@jummon/s2s` |

Each package needs its own **one-time npm-side Trusted Publisher setup**
(`npmjs.com` → package → Settings → Trusted Publisher → GitHub Actions,
owner `jummon-one`, repo `jummon-auth-sdk`, workflow filename `publish.yml`,
no environment) before its first release-triggered publish — `@jummon/auth`
already has this configured; `@jummon/auth-react-native`/`@jummon/s2s` do
not yet (their first publish attempt fails with an auth error until someone
with npm org access does this one-time step — expected, not a bug).

To cut a release: bump the package's `version` in its own `package.json`,
commit, then create a GitHub Release with a tag matching the pattern above —
the workflow guards that the tag's version matches `package.json` before
publishing.
