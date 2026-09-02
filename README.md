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

**Status: SDK-side code is dev-ready; the backend Auth API it talks to
(`jummon-login-interface`'s `/api/v1/auth/*` namespace) is a separate,
not-yet-shipped dispatch — see
`engineering-team/initiatives/headless-embeddable-auth/`. Do not point this
at a tenant in production until that route exists and the tenant has
`headless_embeddable_auth` enabled.**

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
  //   "needs_passkey_assertion" | "needs_mfa" |
  //   "needs_mfa_configure" | "needs_social_redirect" |
  //   "needs_required_action" | "authenticated" | "error"
  renderYourOwnUiFor(snapshot);
});

await flow.start(); // mints the flow + returns branding tokens (snapshot.theme)

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

// once snapshot.status === "authenticated", auth.getUser()/getAccessToken()
// behave exactly as they do in redirect mode — this SDK already exchanged
// the code for tokens for you.
```

`auth.signIn()` / `auth.signInCallback()` both throw
`headless_requires_flow` in this mode — `startAuthFlow()` is the real
entrypoint, because a single call can't express a multi-step login.

Full state/method reference:
`engineering-team/initiatives/headless-embeddable-auth/design/system-design.md`
§3.1/§6 and `design/ux-spec-wave1.md` (reference-screen contract, copy
deck, error/microcopy table, passkey-affordance visibility rules).

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

`createJummonAuth(options)`:

| Option | Required | Default | Notes |
|---|---|---|---|
| `tenant` | yes | — | Tenant slug (`"acme"`), never the tenant UUID. |
| `clientId` | yes | — | Public OIDC client id (`"acme-app"`). Never pass a client secret — this SDK never accepts one. |
| `redirectUri` | yes | — | Must exactly match a registered `redirect_uri` on the client. |
| `scopes` | no | `["openid","profile","email","offline_access"]` | Drop `offline_access` only if you don't need silent refresh. |
| `postLogoutRedirectUri` | no | `redirectUri` | Where the browser lands after `signOut()`. |
| `issuerHost` | no | `"idm.jummon.com"` | `"idm.jummon.dev"` for the dev environment. Never hardcode a full OIDC URL — this is the only host you configure; every endpoint is resolved from the tenant's discovery document. |
| `tokenStorage` | no | `"session"` | `"session" \| "local" \| "memory"` — see Security below. |
| `automaticSilentRenew` | no | `true` | Background renewal before the access token expires. |

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
`invalid_options`.

Headless-mode-specific codes (`HeadlessAuthFlow` snapshots also carry these
on `snapshot.error`, so you rarely need a `try/catch` around every call):
`headless_requires_flow`, `flow_not_started`, `flow_expired`,
`invalid_credentials` (deliberately the *same* code for "wrong password"
and "no such user" — never distinguish these in your own UI either, it's
an enumeration leak), `invalid_mfa_code`, `rate_limited`, `passkey_failed`,
`passkey_origin_unsupported`, `social_login_failed`,
`cors_origin_rejected`, `network_unreachable`.

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

## Requirements

- A modern browser (`window`, `crypto.subtle`, `fetch`). No SSR — call
  `createJummonAuth()` / mount `JummonAuthProvider` from a client
  component or effect.
- Your OIDC client must be registered in Jummon as a public client with
  your `redirectUri` in its `redirect_uris` list. This SDK cannot create or
  modify that registration — talk to whoever manages your Jummon tenant's
  clients.

## Publishing (for Jummon engineering)

This package ships `"private": true` and is **not published**. Before the
first publish:

1. Decide the license (currently `UNLICENSED`) — OSS (`MIT`, matching the
   rest of the industry's client-SDK convention) vs. proprietary.
2. Flip `"private"` to `false` in `package.json`.
3. Confirm the target registry: `publishConfig` currently points at public
   npm (`registry.npmjs.org`, scope `@jummon`, `access: "public"`). For a
   private-only release instead, see [`.npmrc.example`](./.npmrc.example)
   for the GCP Artifact Registry alternative (provisioning, auth via
   `google-artifactregistry-auth`, and the `publishConfig` fields to swap
   in) — no source change needed either way.
4. `npm run build && npm publish` (or `npm publish` from CI, never a local
   long-lived token).
