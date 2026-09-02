# Migrating from `oidc-client-ts`'s `signinPopup()`

The problem: `signinPopup()` opens a popup window and drives the OIDC
authorize flow inside it. Mobile Safari, most in-app WebViews, and several
Chrome-on-Android popup-blocking heuristics block or silently kill that
popup, so login fails or hangs for a real slice of mobile users — this is
exactly the failure the Acme PWA hit.

`@jummon/auth` wraps the same `oidc-client-ts` `UserManager` underneath,
but drives the **full-page redirect** flow (`signinRedirect` /
`signinCallback`) instead — the flow every mobile browser supports because
there's no popup to block.

## Before (popup, broken on mobile)

```ts
import { UserManager } from "oidc-client-ts";

const userManager = new UserManager({
  authority: "https://idm.jummon.com/acme/oidc",
  client_id: "acme-app",
  redirect_uri: "https://app.example.com/auth/callback",
  response_type: "code",
  scope: "openid profile email offline_access",
});

// Login button:
async function login() {
  const user = await userManager.signinPopup(); // blocked/hangs on mobile
  console.log(user.profile);
}

// Reading the current user, elsewhere in the app:
const user = await userManager.getUser();

// Calling your API:
const token = user?.access_token;
```

## After (full-page redirect, works everywhere)

```ts
import { createJummonAuth } from "@jummon/auth";

const auth = createJummonAuth({
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.example.com/auth/callback",
  scopes: ["openid", "profile", "email", "offline_access"],
});

// Login button — navigates the page away, does not return a user:
async function login() {
  await auth.signIn();
}

// A NEW route/page at redirectUri, run once on mount:
async function handleCallback() {
  const user = await auth.signInCallback();
  console.log(user);
  window.location.replace("/");
}

// Reading the current user, elsewhere in the app:
const user = await auth.getUser();

// Calling your API — now silently refreshes if expired, instead of
// handing you a possibly-stale token:
const token = await auth.getAccessToken();
```

## What actually changes in your app

1. **Add a callback route.** `signinPopup()` handled the whole round-trip
   in one call; the redirect flow needs a real route at `redirectUri`
   (`/auth/callback` in the example) that calls `signInCallback()` once.
   This is the one structural change — everything else is close to
   line-for-line.
2. **`login()` no longer returns a user.** The page navigates away. Move
   whatever you did with the returned `user` into the callback route
   instead (or subscribe via `onAuthStateChanged` — see below).
3. **`getAccessToken()` replaces reading `user.access_token` directly.**
   It silently refreshes an expired token (via `refresh_token`, which is
   why `offline_access` must stay in `scopes`) instead of handing back a
   token that's already dead.
4. **React apps:** replace whatever ad-hoc context/hook wrapped
   `UserManager` with `JummonAuthProvider` / `useJummonAuth()` from
   `@jummon/auth/react` — see `README.md` for the full example, including
   the callback route as a React component.

## What does NOT change

- The tenant, `client_id`, `redirect_uri`, and scopes are the same values
  — this is a transport change (popup → redirect), not a re-registration.
  Your `acme-app` client registration in Jummon needs no changes.
- Still a public client, still PKCE `S256`, still no secret anywhere in
  the browser.
- The token shape (`roles[]` / `permissions[]` claims, `sub`, etc.) is
  unchanged — `@jummon/auth` just parses it into `JummonUser` for you
  instead of you reading `user.profile` / decoding the JWT by hand.

## If you can't add a callback route right now

You can't — the redirect flow requires the browser to land somewhere with
your JS running to call `signInCallback()`. There's no popup-free shape
that skips this step; it's the trade-off for compatibility with browsers
that block popups. Budget it as a small, one-time route addition, not an
optional step.
