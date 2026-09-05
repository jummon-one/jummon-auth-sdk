# @jummon/auth-react-native

React Native / Expo adapters for [`@jummon/auth`](https://www.npmjs.com/package/@jummon/auth)'s
platform-agnostic core (`@jummon/auth/core`). Ships the same headless in-app
login (`mode: "headless"` — password, passkey, social) `@jummon/auth` ships
for the web, wired to RN-native storage/crypto/navigation/WebAuthn instead of
`window`/`navigator`/`localStorage`.

**Headless-only.** RN has no addressable URL bar to redirect to a hosted
login page and back, so this package never offers a "redirect" mode —
`createJummonAuthReactNative()` always builds a headless client.

## Install

```bash
npm install @jummon/auth @jummon/auth-react-native
# + whichever native modules you'll pass in (see below) — none are hard
# dependencies of this package, you choose the versions your app already pins:
npm install @react-native-async-storage/async-storage expo-secure-store expo-crypto
npm install react-native-passkey # optional — omit if passkeys aren't Wave-1 for your app
```

This package never `import`s any of those native modules itself — every
adapter is a small factory function that takes the ALREADY-IMPORTED module
(or an object shaped like it) as a constructor argument. That's why none of
them are hard `dependencies`: you control exactly which native module
satisfies each shape, including a `react-native-keychain`-backed shim instead
of `expo-secure-store` (see `SecureStorageLike` below) on a bare-RN app.

## Quick start

```tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import * as ExpoCrypto from "expo-crypto";
import { Linking } from "react-native";
import { Passkey } from "react-native-passkey"; // optional
import { createJummonAuthReactNative } from "@jummon/auth-react-native";
import { JummonAuthProvider, useHeadlessAuthFlow, useJummonAuth } from "@jummon/auth/react";

const client = createJummonAuthReactNative(
  {
    tenant: "acme", // slug, never the tenant UUID
    clientId: "acme-app",
    redirectUri: "acme://auth/callback", // your app's registered custom scheme / deep link
    issuerHost: "idm.jummon.com", // "idm.jummon.dev" in the dev environment
  },
  {
    asyncStorage: AsyncStorage,
    secureStore: SecureStore,
    expoCrypto: ExpoCrypto,
    linking: Linking, // or `import * as Linking from "expo-linking"`
    passkey: Passkey, // omit entirely if you have no passkey story yet
  },
);

export function App() {
  return (
    <JummonAuthProvider client={client}>
      <LoginScreen />
    </JummonAuthProvider>
  );
}

function LoginScreen() {
  const { snapshot, start, submitPassword, startPasskeyLogin, startSocialLogin, submitMfaCode } =
    useHeadlessAuthFlow();

  React.useEffect(() => {
    start();
  }, []);

  // Render your OWN UI off `snapshot.status` — see @jummon/auth's README for
  // the full state machine (needs_credentials, needs_mfa, needs_required_action, …).
  return null;
}

function Profile() {
  const { user, signOut } = useJummonAuth();
  // ...
}
```

`JummonAuthProvider`/`useJummonAuth`/`useHeadlessAuthFlow` are the SAME
exports the web package (`@jummon/auth/react`) ships — this package only
supplies the `client` you hand to the provider's `client` prop; the React
binding itself is platform-agnostic and never imported here.

## Social login / deep-link return

`redirect()` opens the system browser (`Linking.openURL` — never an in-app
WebView; Google and other IdPs block embedded-WebView OAuth outright).
Register your `redirectUri`'s scheme (`acme://auth/callback` above) as a deep
link in your app config (Expo: `app.json`'s `scheme`; bare RN: the platform's
own URL-scheme/associated-domain setup) so the OS routes the provider's
callback back into your app. On the screen your `redirectUri` points at, call
`useHeadlessAuthFlow().resume()` on mount — same call the web package's
social-redirect flow makes, just resolved off the RN `Linking` adapter's
cold-start/`'url'`-event tracking instead of `window.location`.

## Storage split

- Non-secret, short-lived flow-resume state → `AsyncStorage`.
- Long-lived session tokens (`access_token`/`refresh_token`) → your secure
  backend, routed by key prefix (`createReactNativeStorage`, exported from
  `./adapters` too). `secureStore` accepts either `expo-secure-store`'s
  `{getItemAsync,setItemAsync,deleteItemAsync}` shape, or anything shaped
  like `AsyncStorage` (`{getItem,setItem,removeItem}`) — wrap
  `react-native-keychain` (or another bare-RN secure store) into that second
  shape if you're not on Expo.

## Known runtime gotcha — `atob`/`btoa`/`Buffer`

This package's own base64/base64url codec (`src/internal/base64.ts`) is
dependency-free (no `atob`/`btoa`/`Buffer` assumption) specifically because
Hermes (RN's default JS engine) doesn't ship those globals. If your app also
pulls in `@jummon/auth`'s web-oriented code paths some other way, make sure
you're only importing `@jummon/auth/core` (as this package does) — the main
`@jummon/auth` entry and `@jummon/auth/react`'s non-headless bits are
web-oriented and may assume browser globals this package's own code never
touches.

## Passkeys

`react-native-passkey`'s request/response objects are JSON (every binary
field is already a base64url string) — this package's WebAuthn adapter
(`createReactNativeWebAuthn`) is the translation layer between that JSON
shape and the DOM-shaped `PublicKeyCredential` the agnostic core speaks. Omit
`passkey` from `createReactNativePlatformAdapters()`/
`createJummonAuthReactNative()` entirely if passkeys aren't in scope yet —
`registerPasskey()`/`startPasskeyLogin()` degrade to a clear
`passkey_origin_unsupported`/`passkey_failed` error instead of crashing.

## Risk signals

Opt-in client risk-signal collection (initiative #85 — see
[`@jummon/auth`'s README](../../README.md#opt-in-client-risk-signal-collection-collectrisksignals)
for the full allowlist/spec) works the same as on web: pass
`collectRiskSignals: true` in the options you give
`createJummonAuthReactNative()`. `device_id`/`flow_ms`/`schema` need no RN
dependency at all (computed by the agnostic core against your
`asyncStorage`/`expoCrypto` deps); `tz` has a built-in `Intl` fallback that
works out of the box on modern Hermes; `lang`/`device_class` have no
first-party RN API, so supply them yourself (RN has no built-in
`navigator.language` equivalent):

```ts
import * as Localization from "expo-localization"; // or react-native-localize

const client = createJummonAuthReactNative(
  { tenant: "acme", clientId: "acme-app", redirectUri: "acme://auth/callback", collectRiskSignals: true },
  {
    asyncStorage: AsyncStorage,
    secureStore: SecureStore,
    expoCrypto: ExpoCrypto,
    linking: Linking,
    riskSignals: {
      getLanguage: () => Localization.getLocales()[0]?.languageTag ?? null,
      getDeviceClass: () => (Localization.getLocales()[0] /* or Dimensions-based heuristic */ ? "mobile" : null),
    },
  },
);
```

Omit `riskSignals` entirely for the `Intl`-only fallback (timezone only) —
`createReactNativeRiskSignals()` never throws and every field degrades to
`null` rather than crashing when a dep is missing or its callback throws.
