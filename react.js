// Metro (React Native's bundler) resolution fallback (B2, RN launch
// blocker) — see `./core.js`'s doc comment for the full rationale; same
// reasoning applies to the `@jummon/auth/react` subpath (the headless-aware
// React binding — `JummonAuthProvider`/`useJummonAuth`/`useHeadlessAuthFlow`
// — that RN apps import unchanged, per `@jummon/auth-react-native`'s
// README).
//
// Static, hand-maintained, NOT part of the `dist/` build output.
export * from "./dist/react.js";
