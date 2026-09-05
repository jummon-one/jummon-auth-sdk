// Metro (React Native's bundler) resolution fallback (B2, RN launch
// blocker) — Metro only honors package.json's `exports` map with
// `unstable_enablePackageExports` enabled, which isn't the default across
// the `react-native >=0.70` peer range `@jummon/auth-react-native` targets.
// Without that flag, Metro resolves a subpath import like
// `@jummon/auth/core` the pre-`exports` way: literally as
// `<package root>/core.js`, ignoring `package.json` entirely for subpaths.
// This file exists ONLY for that fallback path — modern resolvers (Node,
// bundlers with `exports` support, Metro with the flag enabled) use the
// `exports` map in `package.json` instead and never load this file.
//
// Static, hand-maintained, NOT part of the `dist/` build output — `tsup`'s
// `clean: true` only wipes `dist/`, so this survives every build.
export * from "./dist/core.js";
