#!/usr/bin/env node
// B3 guard (RN launch blocker): npm workspaces does NOT rewrite a
// `file:`-protocol dependency specifier at publish time — it ships
// verbatim in the published package.json, so `npm install
// @jummon/auth-react-native` fails for every external user the moment
// their local filesystem doesn't happen to have `../..` relative to their
// own node_modules layout. `.cjs` extension forces CommonJS regardless of
// this package's `"type": "module"`, so `require()` always works here
// irrespective of Node/npm version quirks around `-e`/`--eval` module type
// inference.
//
// Runs as this package's `prepack` — npm invokes `prepack` automatically
// before `npm pack`/`npm publish` (and before `npm install` compiles it as
// a workspace member's own `prepare`/`prepack` step), so a `file:`
// specifier can never silently ship again.
const path = require("node:path");
const pkg = require(path.join(__dirname, "..", "package.json"));

const offenders = Object.entries({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies }).filter(
  ([, version]) => typeof version === "string" && version.startsWith("file:"),
);

if (offenders.length > 0) {
  console.error(
    `[verify-no-file-deps] BLOCKED: ${pkg.name}@${pkg.version} has file:-protocol dependenc${
      offenders.length === 1 ? "y" : "ies"
    } that would break "npm install ${pkg.name}" for every external user:`,
  );
  for (const [name, version] of offenders) {
    console.error(`  - ${name}: ${version}`);
  }
  console.error("Use a real semver range instead — npm workspaces still symlinks locally when it's satisfied.");
  process.exit(1);
}

console.log(`[verify-no-file-deps] OK — no file: specifiers in ${pkg.name}@${pkg.version}.`);
