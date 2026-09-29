#!/usr/bin/env node
// Local-only workspace-root linking (issue #235 build blocker).
//
// npm workspaces auto-symlinks a `packages/*` member's dependency on a
// SIBLING `packages/*` package, but @jummon/auth is the monorepo ROOT (the
// `workspaces` container itself, not a `packages/*` member) — npm never
// symlinks it for this package. Left alone, `@jummon/auth-react-native`'s
// local build/typecheck resolves its `@jummon/auth` dependency from
// whatever was last published to the registry, not the reconciled source
// sitting two directories up in this same checkout (see recovery-flow #165:
// registry 0.4.0 predates `HeadlessRecoveryFlowCore`/
// `HeadlessRecoveryFlowSnapshot`).
//
// This script replicates what npm's linker does for a real workspace
// member: it points `node_modules/@jummon/auth` at the repo root via a
// symlink, replacing any registry-materialized copy. It is LOCAL-ONLY —
// this package's own `package.json` `dependencies["@jummon/auth"]` stays a
// normal external-install-safe semver range (never `file:`/`*`; see
// `verify-no-file-deps.cjs`), so a real `npm install
// @jummon/auth-react-native` by an external consumer is completely
// unaffected: there is no repo root to link to in that layout, and the
// guard below detects that and no-ops instead of erroring.
//
// Idempotent + no-op-safe: correct to call repeatedly (wired as
// postinstall + pretypecheck + prebuild) and safe if the symlink already
// points at the right place, or if there is nothing to link.
//
// Uses only relative paths derived from `__dirname` (this file's own
// on-disk location) — correct under a fresh CI checkout regardless of the
// working directory npm invokes the lifecycle script from.
const fs = require("node:fs");
const path = require("node:path");

const packageDir = path.join(__dirname, ".."); // packages/react-native
const repoRoot = path.join(packageDir, "..", ".."); // monorepo root
const scopeDir = path.join(packageDir, "node_modules", "@jummon");
const linkPath = path.join(scopeDir, "auth");

// Sanity guard: only link if repoRoot really looks like the @jummon/auth
// monorepo root. Defends against this script running in a layout it
// wasn't written for — most importantly, a real external consumer's
// `npm install @jummon/auth-react-native`, where
// `node_modules/@jummon/auth-react-native/../..` is just their own
// `node_modules` directory (no package.json there at all).
const repoRootPkgPath = path.join(repoRoot, "package.json");
if (!fs.existsSync(repoRootPkgPath)) {
  console.log(
    `[link-workspace-root] no package.json at ${repoRootPkgPath} — skipping (not the @jummon/auth monorepo checkout, e.g. a standalone external install; nothing to link).`,
  );
  process.exit(0);
}

let repoRootPkg;
try {
  repoRootPkg = JSON.parse(fs.readFileSync(repoRootPkgPath, "utf8"));
} catch (err) {
  console.log(`[link-workspace-root] could not parse ${repoRootPkgPath} — skipping: ${err.message}`);
  process.exit(0);
}

if (repoRootPkg.name !== "@jummon/auth") {
  console.log(
    `[link-workspace-root] ${repoRoot} is package "${repoRootPkg.name}", not "@jummon/auth" — skipping (not the monorepo checkout).`,
  );
  process.exit(0);
}

fs.mkdirSync(scopeDir, { recursive: true });

const relativeTarget = path.relative(scopeDir, repoRoot);

let existing;
try {
  existing = fs.lstatSync(linkPath);
} catch {
  existing = null;
}

if (existing && existing.isSymbolicLink()) {
  const current = fs.readlinkSync(linkPath);
  const resolvedCurrent = path.resolve(scopeDir, current);
  if (resolvedCurrent === repoRoot) {
    console.log(`[link-workspace-root] OK — ${linkPath} already -> ${repoRoot}`);
    process.exit(0);
  }
}

// Replace whatever is there — a registry-materialized copy (regular
// directory) from a previous `npm install`, or a stale/incorrect symlink.
if (existing) {
  fs.rmSync(linkPath, { recursive: true, force: true });
}

fs.symlinkSync(relativeTarget, linkPath, process.platform === "win32" ? "junction" : "dir");
console.log(`[link-workspace-root] linked ${linkPath} -> ${repoRoot} (relative: ${relativeTarget})`);
