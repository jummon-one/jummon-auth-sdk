import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  // Metro (RN's bundler) re-transpiles from source anyway, but ES2020 keeps
  // this build's own syntax aligned with `@jummon/auth`'s web target
  // (`../../tsup.config.ts`) — the two packages share the same agnostic
  // core's output shape.
  target: "es2020",
  minify: false,
  external: ["@jummon/auth", "@jummon/auth/core", "react-native"],
});
