import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  // Node-only target — this package uses `node:crypto` and is never meant
  // to reach a browser bundler. ES2022 (not ES2020 like @jummon/auth) is
  // safe here precisely because there is no browser compatibility matrix
  // to respect.
  target: "node18",
  platform: "node",
  minify: false,
});
