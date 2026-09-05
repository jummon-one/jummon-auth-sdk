import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Plain Node — no `window`/`document` needed. Every adapter under test
    // takes its native dependency by constructor injection (mocked plain
    // objects), never a global, so there is nothing DOM-shaped to simulate.
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
