import { describe, expect, it } from "vitest";
import { deriveLoginLayout } from "./loginLayout";

describe("deriveLoginLayout", () => {
  // --- Null-safe fallback (behavior-neutral for every tenant until authored) ---

  it("returns null when data has no login_layout key at all", () => {
    expect(deriveLoginLayout({})).toBeNull();
  });

  it("returns null when data is null/undefined", () => {
    expect(deriveLoginLayout(null)).toBeNull();
    expect(deriveLoginLayout(undefined)).toBeNull();
  });

  it("returns null when login_layout is explicitly null (unauthored tenant, omitempty round-trip)", () => {
    expect(deriveLoginLayout({ login_layout: null })).toBeNull();
  });

  it("returns null when login_layout is malformed (defensive, never throws)", () => {
    expect(deriveLoginLayout({ login_layout: "not-an-object" })).toBeNull();
    expect(deriveLoginLayout({ login_layout: {} })).toBeNull();
    expect(deriveLoginLayout({ login_layout: { methods: "not-an-array" } })).toBeNull();
  });

  // --- Real authored shape ---

  it("groups methods into primary/fallback/mfa lanes, sorted by order within each lane", () => {
    const result = deriveLoginLayout({
      login_layout: {
        methods: [
          { method: "password", lane: "fallback", order: 0 },
          { method: "social", lane: "primary", order: 1, emphasis: "secondary" },
          { method: "passkey", lane: "primary", order: 0, emphasis: "primary_cta" },
          { method: "otp", lane: "mfa", order: 0 },
        ],
      },
    });

    expect(result).not.toBeNull();
    expect(result!.primaryMethods).toEqual([
      { method: "passkey", emphasis: "primary_cta" },
      { method: "social", emphasis: "secondary" },
    ]);
    expect(result!.fallbackMethods).toEqual([{ method: "password", emphasis: null }]);
    expect(result!.mfaMethods).toEqual([{ method: "otp", emphasis: null }]);
  });

  it("drops methods placed in lane '' (explicitly unplaced) or an unrecognized lane", () => {
    const result = deriveLoginLayout({
      login_layout: {
        methods: [
          { method: "magic_link", lane: "", order: 0 },
          { method: "sso", lane: "not-a-real-lane", order: 0 },
          { method: "password", lane: "primary", order: 0 },
        ],
      },
    });

    expect(result).toEqual({
      primaryMethods: [{ method: "password", emphasis: null }],
      fallbackMethods: [],
      mfaMethods: [],
    });
  });

  it("an authored-but-empty methods array resolves to a present layout with all-empty lanes, not null", () => {
    expect(deriveLoginLayout({ login_layout: { methods: [] } })).toEqual({
      primaryMethods: [],
      fallbackMethods: [],
      mfaMethods: [],
    });
  });

  it("falls back to array index for a missing/non-numeric order, preserving stable insertion order for ties", () => {
    const result = deriveLoginLayout({
      login_layout: {
        methods: [
          { method: "social", lane: "primary" },
          { method: "sso", lane: "primary" },
          { method: "passkey", lane: "primary", order: 0 },
        ],
      },
    });

    // "social" (index 0) and "passkey" (order 0) tie at 0 — stable sort keeps
    // "social" first (original position); "sso" (index 1) sorts after both.
    expect(result!.primaryMethods.map((m) => m.method)).toEqual(["social", "passkey", "sso"]);
  });

  it("normalizes an unrecognized emphasis value to null rather than passing it through", () => {
    const result = deriveLoginLayout({
      login_layout: { methods: [{ method: "password", lane: "primary", order: 0, emphasis: "huge" }] },
    });
    expect(result!.primaryMethods[0]!.emphasis).toBeNull();
  });

  it("skips a non-object entry inside methods defensively", () => {
    const result = deriveLoginLayout({
      login_layout: { methods: [null, "garbage", { method: "password", lane: "primary", order: 0 }] },
    });
    expect(result!.primaryMethods).toEqual([{ method: "password", emphasis: null }]);
  });
});
