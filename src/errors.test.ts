import { describe, expect, it } from "vitest";
import { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "./errors";

describe("mapHeadlessErrorCode", () => {
  it("collapses INVALID_CREDENTIALS and USER_NOT_FOUND to the same code (enumeration-safety, security-note.md §3)", () => {
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2001")).toBe("invalid_credentials");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2004")).toBe("invalid_credentials");
  });

  it("maps the rest of ux-spec-wave1.md §3's table", () => {
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2003")).toBe("invalid_mfa_code");
    expect(mapHeadlessErrorCode("AUTH-LIM-5001")).toBe("rate_limited");
    expect(mapHeadlessErrorCode("AUTH-EXP-4001")).toBe("flow_expired");
    expect(mapHeadlessErrorCode("AUTH-EXP-4002")).toBe("flow_expired");
    expect(mapHeadlessErrorCode("AUTH-EXP-4003")).toBe("flow_expired");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2010")).toBe("passkey_failed");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2216")).toBe("passkey_failed");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2300")).toBe("social_login_failed");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2301")).toBe("social_login_failed");
  });

  it("falls back to unknown for anything unmapped, including null/undefined", () => {
    expect(mapHeadlessErrorCode("AUTH-INT-9999")).toBe("unknown");
    expect(mapHeadlessErrorCode(undefined)).toBe("unknown");
    expect(mapHeadlessErrorCode(null)).toBe("unknown");
  });
});

describe("toJummonAuthError", () => {
  it("passes through an existing JummonAuthError unchanged", () => {
    const original = new JummonAuthError("flow_expired", "expired");
    expect(toJummonAuthError(original)).toBe(original);
  });

  it("maps known oidc-client-ts error codes", () => {
    expect(toJummonAuthError({ error: "login_required" }).code).toBe("login_required");
    expect(toJummonAuthError({ error: "access_denied" }).code).toBe("access_denied");
  });

  it("collapses anything else to unknown, preserving the message", () => {
    const err = toJummonAuthError(new Error("boom"));
    expect(err.code).toBe("unknown");
    expect(err.message).toBe("boom");
  });
});
