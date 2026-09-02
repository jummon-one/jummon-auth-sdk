import { describe, expect, it } from "vitest";
import { JummonAuthError, mapHeadlessErrorCode, toJummonAuthError } from "./errors";

describe("mapHeadlessErrorCode", () => {
  it("checks Family A (local, snake_case) codes verbatim BEFORE the AUTH-* table (wire-contract-v1.md §4.2)", () => {
    // Previously these always collapsed to "unknown" because the mapper
    // only recognized AUTH-*-shaped strings — the literal blocker #3 bug.
    expect(mapHeadlessErrorCode("flow_expired")).toBe("flow_expired");
    expect(mapHeadlessErrorCode("cors_origin_rejected")).toBe("cors_origin_rejected");
    expect(mapHeadlessErrorCode("flow_token_missing")).toBe("flow_not_started");
  });

  it("collapses INVALID_CREDENTIALS and USER_NOT_FOUND to the same code (enumeration-safety, security-note.md §3)", () => {
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2001")).toBe("invalid_credentials");
    expect(mapHeadlessErrorCode("AUTH-AUTHN-2004")).toBe("invalid_credentials");
  });

  it("maps the rest of the AUTH-* table (Family B)", () => {
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

  it("falls back to the `type` bucket for an unmapped code instead of a bare unknown (wire-contract-v1.md §4.3)", () => {
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "authentication")).toBe("invalid_credentials");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "authorization")).toBe("access_denied");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "forbidden")).toBe("access_denied");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "expired")).toBe("flow_expired");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "network")).toBe("network_unreachable");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "configuration")).toBe("unknown");
    expect(mapHeadlessErrorCode("AUTH-INT-9999", "not_found")).toBe("unknown");
    expect(mapHeadlessErrorCode("AUTH-INT-9999")).toBe("unknown");
  });

  it("falls back to unknown for anything unmapped, including null/undefined, when no `type` is present either", () => {
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
