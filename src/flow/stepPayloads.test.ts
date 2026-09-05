import { describe, expect, it } from "vitest";
import { buildDeviceConsentSubmit, buildTermsAgreementSubmit } from "./stepPayloads";

describe("buildTermsAgreementSubmit", () => {
  it("accepted=false needs no other argument and sends only terms_agreed", () => {
    expect(buildTermsAgreementSubmit(false)).toEqual({ terms_agreed: "false" });
  });

  it("accepted=false ignores any opts passed (backend short-circuits before reading them anyway)", () => {
    expect(buildTermsAgreementSubmit(false, { consentAccepted: true, termsVersion: "v1" })).toEqual({
      terms_agreed: "false",
    });
  });

  it("accepted=true with consentAccepted:true sends all three string fields", () => {
    expect(buildTermsAgreementSubmit(true, { consentAccepted: true, termsVersion: "2026-09-01" })).toEqual({
      terms_agreed: "true",
      consent_accepted: "true",
      terms_version: "2026-09-01",
    });
  });

  it("accepted=true defaults terms_version to an empty string when omitted", () => {
    expect(buildTermsAgreementSubmit(true, { consentAccepted: true })).toEqual({
      terms_agreed: "true",
      consent_accepted: "true",
      terms_version: "",
    });
  });

  it("accepted=true with consentAccepted omitted throws (would hit missing_lgpd_consent server-side)", () => {
    expect(() => buildTermsAgreementSubmit(true)).toThrow(/consent_accepted/);
  });

  it("accepted=true with consentAccepted:false throws — LGPD consent must be explicit", () => {
    expect(() => buildTermsAgreementSubmit(true, { consentAccepted: false })).toThrow(/consent_accepted/);
  });

  it("every boolean-shaped field is a STRING, never a native JSON boolean (strconv.ParseBool wire quirk)", () => {
    const result = buildTermsAgreementSubmit(true, { consentAccepted: true, termsVersion: "v1" });
    expect(typeof result.terms_agreed).toBe("string");
    expect(typeof (result as { consent_accepted: string }).consent_accepted).toBe("string");
  });
});

describe("buildDeviceConsentSubmit", () => {
  it("accepted=true sends consent_accepted: \"true\" (string, not a native JSON boolean)", () => {
    const result = buildDeviceConsentSubmit(true);
    expect(result).toEqual({ consent_accepted: "true" });
    expect(typeof result.consent_accepted).toBe("string");
  });

  it("accepted=false sends consent_accepted: \"false\"", () => {
    expect(buildDeviceConsentSubmit(false)).toEqual({ consent_accepted: "false" });
  });
});
