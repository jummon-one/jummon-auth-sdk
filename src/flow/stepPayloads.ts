/**
 * Typed request/response shapes for the required-action step refs
 * `needs_required_action` otherwise flattens into one opaque bucket
 * (`HeadlessFlowSnapshot.data: Record<string, unknown>`) — folding the
 * wire-quirk knowledge that used to live only in the Prummo integration
 * guide (`engineering-team/initiatives/headless-embeddable-auth/
 * PRUMMO-INTEGRATION-GUIDE.md` §4.1) into the SDK itself, so a new
 * integrator reads types/doc comments here instead of a tribal doc.
 *
 * Confirmed against `jummon-auth-engine`'s `SubmitStepData`
 * (`internal/authentication/authenticationstep/models/models.go:252-290`)
 * and each step's `OnPost`/`OnGet`
 * (`internal/authentication/authenticationstep/steps/{terms_agreement,
 * otp_configure,create_password}.go`). One universal wire quirk applies to
 * every boolean field below: the auth-engine reads booleans via Go's
 * `strconv.ParseBool` off a JSON STRING field, never a native JSON
 * boolean — every `"true"`/`"false"` type here is a literal string type,
 * not `boolean`, on purpose. Sending `true` (JSON boolean) is silently
 * dropped server-side, not rejected — an easy, silent bug for a
 * hand-rolled integration to hit.
 *
 * Only the 3 refs with a same-shape SDK method already exist as typed
 * submit builders here (`terms-agreement` gets a new one below;
 * `otp-configure-form`/`create-password-form` reuse `submitMfaCode`-style
 * dedicated methods added alongside this file — see `headlessAuthFlowCore.ts`).
 * `verify-email-form`, `validate-phone-form`, and `device-consent-form`
 * are typed here for documentation/DX (so their shape is discoverable via
 * autocomplete instead of a guide) but do NOT yet get a dedicated
 * `HeadlessAuthFlow` method — tracked as a follow-up, see this file's
 * closing doc comment for why each was deferred rather than shipped now.
 */

/** `terms-agreement` (`terms_agreement.go:81-134`) — LGPD-flavored terms + consent. */
export type TermsAgreementSubmit =
  | {
      terms_agreed: "true";
      /** Required when `terms_agreed` is `"true"` — LGPD requires a separate, explicit consent from the generic terms acceptance. Omitting/`"false"` here while `terms_agreed` is `"true"` is rejected server-side with `missing_lgpd_consent`, even though `terms_agreed` itself was accepted. */
      consent_accepted: "true";
      /** Free-form version tag of the terms content actually shown to the user — persisted verbatim, not validated against a server-side enum. */
      terms_version: string;
    }
  | {
      /** A decline needs no other field — the backend short-circuits on `terms_agreed === "false"` before ever looking at `consent_accepted`/`terms_version` (`terms_agreement.go:108-121`), surfaced as `user_declined_the_terms`. */
      terms_agreed: "false";
    };

/** `otp-configure-form` (`otp_configure.go:83-109`) — initial TOTP setup DURING login (distinct from `JummonAuthClient.beginOtpEnroll()`'s standalone post-login enrollment, `../types.ts`'s `OtpEnrollmentChallenge` doc comment). */
export interface OtpConfigureSubmit {
  /** The 6-digit code the authenticator app generated from the secret in `data.otp_string` (an `otpauth://` URI, minted once per `AuthRequest` — a repeated `poll()` never regenerates it). */
  otp: string;
}

/** `create-password-form` (`create_password.go:103-247`) — already has a dedicated method, `HeadlessAuthFlow.setPassword()`; typed here too for a single place to read every required-action shape. */
export interface CreatePasswordSubmit {
  password: string;
  confirmation_password: string;
}
/** `data` shape the step preceding `create-password-form` (`start`/`submit`/`poll`) carries — the tenant's LIVE password policy, for client-side validation before submit (the backend always revalidates server-side regardless). */
export interface CreatePasswordStepData {
  name?: string;
  /** `"onboarding" | "recover_password" | "recover_otp" | ""` — informational only, not validated against server-side by the SDK. */
  action?: string;
  password_config?: {
    accept_birthdate?: boolean;
    accept_name?: boolean;
    requires_special_chars?: boolean;
    requires_numbers?: boolean;
    requires_lowercase?: boolean;
    requires_uppercase?: boolean;
    min_length?: number;
    max_length?: number;
    last_uses?: number;
  };
}

/**
 * `verify-email-form` (onboarding, `verify_email.go:116-177`) — TYPE ONLY,
 * no dedicated `HeadlessAuthFlow` method yet (tracked follow-up, see this
 * file's closing comment). `email` is always the MASKED value the step's
 * `data` already returned (`j***@example.com`), round-tripped verbatim —
 * never the user's real address, which never reaches the client here.
 */
export type VerifyEmailSubmit =
  | { email: string; otp: string }
  | { email: string; resend: "true" };
export interface VerifyEmailStepData {
  /** Masked: first local-part char + `@` + full domain. */
  email: string;
  /** RFC3339 — disable the "resend" affordance client-side until this passes. */
  resend_available_at: string;
}

/**
 * `validate-phone-form` (onboarding, `validate_phone.go:122-200`) — TYPE
 * ONLY, same follow-up status as `verify-email-form`. `phone` is masked
 * the same way; the SMS code (Sinch Verification API) is **4 digits**,
 * not 6 like TOTP/email — a real, easy-to-miss field-length mismatch if a
 * UI reuses the same input mask as the email/TOTP step.
 */
export type ValidatePhoneSubmit =
  | { phone: string; otp: string }
  | { phone: string; resend: "true" };
export interface ValidatePhoneStepData {
  /** Masked, e.g. `*******1234`. */
  phone: string;
  resend_available_at: string;
}

/**
 * `device-consent-form` (OIDC device-code consent, `device_consent.go:84-117`).
 *
 * Previously TYPE-ONLY: the backend route this step's submit reuses
 * (`jummon-login-interface`'s `services-auth.ts:354-357`) used to read
 * `consent_accepted` off `request.query.accepted` — the QUERY STRING — for
 * this one ref only, ignoring the JSON body even if well-formed (item B4,
 * `engineering-team/initiatives/headless-embeddable-auth/
 * SDK-DEFINITIVE-REVIEW-SYNTHESIS-2026-09-05.md`). **B4 shipped**
 * (`jummon-login-interface` commit `a7487e0`): the route now reads
 * `consent_accepted` from the JSON body first, falling back to the query
 * string only for backward compatibility — the SDK sends body-only, like
 * every other required-action step, via `buildDeviceConsentSubmit()`/
 * `HeadlessAuthFlow.submitDeviceConsent()` below.
 */
export type DeviceConsentSubmit = {
  consent_accepted: "true" | "false";
};
export interface DeviceConsentStepData {
  client_name: string;
  scopes: Array<{ name: string; description?: string; id: string; claim_mapper?: string; restricted?: boolean }>;
}

/**
 * Builds the `submitRequiredAction("device-consent-form", ...)` body from a
 * boolean, applying the string-not-boolean wire quirk (this file's top doc
 * comment) — same shape/rationale as `buildTermsAgreementSubmit()`, minus
 * the LGPD consent-gating (this step has no separate consent field).
 */
export function buildDeviceConsentSubmit(accepted: boolean): DeviceConsentSubmit {
  return { consent_accepted: accepted ? "true" : "false" };
}

/**
 * Builds the `submitRequiredAction("terms-agreement", ...)` body from a
 * boolean + the optional consent/version fields, applying the
 * string-not-boolean wire quirk (this file's top doc comment) so callers
 * never hand-construct `"true"`/`"false"` strings themselves. Throws
 * synchronously (a plain `Error`, not `JummonAuthError` — this is a
 * caller-side programming error, not a network/backend failure) if
 * `accepted` is `true` but `consentAccepted` was passed `false`/omitted —
 * catches the LGPD `missing_lgpd_consent` mistake at call time instead of a
 * round trip to the backend.
 */
export function buildTermsAgreementSubmit(
  accepted: boolean,
  opts?: { consentAccepted?: boolean; termsVersion?: string },
): TermsAgreementSubmit {
  if (!accepted) {
    return { terms_agreed: "false" };
  }
  if (opts?.consentAccepted !== true) {
    throw new Error(
      'buildTermsAgreementSubmit(true, ...): "consent_accepted" is required (LGPD) whenever terms_agreed is true — ' +
        "pass { consentAccepted: true, termsVersion } or the backend rejects with missing_lgpd_consent.",
    );
  }
  return {
    terms_agreed: "true",
    consent_accepted: "true",
    terms_version: opts?.termsVersion ?? "",
  };
}
