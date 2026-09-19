import { JummonAuthError } from "../errors";
import { decodeCredentialCreationOptions, encodeAttestationForWire } from "../flow/webauthn";
import { browserWebAuthn } from "../platform/browser/webauthn";
import type { PlatformWebAuthn } from "../core/platform/types";

/**
 * Native/browser WebAuthn ceremony runner for the credential-type-aware
 * account-recovery journey (issue #163/#165,
 * `engineering-team/initiatives/account-recovery/design/
 * CREDENTIAL-TYPE-AWARE-RECOVERY-DESIGN.md` §2/§11.2). Deliberately a
 * SEPARATE module from `./passkeyEnrollment.ts` (the authenticated
 * self-service `/catalog/me/credentials/passkeys/{begin,finish}` ceremony):
 * this one runs from an UNAUTHENTICATED, recovery-verified context — there
 * is no access_token, no `apiHost` fetch of its own. The challenge
 * ({@link RecoveryPasskeyChallenge}) is whatever `enroll-passkey-form`'s
 * `OnGet` response already carried (`dynamic-flows`' generic step-submit
 * machinery fetched it — see `HeadlessRecoveryFlowCore.enrollPasskey()` in
 * `../core/headlessRecoveryFlowCore.ts`), and the result is handed back to
 * that SAME generic `submit()` call, never a dedicated HTTP request of its
 * own (design §11.2: "Result is POSTed back through the SAME generic
 * submit('enroll-passkey-form', {...}) call").
 *
 * Reuses `flow/webauthn.ts`'s codec UNCHANGED — `decodeCredentialCreation
 * Options`/`encodeAttestationForWire` are byte-identical to the in-login
 * `fido-registration` step and the self-service enrollment ceremony
 * (`./passkeyEnrollment.ts`) — no new wire format on either the decode or
 * the encode side.
 *
 * `webauthn: PlatformWebAuthn` is the SAME extension point
 * `enrollPasskey()`/`HeadlessAuthFlow.registerPasskey()` already document
 * as the intended seam for a React Native caller (Phase 2) — a native
 * iOS/Android app supplies its own `PlatformWebAuthn` (ASAuthorization
 * PlatformPublicKeyCredentialProvider / Android Credential Manager,
 * wrapped) instead of the browser's `navigator.credentials`.
 *
 * NOT built here (design §11's Wave 4, explicitly deferred/tracked
 * separately, out of this dispatch's scope): the mobile deep-link/
 * Universal-Link resume path (R12), the PKCE proof-of-possession binding
 * the recovery-token redemption to the initiating device (R13/R17), the
 * cross-device short-code fallback (R14), and in-memory-only/never-
 * persisted-to-disk token handling (R15/R16) —
 * `RECOVERY-THREAT-MODEL.md` §3.5. This module only closes the "how does a
 * native app run the actual WebAuthn ceremony" gap design §11.2 names as
 * "purely SDK-side"; the transport-security requirements around HOW the
 * recovery journey is reached on mobile are a separate, larger piece of
 * work the design's own Wave roadmap places in Wave 4.
 */
export interface RecoveryPasskeyChallenge {
  ceremonyId: string;
  /** Base64 outer-envelope-encoded `PublicKeyCredentialCreationOptions` — identical shape to `BeginResponse.Options` (`jummon-auth-engine/internal/passkeys/handler.go`) and the recovery-specific `enroll-passkey-form` `OnGet` response. */
  options: string;
}

export interface RecoveryPasskeyAttestationSubmission {
  ceremony_id: string;
  attestation: Record<string, unknown>;
  name?: string;
}

/**
 * Runs the WebAuthn `create()` ceremony against an ALREADY-FETCHED
 * challenge (the caller — `HeadlessRecoveryFlowCore.enrollPasskey()` —
 * already has it from the current step's response) and returns the
 * wire-ready payload to `submit()` back to `enroll-passkey-form`. Never
 * performs its own network call — there is no dedicated recovery-passkey
 * HTTP endpoint on the SDK side, only the generic execution-flow step
 * submit.
 */
export async function runRecoveryPasskeyCeremony(
  challenge: RecoveryPasskeyChallenge,
  name: string | undefined,
  webauthn: PlatformWebAuthn = browserWebAuthn,
): Promise<RecoveryPasskeyAttestationSubmission> {
  if (!webauthn.isSupported()) {
    throw new JummonAuthError(
      "passkey_origin_unsupported",
      "Passkeys aren't available on this device/browser — account recovery requires platform " +
        "authenticator support (a secure context on web, or a native passkey provider on mobile).",
    );
  }

  let credential: PublicKeyCredential | null;
  try {
    credential = await webauthn.create(decodeCredentialCreationOptions(challenge.options));
  } catch (err) {
    throw recoveryPasskeyFailedError(err);
  }
  if (!credential) {
    throw recoveryPasskeyFailedError();
  }

  return {
    ceremony_id: challenge.ceremonyId,
    attestation: encodeAttestationForWire(credential),
    name,
  };
}

function recoveryPasskeyFailedError(cause?: unknown): JummonAuthError {
  return new JummonAuthError(
    "passkey_failed",
    "We couldn't finish setting up your new passkey. Try again, or use another recovery option.",
    cause,
  );
}
