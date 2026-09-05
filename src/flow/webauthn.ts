import { base64ToBytes, base64UrlToBytes, bytesToBase64Url } from "../internal/base64";

/**
 * WebAuthn options/response wire encoding for `HeadlessAuthFlow`'s passkey
 * ceremonies (`startPasskeyLogin`, `registerPasskey`,
 * `implementation-plan.md` §8 item 5). Talks `navigator.credentials`
 * directly instead of an SSR page's `@simplewebauthn/browser` script tag —
 * same two-phase wire contract `jummon-login-interface/src/pages/login/
 * index.tsx:120-238` already implements against auth-engine's go-webauthn
 * server (`jummon-auth-engine/internal/authentication/authenticationstep/
 * steps/authextensions/fido_validator.go`), which parses the standard
 * WebAuthn-JSON response shape (`id`/`rawId`/`type`/`response.*`,
 * base64url-encoded) — this file produces exactly that shape so no server
 * change is needed to accept it.
 *
 * Two base64 alphabets are in play, deliberately: the outer envelope
 * (`fido_login_options` / `fido_registration_options`) is Go's
 * `encoding/json` default `[]byte` marshaling — **standard** base64 — while
 * every field *inside* that decoded JSON (`challenge`, credential `id`s)
 * follows the WebAuthn spec's own **base64url** convention. Getting these
 * swapped silently corrupts the challenge and fails the ceremony.
 */

interface WireCredentialDescriptor {
  id: string;
  type: "public-key";
  transports?: AuthenticatorTransport[];
}

interface WireCredentialRequestOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: WireCredentialDescriptor[];
}

export function decodeCredentialRequestOptions(base64Options: string): PublicKeyCredentialRequestOptions {
  const wire = JSON.parse(decodeOuterEnvelope(base64Options)) as WireCredentialRequestOptions;
  return {
    challenge: base64UrlToBytes(wire.challenge),
    timeout: wire.timeout,
    rpId: wire.rpId,
    userVerification: wire.userVerification,
    allowCredentials: wire.allowCredentials?.map((cred) => ({
      id: base64UrlToBytes(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
  };
}

interface WireCredentialCreationOptions {
  rp: PublicKeyCredentialRpEntity;
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: WireCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
}

export function decodeCredentialCreationOptions(base64Options: string): PublicKeyCredentialCreationOptions {
  const wire = JSON.parse(decodeOuterEnvelope(base64Options)) as WireCredentialCreationOptions;
  return {
    rp: wire.rp,
    user: {
      id: base64UrlToBytes(wire.user.id),
      name: wire.user.name,
      displayName: wire.user.displayName,
    },
    challenge: base64UrlToBytes(wire.challenge),
    pubKeyCredParams: wire.pubKeyCredParams,
    timeout: wire.timeout,
    excludeCredentials: wire.excludeCredentials?.map((cred) => ({
      id: base64UrlToBytes(cred.id),
      type: cred.type,
      transports: cred.transports,
    })),
    authenticatorSelection: wire.authenticatorSelection,
    attestation: wire.attestation,
  };
}

export function encodeAssertionForWire(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

export function encodeAttestationForWire(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function decodeOuterEnvelope(base64: string): string {
  return new TextDecoder().decode(base64ToBytes(base64));
}
