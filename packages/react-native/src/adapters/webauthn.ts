import type { PlatformWebAuthn } from "@jummon/auth/core";
import { base64UrlToBytes, bytesToBase64Url } from "../internal/base64";

/**
 * Structural shape of `react-native-passkey`'s `Passkey` class — defined
 * locally, never imported, same "peer, not a dependency" reasoning as the
 * other adapters. Unlike the DOM's `navigator.credentials` (binary
 * `ArrayBuffer` fields throughout), `react-native-passkey`'s request/result
 * objects are JSON-safe: every binary field is already a base64url STRING —
 * this adapter's whole job is translating between that JSON shape and the
 * DOM-shaped `PublicKeyCredentialCreationOptions`/`PublicKeyCredential` the
 * agnostic core (`@jummon/auth/core`, `../../flow/webauthn.ts`'s
 * encode/decode pair) speaks — see `PlatformWebAuthn`'s doc comment
 * (`@jummon/auth/core`) for why the DOM type is "a type-level convenience,
 * not a runtime browser requirement."
 */
export interface ReactNativePasskeyLike {
  isSupported(): boolean;
  create(request: PasskeyCreateRequest): Promise<PasskeyCreateResult>;
  get(request: PasskeyGetRequest): Promise<PasskeyGetResult>;
}

interface WireCredentialDescriptor {
  id: string;
  type: "public-key";
  transports?: string[];
}

export interface PasskeyCreateRequest {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  excludeCredentials?: WireCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: string;
}

export interface PasskeyCreateResult {
  id: string;
  rawId: string;
  response: { clientDataJSON: string; attestationObject: string };
}

export interface PasskeyGetRequest {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: string;
  allowCredentials?: WireCredentialDescriptor[];
}

export interface PasskeyGetResult {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
}

function toBytes(value: BufferSource): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
}

function toWireDescriptor(cred: PublicKeyCredentialDescriptor): WireCredentialDescriptor {
  return { id: bytesToBase64Url(toBytes(cred.id)), type: "public-key", transports: cred.transports };
}

export function createReactNativeWebAuthn(passkey: ReactNativePasskeyLike): PlatformWebAuthn {
  return {
    isSupported(): boolean {
      return passkey.isSupported();
    },

    async create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential | null> {
      const result = await passkey.create({
        rp: options.rp,
        user: {
          id: bytesToBase64Url(toBytes(options.user.id)),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        challenge: bytesToBase64Url(toBytes(options.challenge)),
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        excludeCredentials: options.excludeCredentials?.map(toWireDescriptor),
        authenticatorSelection: options.authenticatorSelection,
        attestation: options.attestation,
      });
      if (!result) {
        return null;
      }
      // Structurally satisfies the DOM `PublicKeyCredential`/
      // `AuthenticatorAttestationResponse` fields `encodeAttestationForWire()`
      // (`@jummon/auth`'s `flow/webauthn.ts`) actually reads — see this
      // file's top doc comment for why a full DOM-spec object isn't needed.
      return {
        id: result.id,
        rawId: base64UrlToBytes(result.rawId),
        type: "public-key",
        response: {
          clientDataJSON: base64UrlToBytes(result.response.clientDataJSON),
          attestationObject: base64UrlToBytes(result.response.attestationObject),
        },
        getClientExtensionResults: () => ({}),
      } as unknown as PublicKeyCredential;
    },

    async get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential | null> {
      const result = await passkey.get({
        challenge: bytesToBase64Url(toBytes(options.challenge)),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification,
        allowCredentials: options.allowCredentials?.map(toWireDescriptor),
      });
      if (!result) {
        return null;
      }
      return {
        id: result.id,
        rawId: base64UrlToBytes(result.rawId),
        type: "public-key",
        response: {
          clientDataJSON: base64UrlToBytes(result.response.clientDataJSON),
          authenticatorData: base64UrlToBytes(result.response.authenticatorData),
          signature: base64UrlToBytes(result.response.signature),
          userHandle: result.response.userHandle ? base64UrlToBytes(result.response.userHandle) : null,
        },
        getClientExtensionResults: () => ({}),
      } as unknown as PublicKeyCredential;
    },
  };
}
