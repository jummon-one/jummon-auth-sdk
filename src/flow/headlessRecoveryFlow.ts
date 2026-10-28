import { browserWebAuthn } from "../platform/browser/webauthn";
import type { PlatformWebAuthn } from "../core/platform/types";
import {
  HeadlessRecoveryFlowCore,
  type HeadlessRecoveryFlowOptions,
  type HeadlessRecoveryFlowSnapshot,
} from "../core/headlessRecoveryFlowCore";

export type { HeadlessRecoveryFlowOptions, HeadlessRecoveryFlowSnapshot };

/**
 * Public type alias for the object `createHeadlessRecoveryFlow()`/
 * `HeadlessJummonAuthClient.startRecoveryFlow()` (`../client.ts`) return —
 * named for parity with `HeadlessAuthFlow` even though, unlike that one,
 * this is presently a concrete class (`HeadlessRecoveryFlowCore`) rather
 * than a hand-written interface; callers should type against this alias,
 * not the class, so a future interface extraction stays non-breaking.
 */
export type HeadlessRecoveryFlow = HeadlessRecoveryFlowCore;

/**
 * Per-call overrides accepted by `HeadlessJummonAuthClient.startRecoveryFlow()`
 * (`../client.ts`) on top of the tenant/clientId/redirectUri/apiHost it
 * already derives from `JummonAuthOptions` — everything else
 * `HeadlessRecoveryFlowOptions` needs is either that derived config or the
 * caller-supplied `flowRef`.
 */
export interface HeadlessRecoveryStartOptions {
  /** Forwarded verbatim as `HeadlessRecoveryFlowOptions.referenceUrl` — see that field's doc comment. */
  referenceUrl?: string;
}

/**
 * WEB entrypoint for the credential-type-aware account-recovery journey
 * (issue #163/#165) — mirrors `./headlessAuthFlow.ts`'s
 * `createHeadlessAuthFlow()` shape exactly: the agnostic step-machine logic
 * lives in `HeadlessRecoveryFlowCore` (`../core/headlessRecoveryFlowCore.ts`);
 * a future React Native engine constructs that class directly with its own
 * `PlatformWebAuthn` (native passkey provider), bypassing this browser
 * wrapper entirely.
 *
 * Standalone entrypoint for a caller with no (or not-yet-constructed)
 * `createJummonAuth()` client (e.g. a pre-login recovery link landing page
 * that never calls `createJummonAuth()` at all). A caller who already holds
 * a headless `createJummonAuth()` client should prefer
 * `HeadlessJummonAuthClient.startRecoveryFlow(flowRef)` (`../client.ts`)
 * instead — it derives `baseHost`/`tenantSlug`/`clientId`/`redirectUri` from
 * the client's own `JummonAuthOptions` instead of requiring them here by
 * hand. Both construct the exact same `HeadlessRecoveryFlowCore`.
 */
export function createHeadlessRecoveryFlow(
  options: HeadlessRecoveryFlowOptions,
  webauthn: PlatformWebAuthn = browserWebAuthn,
): HeadlessRecoveryFlowCore {
  return new HeadlessRecoveryFlowCore(options, webauthn);
}
