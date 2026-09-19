import { browserWebAuthn } from "../platform/browser/webauthn";
import type { PlatformWebAuthn } from "../core/platform/types";
import {
  HeadlessRecoveryFlowCore,
  type HeadlessRecoveryFlowOptions,
  type HeadlessRecoveryFlowSnapshot,
} from "../core/headlessRecoveryFlowCore";

export type { HeadlessRecoveryFlowOptions, HeadlessRecoveryFlowSnapshot };

/**
 * WEB entrypoint for the credential-type-aware account-recovery journey
 * (issue #163/#165) — mirrors `./headlessAuthFlow.ts`'s
 * `createHeadlessAuthFlow()` shape exactly: the agnostic step-machine logic
 * lives in `HeadlessRecoveryFlowCore` (`../core/headlessRecoveryFlowCore.ts`);
 * a future React Native engine constructs that class directly with its own
 * `PlatformWebAuthn` (native passkey provider), bypassing this browser
 * wrapper entirely.
 */
export function createHeadlessRecoveryFlow(
  options: HeadlessRecoveryFlowOptions,
  webauthn: PlatformWebAuthn = browserWebAuthn,
): HeadlessRecoveryFlowCore {
  return new HeadlessRecoveryFlowCore(options, webauthn);
}
