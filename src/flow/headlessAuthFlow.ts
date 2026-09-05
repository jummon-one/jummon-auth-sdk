import { createBrowserPlatformAdapters } from "../platform/browser";
import type { PlatformAdapters } from "../core/platform/types";
import {
  HeadlessAuthFlowCore,
  type HeadlessAuthFlow,
  type HeadlessFlowSnapshot,
  type HeadlessSessionSink,
} from "../core/headlessAuthFlowCore";
import type { JummonAuthOptions } from "../types";

export type { HeadlessAuthFlow, HeadlessFlowSnapshot, HeadlessSessionSink };

/**
 * WEB entrypoint for the headless multi-step login flow. `createJummonAuth({
 * ...options, mode: "headless" }).startAuthFlow()` (`../client.ts`) calls
 * this with no third argument, so it wires the default browser adapters
 * (`../platform/browser`) — identical behavior to the pre-refactor
 * `oidc-client-ts`/`window`-coupled implementation, including the
 * synchronous `ssr_unsupported` throw when called during server rendering
 * (now performed by `createBrowserPlatformAdapters`, not this function
 * itself).
 *
 * The actual step-machine logic lives in the platform-agnostic
 * `HeadlessAuthFlowCore` (`../core/headlessAuthFlowCore.ts`) — a future
 * React Native engine constructs that class directly with its own
 * `PlatformAdapters`, bypassing this browser-specific wrapper entirely.
 */
export function createHeadlessAuthFlow(
  options: JummonAuthOptions,
  sink: HeadlessSessionSink,
  adapters: PlatformAdapters = createBrowserPlatformAdapters(options),
): HeadlessAuthFlow {
  return new HeadlessAuthFlowCore(options, sink, adapters);
}
