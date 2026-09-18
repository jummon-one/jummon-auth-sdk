/**
 * ADR-0002 Wave 3 (#155, passwordless-first login layout) — turns the raw
 * wire shape (`HeadlessLoginLayout`, `./types.ts`) into the SDK's public,
 * complexity-abstracting surface: three pre-grouped, pre-sorted lane arrays
 * a consuming app renders directly, instead of parsing `data.login_layout`'s
 * `{methods: [{method, lane, order, emphasis}]}` bag itself. Mirrors this
 * package's own rule (README's "the SDK abstracts auth complexity") the
 * same way `deriveState()` (`./stepState.ts`) turns a raw `current_step.ref`
 * into a richer DX enum — one pure function, one input shape, no network
 * call, no side effect.
 */
import type { HeadlessLoginMethodLane, HeadlessLoginMethodPlacement, HeadlessLoginMethodRef } from "./types";

/**
 * One method's rendering hint inside a lane — everything a consumer needs
 * to draw a button, and nothing else. `method` is widened to `| string` so
 * a future backend-added `HeadlessLoginMethodRef` value degrades to "render
 * generically" (e.g. a fallback label) instead of failing a strict union
 * check at the consumer's compile time — the closed-enum discipline lives
 * server-side (`jummon-auth-engine`'s `loginauthoring.ValidateLoginLayout`),
 * not here.
 */
export interface HeadlessLoginMethodDescriptor {
  method: HeadlessLoginMethodRef | string;
  /** `null` when the author left it unset — treat as "no emphasis hint", never as a security signal. */
  emphasis: "primary_cta" | "secondary" | null;
}

/**
 * The SDK's public, typed projection of an authored `LoginLayout` —
 * `HeadlessFlowSnapshot.loginLayout`'s type. Each array is already sorted by
 * the wire's `order` (ascending, ties broken by original array position);
 * a method authored with `lane: ""` (explicitly unplaced) never appears in
 * any array here. Rendering contract: primary methods first (as
 * passwordless-first CTAs), an "or" divider, then fallback methods
 * de-emphasized; `mfaMethods` is informational only (this SDK's existing
 * `needs_mfa`/`needs_mfa_configure` states already drive the actual MFA
 * step — this array is for a login screen that wants to preview which
 * factors a tenant has configured, not a new place to trigger MFA from).
 */
export interface HeadlessLoginMethodLayout {
  primaryMethods: HeadlessLoginMethodDescriptor[];
  fallbackMethods: HeadlessLoginMethodDescriptor[];
  mfaMethods: HeadlessLoginMethodDescriptor[];
}

function toDescriptor(placement: HeadlessLoginMethodPlacement): HeadlessLoginMethodDescriptor {
  return {
    method: placement.method,
    emphasis: placement.emphasis === "primary_cta" || placement.emphasis === "secondary" ? placement.emphasis : null,
  };
}

/**
 * Reads `data.login_layout` off a step response's `data` bag and resolves
 * it to the SDK's public, lane-grouped shape — or `null` when unauthored
 * (absent/`null`/malformed), which is the **null-safe fallback** every
 * tenant that has never opened Flow Studio's lane UI gets forever: a caller
 * checking `snapshot.loginLayout` sees exactly `null` and falls back to
 * whatever default order it already renders, byte-for-byte today's
 * behavior (DESIGN-WAVE3-PASSWORDLESS-LAYOUT.md §2/§4).
 *
 * Deliberately defensive, not a validator: this reads presentation data the
 * backend already validated at author-time
 * (`loginauthoring.ValidateLoginLayout`) — a malformed/unexpected shape here
 * degrades to "no layout" rather than throwing, since a rendering-order hint
 * is never worth crashing a login screen over.
 */
export function deriveLoginLayout(data: Record<string, unknown> | null | undefined): HeadlessLoginMethodLayout | null {
  const raw = data?.["login_layout"];
  if (raw === null || raw === undefined || typeof raw !== "object") {
    return null;
  }
  const methods = (raw as { methods?: unknown }).methods;
  if (!Array.isArray(methods)) {
    return null;
  }

  const primaryMethods: Array<{ order: number; descriptor: HeadlessLoginMethodDescriptor }> = [];
  const fallbackMethods: Array<{ order: number; descriptor: HeadlessLoginMethodDescriptor }> = [];
  const mfaMethods: Array<{ order: number; descriptor: HeadlessLoginMethodDescriptor }> = [];

  const laneBucket: Record<Exclude<HeadlessLoginMethodLane, "">, typeof primaryMethods> = {
    primary: primaryMethods,
    fallback: fallbackMethods,
    mfa: mfaMethods,
  };

  methods.forEach((entry, index) => {
    if (!entry || typeof entry !== "object") return;
    const placement = entry as Partial<HeadlessLoginMethodPlacement>;
    if (typeof placement.method !== "string") return;
    const lane = placement.lane;
    if (lane !== "primary" && lane !== "fallback" && lane !== "mfa") {
      // "" (unplaced) or an unrecognized future lane value — never rendered.
      return;
    }
    laneBucket[lane].push({
      order: typeof placement.order === "number" ? placement.order : index,
      descriptor: toDescriptor(placement as HeadlessLoginMethodPlacement),
    });
  });

  const byOrder = (a: { order: number }, b: { order: number }) => a.order - b.order;

  return {
    primaryMethods: primaryMethods.sort(byOrder).map((m) => m.descriptor),
    fallbackMethods: fallbackMethods.sort(byOrder).map((m) => m.descriptor),
    mfaMethods: mfaMethods.sort(byOrder).map((m) => m.descriptor),
  };
}
