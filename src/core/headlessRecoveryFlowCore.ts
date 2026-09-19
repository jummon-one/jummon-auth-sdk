import { JummonAuthError } from "../errors";
import type { PlatformWebAuthn } from "./platform/types";
import { browserWebAuthn } from "../platform/browser/webauthn";
import {
  runRecoveryPasskeyCeremony,
  type RecoveryPasskeyChallenge,
} from "../internal/recoveryPasskeyEnrollment";

/**
 * Platform-agnostic driver for the credential-type-aware account-recovery
 * journey (issue #163/#165, `CREDENTIAL-TYPE-AWARE-RECOVERY-DESIGN.md`
 * §11.2). Pointed at `iam-dynamic-flows`' generic execution-flow API
 * (`POST /dynamic/executionflows` to init, `GET|POST /dynamic/
 * executionflows/steps` with an `x-flow-token` bearer to drive each step),
 * NOT the auth-engine headless Auth API `HeadlessAuthFlowCore` drives — a
 * DIFFERENT service, confirmed transport-agnostic already (design §11.2:
 * "`ExecutionFlowDto.Token`/`StepResponse.NextToken` is a rotating bearer,
 * no cookie dependency").
 *
 * Every step except `enroll-passkey-form` is driven through the generic
 * {@link submit} — identical shape to how `validate-user-form`/
 * `how-to-recover-form`/`update-password-form` already work through this
 * same mechanism (design §11.2). `enroll-passkey-form` gets the one
 * dedicated method ({@link enrollPasskey}) because it must call the
 * platform authenticator, not just POST JSON — see
 * `../internal/recoveryPasskeyEnrollment.ts`'s doc comment.
 *
 * `baseHost` is caller-supplied (not defaulted to a guessed API-gateway
 * path) — confirming the externally-reachable host/path for
 * `iam-dynamic-flows`' execution-flow API is an infra/gateway-routing
 * question this SDK change does not resolve; see this dispatch's own
 * report for the exact open item.
 *
 * NOT built here (design §11's Wave 4, explicitly deferred): resumable
 * flow persistence across app backgrounding (`../core/flowPersistence.ts`
 * mirrors a DIFFERENT, lower-stakes case per design §11.2's own warning —
 * a recovery token/context must never be persisted to disk, threat model
 * R15/R16), the mobile deep-link/Universal-Link entry point (R12), and the
 * PKCE device-binding for redemption (R13/R14/R17). This class only
 * implements the generic step-driver + native passkey ceremony the design
 * names as "purely SDK-side" work.
 */
export interface HeadlessRecoveryFlowOptions {
  /** Host (no scheme, no trailing slash) where `iam-dynamic-flows`' execution-flow API is externally reachable. */
  baseHost: string;
  /** The tenant's recovery flow ref to start (e.g. `"recover-account-credential-aware"`). */
  flowRef: string;
  clientId?: string;
  redirectUri?: string;
  referenceUrl?: string;
}

export type HeadlessRecoveryFlowStatus = "idle" | "loading" | "in_progress" | "done" | "error";

export interface HeadlessRecoveryFlowSnapshot {
  status: HeadlessRecoveryFlowStatus;
  /** The current step's ref (e.g. `"validate-user-form"`, `"enroll-passkey-form"`) — `null` before {@link init} or once {@link status} is `"done"`. */
  stepRef: string | null;
  /**
   * The current step's raw response `data` payload — shape depends on
   * `stepRef`. Notable shapes for the masked-hints/confirm-partial recovery
   * UX (`engineering-team/initiatives/account-recovery/design/
   * RECOVERY-MASKED-HINTS-UX.md` §10.1):
   *
   *   - `how-to-recover-form`: `{reference_url, options: string[],
   *     option_details?: Array<{ref: string; masked_hint?: string}>}` —
   *     `option_details` is ADDITIVE (never replaces `options`, which
   *     `select-credential-form` also reuses for credential TYPES that
   *     carry no masked hint). `masked_hint` is ALREADY masked server-side
   *     (e.g. `"j•••@gmail.com"`, `"••• ••••-4821"`) — never a raw
   *     email/phone. Omitted entirely for `otp`/`recovery_code` (no
   *     destination to mask — render a capability statement locally
   *     instead, same as the web picker does).
   *   - `confirm-contact-form`: `{reference_url, channel: string,
   *     masked_hint?: string}` — `channel` is one of `"sms"`|`"whatsapp"`|
   *     `"email"`, selects which UI variant to render (last-4-digit entry
   *     vs. full-email entry); `masked_hint` is the SAME masked string
   *     `how-to-recover-form` already showed, re-derived server-side.
   *
   * See {@link HeadlessRecoveryFlowCore.confirmPartial} for how to submit
   * this step, and note that its RESPONSE is identical whether the
   * submitted value matched or not (anti-enumeration, design §5.3) — this
   * `data` payload is never a signal to branch UI on beyond "did the
   * network call succeed."
   */
  data: unknown;
  error: JummonAuthError | null;
}

interface ExecutionFlowStepEnvelope {
  done?: boolean;
  next_token: string;
  current_step?: { step?: { ref?: string } };
  data: unknown;
  /**
   * Server-computed "don't render this step, auto-submit its sole option
   * instead" signal (design §3/§11 item 3, `dynamic-flows`
   * `executionflow.StepResponse.AutoProceed` — a top-level field, sibling
   * of `data`, not nested under it). Set true today only by
   * `how-to-recover-form` when exactly one recovery channel is available
   * for the user. Resolved transparently inside {@link
   * HeadlessRecoveryFlowCore.toSnapshot} — callers of {@link
   * HeadlessRecoveryFlowCore.init}/{@link HeadlessRecoveryFlowCore.current}/
   * {@link HeadlessRecoveryFlowCore.submit} never see an
   * `auto_proceed: true` step; the snapshot they get back already skipped
   * it.
   */
  auto_proceed?: boolean;
}

interface ExecutionFlowInitEnvelope {
  token: string;
  current_step: string;
}

export class HeadlessRecoveryFlowCore {
  private token: string | null = null;

  constructor(
    private readonly opts: HeadlessRecoveryFlowOptions,
    private readonly webauthn: PlatformWebAuthn = browserWebAuthn,
  ) {}

  /** Starts a fresh recovery execution — `POST /dynamic/executionflows`. */
  async init(): Promise<HeadlessRecoveryFlowSnapshot> {
    const envelope = await this.request<ExecutionFlowInitEnvelope>("POST", "/dynamic/executionflows", {
      flow_ref: this.opts.flowRef,
      client_id: this.opts.clientId,
      redirect_uri: this.opts.redirectUri,
      reference_url: this.opts.referenceUrl,
    });
    this.token = envelope.token;
    // The init envelope's current_step is the bare ref (ExecutionFlowDto),
    // not the richer StepResponse shape submit()/current() return — a
    // separate GET is what the FIRST step's actual `data` payload comes
    // from, mirroring how a fresh browser page load always issues a GET
    // before rendering the first form.
    return this.current();
  }

  /** Re-fetches the CURRENT step without submitting anything — `GET /dynamic/executionflows/steps`. */
  async current(): Promise<HeadlessRecoveryFlowSnapshot> {
    const envelope = await this.request<ExecutionFlowStepEnvelope>("GET", "/dynamic/executionflows/steps");
    return this.toSnapshot(envelope);
  }

  /** Submits the current step's data and advances — `POST /dynamic/executionflows/steps`. */
  async submit(data: Record<string, unknown>): Promise<HeadlessRecoveryFlowSnapshot> {
    const envelope = await this.request<ExecutionFlowStepEnvelope>(
      "POST",
      "/dynamic/executionflows/steps",
      data,
    );
    return this.toSnapshot(envelope);
  }

  /**
   * Convenience wrapper for `recovery-codes-form`'s `mode=redeem`
   * placement (issue #163/#165 Wave 3, design §3.4/§4) — an alternative
   * recovery FACTOR alongside SMS/email/OTP (`how-to-recover-form`'s
   * `recovery_code` option). Purely a thin `submit({code})` — the backend
   * infers `mode=redeem` from server-held execution state (never a
   * client-supplied flag, `dynamic-flows` step_recovery_codes.go's own
   * `inferMode` doc comment), so this method carries zero logic beyond
   * naming the call site clearly. `mode=generate` (shown right after a
   * fresh credential re-enrollment, to bootstrap the NEXT recovery) stays
   * on the generic {@link submit} — it POSTs `{confirmed: true}`, a
   * different shape this dedicated method does not cover.
   */
  async redeemRecoveryCode(code: string): Promise<HeadlessRecoveryFlowSnapshot> {
    return this.submit({ code });
  }

  /**
   * Submits the confirm-partial value for `confirm-contact-form` — the
   * last-4 digits (sms/whatsapp) or the full email address (email), per
   * the channel chosen on the prior `how-to-recover-form` step (design
   * RECOVERY-MASKED-HINTS-UX.md §10.2). Purely `submit({partial})` — the
   * server infers which comparison to run from its own held execution
   * state (never a client-supplied channel flag), same posture
   * {@link redeemRecoveryCode}'s doc comment already establishes for
   * `inferMode`.
   *
   * The response is IDENTICAL whether `value` matched or not (§5.3,
   * anti-enumeration) — never branch UI on this call's resolution beyond
   * "did the network request succeed"; the snapshot always advances to
   * `validate-recovery-form`.
   */
  async confirmPartial(value: string): Promise<HeadlessRecoveryFlowSnapshot> {
    return this.submit({ partial: value });
  }

  /**
   * Drives `enroll-passkey-form` end to end: reads the CURRENT step's
   * `{ceremony_id, options}` (already fetched via {@link init}/{@link current}
   * — the SAME shape today's in-login `fido-registration` step and the
   * self-service `BeginResponse` use, design §2's table), runs the
   * platform-authenticator ceremony via the injected `PlatformWebAuthn`,
   * and POSTs the result back through the generic {@link submit}. The
   * Recovery Grant (design §3.2) NEVER reaches this SDK — it is minted and
   * redeemed entirely server-side; this method only ever sees the WebAuthn
   * challenge/response pair.
   */
  async enrollPasskey(
    snapshot: HeadlessRecoveryFlowSnapshot,
    name?: string,
  ): Promise<HeadlessRecoveryFlowSnapshot> {
    if (snapshot.stepRef !== "enroll-passkey-form") {
      throw new JummonAuthError(
        "unknown",
        `enrollPasskey() called while the current step is "${snapshot.stepRef}", expected "enroll-passkey-form".`,
      );
    }
    const challenge = snapshot.data as Partial<{ ceremony_id: string; options: string }> | null;
    if (!challenge?.ceremony_id || !challenge.options) {
      throw new JummonAuthError(
        "unknown",
        "enroll-passkey-form's response is missing ceremony_id/options — call init()/current() first.",
      );
    }

    const wireChallenge: RecoveryPasskeyChallenge = {
      ceremonyId: challenge.ceremony_id,
      options: challenge.options,
    };
    const attestation = await runRecoveryPasskeyCeremony(wireChallenge, name, this.webauthn);
    return this.submit(attestation as unknown as Record<string, unknown>);
  }

  /**
   * Resolves the envelope into a caller-facing snapshot — AND, per design
   * §3.2/§10.3, transparently resolves any `auto_proceed: true` chain
   * first: a native app calling {@link init}/{@link current} on a
   * single-channel account resolves straight to `confirm-contact-form`
   * (or whatever the next real step is), never rendering the one-item
   * `how-to-recover-form` picker at all — the app never even sees that
   * `stepRef`. This is the concrete "better on mobile than web" gap named
   * in §3.2: the web SSR still has one visible transitional round-trip
   * (§3.1); the SDK has none.
   *
   * `maxAutoProceedHops` bounds the recursion — a server bug that kept
   * setting `auto_proceed: true` forever must surface as a real error
   * here, not hang the caller's promise indefinitely.
   */
  private async toSnapshot(
    envelope: ExecutionFlowStepEnvelope,
    hopsRemaining = HeadlessRecoveryFlowCore.maxAutoProceedHops,
  ): Promise<HeadlessRecoveryFlowSnapshot> {
    this.token = envelope.next_token || this.token;
    if (envelope.done) {
      return { status: "done", stepRef: null, data: envelope.data ?? null, error: null };
    }

    if (envelope.auto_proceed) {
      if (hopsRemaining <= 0) {
        throw new JummonAuthError(
          "unknown",
          "Recovery flow kept returning auto_proceed=true past the safety limit — refusing to loop forever.",
        );
      }
      const data = envelope.data as { options?: string[] } | null;
      const onlyOption = data?.options?.[0];
      if (onlyOption) {
        const next = await this.request<ExecutionFlowStepEnvelope>("POST", "/dynamic/executionflows/steps", {
          option: onlyOption,
        });
        return this.toSnapshot(next, hopsRemaining - 1);
      }
      // auto_proceed=true with no option to submit is a server contract
      // violation, not a hang — fail loudly rather than silently render
      // whatever stale data rode alongside it.
      throw new JummonAuthError(
        "unknown",
        "Recovery flow returned auto_proceed=true with no option in options[] to auto-submit.",
      );
    }

    return {
      status: "in_progress",
      stepRef: envelope.current_step?.step?.ref ?? null,
      data: envelope.data ?? null,
      error: null,
    };
  }

  /** Safety cap on transparent auto-proceed recursion — see {@link toSnapshot}. */
  private static readonly maxAutoProceedHops = 5;

  private async request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const host = this.opts.baseHost.trim().replace(/\/+$/, "");
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.token) {
      headers["x-flow-token"] = this.token;
    }

    let response: Response;
    try {
      response = await fetch(`https://${host}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        // Bearer, not a cookie — same rationale as HeadlessTransport
        // (../flow/transport.ts) and passkeyEnrollment.ts's request(): no
        // shared cookie jar with this origin, and design §3.2's own
        // "cookie-less so mobile/headless works" requirement.
        credentials: "omit",
      });
    } catch (err) {
      throw new JummonAuthError("network_unreachable", "Could not reach the account-recovery service.", err);
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch (err) {
      throw new JummonAuthError("unknown", "Malformed response from the account-recovery service.", err);
    }

    if (!response.ok) {
      const body = payload as { message?: string; code?: string };
      throw new JummonAuthError("unknown", body.message ?? "Something went wrong during account recovery.", body);
    }
    return payload as T;
  }
}
