import { JummonAuthError } from "../errors";
import type { PlatformCrypto, PlatformWebAuthn } from "./platform/types";
import { browserWebAuthn } from "../platform/browser/webauthn";
import { browserCrypto } from "../platform/browser/crypto";
import { generatePkcePair } from "./platform/pkce";
import {
  runRecoveryPasskeyCeremony,
  type RecoveryPasskeyChallenge,
} from "../internal/recoveryPasskeyEnrollment";

/** `POST /dynamic/executionflows/steps` — the ONLY path that ever needs the PKCE verifier attached (see `request()`'s doc comment). */
const STEPS_PATH = "/dynamic/executionflows/steps";

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
 * R15/R16) and R14's cross-device numeric-code exchange (needs a dedicated
 * dynamic-flows endpoint this SDK-only pass doesn't add — see the mobile
 * parity dispatch's own report for the filed follow-up). The mobile
 * deep-link/Universal-Link entry point (R12) is `@jummon/auth-react-native`'s
 * `createRecoveryReturnListener` (`packages/react-native/src/adapters/
 * navigation.ts`) — SEPARATE from this class, which never touches
 * `Linking`. PKCE device-binding for redemption (R13/R17) IS built HERE —
 * see below.
 *
 * **PKCE device-binding (threat model §3.5 R13/R17).** {@link init} mints a
 * fresh RFC 7636 verifier/challenge pair via the injected `PlatformCrypto`
 * (`generatePkcePair`, the SAME primitive `HeadlessAuthFlowCore.start()`
 * uses for the OIDC leg) — the CHALLENGE goes out in the init request body
 * (`code_challenge`/`code_challenge_method: "S256"`), the verifier is kept
 * ONLY in the `#codeVerifier` private field and is attached automatically
 * to every subsequent step submission ({@link request}'s own doc comment
 * explains why every submit, not just a hand-picked "the redeem step").
 * Once `dynamic-flows` is updated to relay `code_challenge` into its
 * Recovery Grant `Mint` S2S call and `code_verifier` into whichever step
 * finishes the ceremony (`jummon-auth-engine`'s `recoverygrant.Usecase`
 * already enforces the match fail-closed once a challenge is present — see
 * that repo's `internal/recoverygrant/recoverygrant.go`), an intercepted
 * grant id/deep link alone becomes unredeemable without also holding this
 * verifier, which never leaves the initiating device (R17/R19). Until that
 * `dynamic-flows` plumbing lands, these two extra fields are inert but
 * harmless additions to the wire body — no behavior change for a backend
 * that doesn't read them yet.
 *
 * **In-memory only (R15/R16).** `#token`/`#codeVerifier` are TRUE private
 * class fields (`#`, not TypeScript's `private` keyword) — they are not own
 * enumerable properties, so `JSON.stringify(flow)`/`{...flow}`/
 * `Object.keys(flow)` can never surface them. This class also never accepts
 * a storage adapter of any kind — there is structurally no code path by
 * which a recovery token or its verifier could reach `AsyncStorage`, a
 * plain file, or `flowPersistence.ts`'s resume mechanism (which is for the
 * unrelated, lower-stakes OIDC auth flow). **Contract for integrators:**
 * never wrap an instance of this class (or hold a reference to it) in
 * anything you persist — hold it only for the lifetime of the recovery UI,
 * and let it be garbage-collected once the flow reaches `"done"`/`"error"`.
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
  // TRUE private fields (`#`) — see the class doc comment's "In-memory
  // only (R15/R16)" section for why this specifically (not TypeScript's
  // `private` keyword, which compiles to a normal enumerable property).
  #token: string | null = null;
  #codeVerifier: string | null = null;

  constructor(
    private readonly opts: HeadlessRecoveryFlowOptions,
    private readonly webauthn: PlatformWebAuthn = browserWebAuthn,
    private readonly crypto: PlatformCrypto = browserCrypto,
  ) {}

  /**
   * Starts a fresh recovery execution — `POST /dynamic/executionflows`.
   * Mints this flow's PKCE pair (threat model §3.5 R13/R17, class doc
   * comment) BEFORE the network call — the verifier never leaves this
   * instance, only the challenge goes out on the wire.
   */
  async init(): Promise<HeadlessRecoveryFlowSnapshot> {
    let codeChallenge: string;
    try {
      const pair = await generatePkcePair(this.crypto);
      this.#codeVerifier = pair.codeVerifier;
      codeChallenge = pair.codeChallenge;
    } catch (err) {
      throw new JummonAuthError("unknown", "Could not generate the recovery flow's PKCE device-binding pair.", err);
    }

    const envelope = await this.request<ExecutionFlowInitEnvelope>("POST", "/dynamic/executionflows", {
      flow_ref: this.opts.flowRef,
      client_id: this.opts.clientId,
      redirect_uri: this.opts.redirectUri,
      reference_url: this.opts.referenceUrl,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    this.#token = envelope.token;
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
    this.#token = envelope.next_token || this.#token;
    if (envelope.done) {
      // R15/R16 hygiene: once the flow is genuinely finished, the
      // verifier's job is done — drop it rather than let it linger in
      // memory for the (garbage-collectable but not yet collected)
      // lifetime of this instance.
      this.#codeVerifier = null;
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

  /**
   * threat model §3.5 R13's "the eventual redeem call must present the
   * verifier" — attached transparently to EVERY POST to `STEPS_PATH`
   * (`/dynamic/executionflows/steps`), not just a hand-picked "this one is
   * the redeem step": the generic step-driver shape this class is built
   * around (class doc comment) means the core has no reliable, forward-
   * compatible way to know structurally which `stepRef` is the terminal
   * credential-mutation one for a given tenant's authored recovery journey
   * (Flow Studio can reorder/relabel steps). Sending the verifier on every
   * submit is cheap (one extra ~43-char field) and lets WHICHEVER step
   * `dynamic-flows`/`jummon-auth-engine` eventually gate on it — see the
   * class doc comment's "PKCE device-binding" section.
   */
  private async request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const host = this.opts.baseHost.trim().replace(/\/+$/, "");
    const headers: Record<string, string> = { Accept: "application/json" };
    const outboundBody =
      body !== undefined && path === STEPS_PATH && this.#codeVerifier
        ? { ...(body as Record<string, unknown>), code_verifier: this.#codeVerifier }
        : body;
    if (outboundBody !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.#token) {
      headers["x-flow-token"] = this.#token;
    }

    let response: Response;
    try {
      response = await fetch(`https://${host}${path}`, {
        method,
        headers,
        body: outboundBody !== undefined ? JSON.stringify(outboundBody) : undefined,
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
