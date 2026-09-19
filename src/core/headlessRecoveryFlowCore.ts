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
  /** The current step's raw response `data` payload — shape depends on `stepRef` (e.g. `{ceremony_id, options}` for `enroll-passkey-form`). */
  data: unknown;
  error: JummonAuthError | null;
}

interface ExecutionFlowStepEnvelope {
  done?: boolean;
  next_token: string;
  current_step?: { step?: { ref?: string } };
  data: unknown;
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

  private toSnapshot(envelope: ExecutionFlowStepEnvelope): HeadlessRecoveryFlowSnapshot {
    this.token = envelope.next_token || this.token;
    if (envelope.done) {
      return { status: "done", stepRef: null, data: envelope.data ?? null, error: null };
    }
    return {
      status: "in_progress",
      stepRef: envelope.current_step?.step?.ref ?? null,
      data: envelope.data ?? null,
      error: null,
    };
  }

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
