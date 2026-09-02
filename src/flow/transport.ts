import { JummonAuthError, mapHeadlessErrorCode } from "../errors";
import type { HeadlessAuthEnvelope, HeadlessStartRequestBody } from "./types";

export interface HeadlessTransportOptions {
  tenant: string;
  clientId: string;
  issuerHost: string;
}

const AUTH_API_BASE_PATH = "/api/v1/auth";

/**
 * Thin HTTP client for the headless Auth API namespace
 * (`jummon-login-interface`'s `/api/v1/auth/*`, `implementation-plan.md`
 * §7). `tenant`/`client_id` are URL path segments, never a body field —
 * see `HeadlessAuthEnvelope`'s doc comment (`./types.ts`) for why.
 *
 * Bearer flow-token, not a cookie (`system-design.md` §3.2 — there is no
 * shared cookie jar with the customer's own origin), so every request is
 * `credentials: "omit"`.
 */
export class HeadlessTransport {
  constructor(private readonly opts: HeadlessTransportOptions) {}

  start(body: HeadlessStartRequestBody): Promise<HeadlessAuthEnvelope> {
    return this.request("start", "POST", body);
  }

  submit(flowToken: string, body: Record<string, unknown>): Promise<HeadlessAuthEnvelope> {
    return this.request("submit", "POST", body, flowToken);
  }

  poll(flowToken: string): Promise<HeadlessAuthEnvelope> {
    return this.request("poll", "GET", undefined, flowToken);
  }

  private endpoint(action: "start" | "submit" | "poll"): string {
    const host = this.opts.issuerHost.trim().replace(/\/+$/, "");
    const tenant = encodeURIComponent(this.opts.tenant.trim());
    const clientId = encodeURIComponent(this.opts.clientId.trim());
    return `https://${host}${AUTH_API_BASE_PATH}/${tenant}/${clientId}/${action}`;
  }

  private async request(
    action: "start" | "submit" | "poll",
    method: "GET" | "POST",
    body?: unknown,
    flowToken?: string,
  ): Promise<HeadlessAuthEnvelope> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (flowToken) {
      headers["X-Flow-Token"] = flowToken;
    }

    let response: Response;
    try {
      response = await fetch(this.endpoint(action), {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        credentials: "omit",
      });
    } catch (err) {
      // fetch() throws an opaque TypeError for both a real network outage
      // and a CORS-rejected request — browsers deliberately don't expose
      // which (no response, no status). `start()` is the only call an
      // arbitrary, not-yet-trusted third-party origin makes (every other
      // call already carries a flow_token the Auth API issued), so a
      // same-online failure there is far more likely a CORS/origin
      // rejection than a dead network. Best-effort heuristic only, never
      // authoritative — see `ux-spec-wave1.md` §3's `cors_origin_rejected` row.
      const online = typeof navigator === "undefined" || navigator.onLine !== false;
      const code = action === "start" && online ? "cors_origin_rejected" : "network_unreachable";
      throw new JummonAuthError(
        code,
        code === "cors_origin_rejected"
          ? "This app isn't allowed to sign in from this address."
          : "Could not reach the Jummon Auth API.",
        err,
      );
    }

    let payload: HeadlessAuthEnvelope;
    try {
      payload = (await response.json()) as HeadlessAuthEnvelope;
    } catch (err) {
      throw new JummonAuthError("unknown", "Malformed response from the Jummon Auth API.", err);
    }

    if (!response.ok || payload.error) {
      throw new JummonAuthError(
        mapHeadlessErrorCode(payload.error?.code),
        payload.error?.message ?? "Something went wrong. Try again in a moment.",
        payload.error,
      );
    }
    return payload;
  }
}
