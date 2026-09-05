import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HeadlessEngine } from "../engines/headlessEngine";
import { createHeadlessAuthFlow } from "../flow/headlessAuthFlow";
import type { HeadlessAuthEnvelope } from "../flow/types";

/**
 * End-to-end (through the REAL browser adapters — real `sessionStorage`,
 * real `crypto.getRandomValues` — only the network is mocked) verification
 * of the #85 risk-signal-collector's device_id lifecycle: stable across
 * submits in the same session, rotated by `HeadlessEngine.signOut()`. Uses
 * the web wrapper classes (not the core classes directly) specifically to
 * prove the wiring works the way a real app actually constructs them — one
 * `HeadlessEngine` for the app's lifetime, a fresh `HeadlessAuthFlow` per
 * login attempt, both sharing the same underlying browser storage.
 */

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  issuerHost: "idm.jummon.dev",
  collectRiskSignals: true,
};

function envelope(overrides: Partial<HeadlessAuthEnvelope> = {}): HeadlessAuthEnvelope {
  return {
    flow_token: "ft-1",
    status: "needs_input",
    current_step: { ref: "username-password-form" },
    data: {},
    ...overrides,
  };
}

function jsonResponse(literal: unknown): Response {
  return new Response(JSON.stringify(literal), { status: 200 });
}

describe("#85 risk-signal-collector: device_id lifecycle across HeadlessEngine + HeadlessAuthFlow", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    window.sessionStorage.clear();
  });

  it("device_id is stable within a session and rotates after HeadlessEngine.signOut()", async () => {
    const engine = new HeadlessEngine(OPTIONS);

    // --- Flow #1: start + submit, capture device_id A ---
    fetchMock
      .mockResolvedValueOnce(jsonResponse(envelope()))
      .mockResolvedValueOnce(jsonResponse(envelope({ current_step: { ref: "otp-input-form" } })));
    const flow1 = createHeadlessAuthFlow(OPTIONS, engine);
    await flow1.start();
    await flow1.submitPassword("jane@example.com", "hunter2");

    const [, firstInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    const firstBody = JSON.parse(firstInit.body as string) as { risk_signals?: { device_id?: string } };
    const deviceIdA = firstBody.risk_signals?.device_id;
    expect(typeof deviceIdA).toBe("string");

    // A second submit in the SAME flow/session must reuse the same device_id.
    fetchMock.mockResolvedValueOnce(jsonResponse(envelope({ current_step: { ref: "otp-input-form" } })));
    await flow1.submitMfaCode("123456");
    const [, secondInit] = fetchMock.mock.calls[2] as [string, RequestInit];
    const secondBody = JSON.parse(secondInit.body as string) as { risk_signals?: { device_id?: string } };
    expect(secondBody.risk_signals?.device_id).toBe(deviceIdA);

    // --- signOut() — no active session (never completed auth), so this
    // exercises the "runs unconditionally" path: no revoke, no
    // end_session_endpoint redirect, but device_id still rotates. ---
    await engine.signOut({ redirect: false });
    expect(fetchMock).toHaveBeenCalledTimes(3); // no new fetch calls from signOut() itself

    // --- Flow #2: a NEW HeadlessAuthFlow after signOut, same engine/storage ---
    fetchMock
      .mockResolvedValueOnce(jsonResponse(envelope()))
      .mockResolvedValueOnce(jsonResponse(envelope({ current_step: { ref: "otp-input-form" } })));
    const flow2 = createHeadlessAuthFlow(OPTIONS, engine);
    await flow2.start();
    await flow2.submitPassword("jane@example.com", "hunter2");

    const [, thirdInit] = fetchMock.mock.calls[4] as [string, RequestInit];
    const thirdBody = JSON.parse(thirdInit.body as string) as { risk_signals?: { device_id?: string } };
    const deviceIdB = thirdBody.risk_signals?.device_id;

    expect(typeof deviceIdB).toBe("string");
    expect(deviceIdB).not.toBe(deviceIdA);
  });
});
