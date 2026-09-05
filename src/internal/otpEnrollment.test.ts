import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JummonAuthError } from "../errors";
import { beginOtpEnrollment, confirmOtpEnrollment } from "./otpEnrollment";

describe("beginOtpEnrollment", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("happy path: POSTs to .../otp/enroll/begin, Bearer auth, apiHost (not issuerHost) as base, maps otp_secret/otp_url to secret/otpUrl", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ otp_secret: "JBSWY3DPEHPK3PXP", otp_url: "otpauth://totp/Acme:jane?secret=JBSWY3DPEHPK3PXP" }),
        { status: 200 },
      ),
    );

    const result = await beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" });

    expect(result).toEqual({
      secret: "JBSWY3DPEHPK3PXP",
      otpUrl: "otpauth://totp/Acme:jane?secret=JBSWY3DPEHPK3PXP",
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/otp/enroll/begin");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
  });

  it("maps a 401 to not_authenticated", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "invalid token" }), { status: 401 }),
    );

    await expect(
      beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "not_authenticated" });
  });

  it("maps a 403 (FEDERATED_OTP_SET_FORBIDDEN) to access_denied", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "FEDERATED_OTP_SET_FORBIDDEN", message: "federated account" }), {
        status: 403,
      }),
    );

    const err = await beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("access_denied");
    expect((err as JummonAuthError).message).toBe("federated account");
  });

  it("maps a 5xx to otp_enrollment_failed, not a bare unknown", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UPSTREAM_REQUEST_FAILED", message: "upstream error" }), {
        status: 500,
      }),
    );

    await expect(
      beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "otp_enrollment_failed" });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(
      beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "network_unreachable" });
  });

  it("classifies a malformed (non-JSON) 200 response as unknown", async () => {
    fetchMock.mockResolvedValueOnce(new Response("not json", { status: 200 }));

    const err = await beginOtpEnrollment("token-1", { apiHost: "api.jummon.dev" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JummonAuthError);
    expect((err as JummonAuthError).code).toBe("unknown");
  });
});

describe("confirmOtpEnrollment", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("happy path: POSTs {otp} ONLY (no secret) to .../otp/enroll/finish, resolves on 204", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(
      confirmOtpEnrollment("token-1", "123456", { apiHost: "api.jummon.dev" }),
    ).resolves.toBeUndefined();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/me/credentials/otp/enroll/finish");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-1");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    // Regression pin for the MFA-takeover fix: the request body must NEVER
    // carry a client-supplied secret — the server validates against the one
    // IT minted and persisted at beginOtpEnrollment(), not a wire field.
    expect(body).toEqual({ otp: "123456" });
    expect(body).not.toHaveProperty("otp_secret");
  });

  it("maps a 401 to not_authenticated", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UNAUTHENTICATED", message: "invalid token" }), { status: 401 }),
    );

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "not_authenticated" });
  });

  it("maps a 403 (FEDERATED_OTP_SET_FORBIDDEN) to access_denied", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "FEDERATED_OTP_SET_FORBIDDEN", message: "federated account" }), {
        status: 403,
      }),
    );

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "access_denied" });
  });

  it("maps a wrong/expired code (400) to otp_enrollment_failed", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "UPSTREAM_VALIDATION_FAILED", message: "invalid code" }), {
        status: 400,
      }),
    );

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "otp_enrollment_failed", message: "invalid code" });
  });

  // Pins the server-side fix's rejection of a request with no pending
  // enrollment (beginOtpEnrollment() never called, or its window lapsed) —
  // the SDK doesn't distinguish this from any other 4xx: both collapse to
  // otp_enrollment_failed, same posture as a wrong code.
  it("maps a missing/expired pending enrollment (404) to otp_enrollment_failed", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "OTP_ENROLLMENT_NOT_FOUND", message: "no pending enrollment" }), {
        status: 404,
      }),
    );

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "otp_enrollment_failed", message: "no pending enrollment" });
  });

  it("maps a 5xx with no JSON body to otp_enrollment_failed with a generic message", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 500 }));

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "otp_enrollment_failed" });
  });

  it("classifies a fetch throw as network_unreachable", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    await expect(
      confirmOtpEnrollment("token-1", "000000", { apiHost: "api.jummon.dev" }),
    ).rejects.toMatchObject({ code: "network_unreachable" });
  });
});
