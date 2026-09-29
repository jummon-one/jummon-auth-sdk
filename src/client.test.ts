import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./internal/passkeyEnrollment", () => ({
  DEFAULT_API_HOST: "api.jummon.com",
  enrollPasskey: vi.fn(),
}));
vi.mock("./internal/passwordSelfService", () => ({
  setPasswordSelfService: vi.fn(),
}));
vi.mock("./internal/otpEnrollment", () => ({
  beginOtpEnrollment: vi.fn(),
  confirmOtpEnrollment: vi.fn(),
}));
vi.mock("./internal/credentialsSelfService", () => ({
  listCredentials: vi.fn(),
  removeCredential: vi.fn(),
}));

import { createJummonAuth } from "./client";
import { enrollPasskey } from "./internal/passkeyEnrollment";
import { setPasswordSelfService } from "./internal/passwordSelfService";
import { beginOtpEnrollment, confirmOtpEnrollment } from "./internal/otpEnrollment";
import { listCredentials, removeCredential } from "./internal/credentialsSelfService";
import { HeadlessEngine } from "./engines/headlessEngine";
import { RedirectEngine } from "./engines/redirectEngine";

const OPTIONS = {
  tenant: "acme",
  clientId: "acme-app",
  redirectUri: "https://app.acme.com/callback",
  issuerHost: "idm.jummon.dev",
  tokenStorage: "memory" as const,
};

describe("JummonAuthClient.registerPasskey()", () => {
  beforeEach(() => {
    vi.mocked(enrollPasskey).mockReset();
  });

  it("throws not_authenticated instead of calling the network when there is no session (redirect mode)", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.registerPasskey()).rejects.toMatchObject({ code: "not_authenticated" });
    expect(enrollPasskey).not.toHaveBeenCalled();
  });

  it("resolves the current access_token and delegates to enrollPasskey with apiHost (headless mode)", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(enrollPasskey).mockResolvedValue({ credentialId: "cred-1", name: "My phone" });

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    const result = await auth.registerPasskey("My phone");

    expect(result).toEqual({ credentialId: "cred-1", name: "My phone" });
    expect(enrollPasskey).toHaveBeenCalledWith("token-abc", "My phone", { apiHost: "api.jummon.dev" });
  });

  it("defaults apiHost to api.jummon.com when not configured", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(enrollPasskey).mockResolvedValue({ credentialId: "cred-1", name: "cred-1" });

    const auth = createJummonAuth(OPTIONS);
    await auth.registerPasskey();

    expect(enrollPasskey).toHaveBeenCalledWith("token-abc", undefined, { apiHost: "api.jummon.com" });
  });
});

describe("JummonAuthClient.setPassword()", () => {
  beforeEach(() => {
    vi.mocked(setPasswordSelfService).mockReset();
  });

  it("throws not_authenticated instead of calling the network when there is no session (redirect mode)", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.setPassword("a", "a")).rejects.toMatchObject({ code: "not_authenticated" });
    expect(setPasswordSelfService).not.toHaveBeenCalled();
  });

  it("resolves the current access_token and delegates to setPasswordSelfService with apiHost (headless mode)", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(setPasswordSelfService).mockResolvedValue(undefined);

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    await auth.setPassword("Sup3r$ecret", "Sup3r$ecret");

    expect(setPasswordSelfService).toHaveBeenCalledWith("token-abc", "Sup3r$ecret", "Sup3r$ecret", {
      apiHost: "api.jummon.dev",
    });
  });

  it("defaults apiHost to api.jummon.com when not configured", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(setPasswordSelfService).mockResolvedValue(undefined);

    const auth = createJummonAuth(OPTIONS);
    await auth.setPassword("a", "a");

    expect(setPasswordSelfService).toHaveBeenCalledWith("token-abc", "a", "a", { apiHost: "api.jummon.com" });
  });
});

describe("JummonAuthClient.beginOtpEnroll() / confirmOtpEnroll()", () => {
  beforeEach(() => {
    vi.mocked(beginOtpEnrollment).mockReset();
    vi.mocked(confirmOtpEnrollment).mockReset();
  });

  it("beginOtpEnroll() throws not_authenticated instead of calling the network when there is no session", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.beginOtpEnroll()).rejects.toMatchObject({ code: "not_authenticated" });
    expect(beginOtpEnrollment).not.toHaveBeenCalled();
  });

  it("confirmOtpEnroll() throws not_authenticated instead of calling the network when there is no session", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.confirmOtpEnroll("123456")).rejects.toMatchObject({ code: "not_authenticated" });
    expect(confirmOtpEnrollment).not.toHaveBeenCalled();
  });

  it("beginOtpEnroll() resolves the current access_token and delegates with apiHost (headless mode)", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(beginOtpEnrollment).mockResolvedValue({ secret: "JBSWY3DPEHPK3PXP", otpUrl: "otpauth://totp/x" });

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    const result = await auth.beginOtpEnroll();

    expect(result).toEqual({ secret: "JBSWY3DPEHPK3PXP", otpUrl: "otpauth://totp/x" });
    expect(beginOtpEnrollment).toHaveBeenCalledWith("token-abc", { apiHost: "api.jummon.dev" });
  });

  it("confirmOtpEnroll() resolves the current access_token and delegates otp (no secret) with apiHost", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(confirmOtpEnrollment).mockResolvedValue(undefined);

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    await auth.confirmOtpEnroll("123456");

    expect(confirmOtpEnrollment).toHaveBeenCalledWith("token-abc", "123456", {
      apiHost: "api.jummon.dev",
    });
  });

  it("defaults apiHost to api.jummon.com when not configured", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(beginOtpEnrollment).mockResolvedValue({ secret: "s", otpUrl: "u" });

    const auth = createJummonAuth(OPTIONS);
    await auth.beginOtpEnroll();

    expect(beginOtpEnrollment).toHaveBeenCalledWith("token-abc", { apiHost: "api.jummon.com" });
  });
});

describe("JummonAuthClient.listCredentials()", () => {
  beforeEach(() => {
    vi.mocked(listCredentials).mockReset();
  });

  it("throws not_authenticated instead of calling the network when there is no session", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.listCredentials()).rejects.toMatchObject({ code: "not_authenticated" });
    expect(listCredentials).not.toHaveBeenCalled();
  });

  it("resolves the current access_token and delegates to listCredentials with apiHost (headless mode)", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    const result = {
      credentials: [{ id: "cred-1", type: "passkey" as const, name: "My phone", active: true }],
      partialFailures: [],
    };
    vi.mocked(listCredentials).mockResolvedValue(result);

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    const got = await auth.listCredentials();

    expect(got).toEqual(result);
    expect(listCredentials).toHaveBeenCalledWith("token-abc", { apiHost: "api.jummon.dev" });
  });

  it("defaults apiHost to api.jummon.com when not configured", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(listCredentials).mockResolvedValue({ credentials: [], partialFailures: [] });

    const auth = createJummonAuth(OPTIONS);
    await auth.listCredentials();

    expect(listCredentials).toHaveBeenCalledWith("token-abc", { apiHost: "api.jummon.com" });
  });
});

describe("JummonAuthClient.removeCredential()", () => {
  beforeEach(() => {
    vi.mocked(removeCredential).mockReset();
  });

  it("throws not_authenticated instead of calling the network when there is no session", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue(null);

    const auth = createJummonAuth(OPTIONS);

    await expect(auth.removeCredential("cred-1")).rejects.toMatchObject({ code: "not_authenticated" });
    expect(removeCredential).not.toHaveBeenCalled();
  });

  it("resolves the current access_token and delegates to removeCredential with the id + apiHost (headless mode)", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(removeCredential).mockResolvedValue(undefined);

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    await auth.removeCredential("cred-1");

    expect(removeCredential).toHaveBeenCalledWith(
      "token-abc",
      "cred-1",
      expect.objectContaining({ apiHost: "api.jummon.dev" }),
    );
  });

  // --- #5b: headlessStepUp wiring (removeCredentialViaEngine -> buildHeadlessStepUp) --

  it("headless mode wires a headlessStepUp adapter (start + getAccessToken) into removeCredential()", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(removeCredential).mockResolvedValue(undefined);

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless", apiHost: "api.jummon.dev" });
    await auth.removeCredential("cred-1");

    const [, , opts] = vi.mocked(removeCredential).mock.calls[0] as [
      string,
      string,
      { headlessStepUp?: { start: unknown; getAccessToken: () => Promise<string | null> } },
    ];
    expect(typeof opts.headlessStepUp?.start).toBe("function");
    expect(typeof opts.headlessStepUp?.getAccessToken).toBe("function");

    // getAccessToken() on the adapter delegates straight back to the same
    // engine.getAccessToken() the outer call already resolved through —
    // NOT a second, independent token source.
    await expect(opts.headlessStepUp?.getAccessToken()).resolves.toBe("token-abc");
  });

  it("redirect mode never wires a headlessStepUp adapter — RedirectEngine has no headless re-auth to drive", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(removeCredential).mockResolvedValue(undefined);

    const auth = createJummonAuth(OPTIONS);
    await auth.removeCredential("cred-1");

    const [, , opts] = vi.mocked(removeCredential).mock.calls[0] as [string, string, { headlessStepUp?: unknown }];
    expect(opts.headlessStepUp).toBeUndefined();
  });

  it("propagates a typed last_factor_blocked rejection from the underlying module unchanged", async () => {
    vi.spyOn(HeadlessEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    const { JummonAuthError } = await import("./errors");
    vi.mocked(removeCredential).mockRejectedValue(
      new JummonAuthError("last_factor_blocked", "only remaining factor"),
    );

    const auth = createJummonAuth({ ...OPTIONS, mode: "headless" });

    await expect(auth.removeCredential("cred-1")).rejects.toMatchObject({ code: "last_factor_blocked" });
  });

  it("defaults apiHost to api.jummon.com when not configured", async () => {
    vi.spyOn(RedirectEngine.prototype, "getAccessToken").mockResolvedValue("token-abc");
    vi.mocked(removeCredential).mockResolvedValue(undefined);

    const auth = createJummonAuth(OPTIONS);
    await auth.removeCredential("cred-1");

    expect(removeCredential).toHaveBeenCalledWith(
      "token-abc",
      "cred-1",
      expect.objectContaining({ apiHost: "api.jummon.com" }),
    );
  });
});
