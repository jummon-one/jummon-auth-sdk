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

import { createJummonAuth } from "./client";
import { enrollPasskey } from "./internal/passkeyEnrollment";
import { setPasswordSelfService } from "./internal/passwordSelfService";
import { beginOtpEnrollment, confirmOtpEnrollment } from "./internal/otpEnrollment";
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
