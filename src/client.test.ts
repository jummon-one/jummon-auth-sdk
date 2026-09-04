import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./internal/passkeyEnrollment", () => ({
  DEFAULT_API_HOST: "api.jummon.com",
  enrollPasskey: vi.fn(),
}));

import { createJummonAuth } from "./client";
import { enrollPasskey } from "./internal/passkeyEnrollment";
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
