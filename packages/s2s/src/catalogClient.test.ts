import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { JummonCatalogClient, type TokenProvider } from "./catalogClient";
import { S2SError } from "./errors";

function fakeTokenSource(token = "tok-1"): TokenProvider {
  return { getToken: vi.fn().mockResolvedValue(token) };
}

describe("JummonCatalogClient — createUser", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("posts personal_email (never email) and the required client_id, with Bearer auth", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          user: { id: "u-1", kind: "human", personal_email: "jane@example.com" },
          partial_success: false,
        }),
        { status: 201 },
      ),
    );
    const tokenSource = fakeTokenSource();
    const client = new JummonCatalogClient({ tokenSource, apiHost: "api.jummon.dev" });

    const result = await client.createUser({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane@example.com",
      password: "correct-horse-battery-staple",
      clientId: "prummo-app",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.dev/catalog/users");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");

    const body = JSON.parse(init.body as string);
    expect(body.personal_email).toBe("jane@example.com");
    expect(body.email).toBeUndefined();
    expect(body.client_id).toBe("prummo-app");
    expect(body.password).toBe("correct-horse-battery-staple");
    // onboarding defaults to "password" when a password is supplied and no
    // explicit onboarding was passed.
    expect(body.onboarding).toBe("password");
    expect(body.first_name).toBe("Jane");
    expect(body.last_name).toBe("Doe");

    expect(result.user.id).toBe("u-1");
    expect(result.partialSuccess).toBe(false);
  });

  it("prefers personalEmail over the email alias when both are given", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "u-1", kind: "human" }, partial_success: false }), {
        status: 201,
      }),
    );
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });

    await client.createUser({
      email: "alias@example.com",
      personalEmail: "canonical@example.com",
      clientId: "prummo-app",
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.personal_email).toBe("canonical@example.com");
  });

  it("does not default onboarding when no password is set (plain create, invite later)", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "u-1", kind: "human" }, partial_success: false }), {
        status: 201,
      }),
    );
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });

    await client.createUser({ email: "jane@example.com", clientId: "prummo-app" });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.onboarding).toBeUndefined();
    expect(body.password).toBeUndefined();
  });

  it("rejects locally (never calls fetch) when clientId is missing", async () => {
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });
    await expect(client.createUser({ email: "jane@example.com" } as never)).rejects.toBeInstanceOf(S2SError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("defaults apiHost to api.jummon.com", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "u-1", kind: "human" }, partial_success: false }), {
        status: 201,
      }),
    );
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });
    await client.createUser({ email: "jane@example.com", clientId: "prummo-app" });
    const [url] = fetchMock.mock.calls[0] as [string];
    expect(url).toBe("https://api.jummon.com/catalog/users");
  });

  it("throws http_error with the status on a non-2xx response", async () => {
    fetchMock.mockResolvedValue(new Response("boom", { status: 403 }));
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });
    await expect(
      client.createUser({ email: "jane@example.com", clientId: "b2b-portal" }),
    ).rejects.toMatchObject({ code: "http_error", status: 403 });
  });
});

describe("JummonCatalogClient — invite", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("posts to /catalog/users/{userId}/passwordless-invite with client_id required", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          magic_link: { url: "https://idm.jummon.com/m/abc", expires_at: "2026-09-05T00:00:00Z", token_id: "t-1" },
          email_sent: true,
        }),
        { status: 201 },
      ),
    );
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });

    const result = await client.invite({
      userId: "u-1",
      clientId: "prummo-app",
      redirectTo: "prummoapp://auth/callback",
      linkType: "passwordless-only",
      requiredActions: ["configure-passwordless"],
      sendEmail: true,
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.com/catalog/users/u-1/passwordless-invite");
    const body = JSON.parse(init.body as string);
    expect(body.client_id).toBe("prummo-app");
    expect(body.redirect_to).toBe("prummoapp://auth/callback");
    expect(body.link_type).toBe("passwordless-only");
    expect(body.required_actions).toEqual(["configure-passwordless"]);
    expect(body.send_email).toBe(true);

    expect(result.magicLink.url).toBe("https://idm.jummon.com/m/abc");
    expect(result.magicLink.tokenId).toBe("t-1");
    expect(result.emailSent).toBe(true);
  });

  it("rejects locally when clientId or userId is missing", async () => {
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });
    await expect(client.invite({ userId: "u-1" } as never)).rejects.toBeInstanceOf(S2SError);
    await expect(client.invite({ clientId: "prummo-app" } as never)).rejects.toBeInstanceOf(S2SError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("JummonCatalogClient — setPassword", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("posts password + confirmation_password (mirrored) to /catalog/users/{id}/credentials/password", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });

    await client.setPassword("u-1", "new-pass-123");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.jummon.com/catalog/users/u-1/credentials/password");
    const body = JSON.parse(init.body as string);
    expect(body.password).toBe("new-pass-123");
    expect(body.confirmation_password).toBe("new-pass-123");
  });

  it("uses an explicit confirmationPassword when given", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });

    await client.setPassword("u-1", "new-pass-123", "different");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.confirmation_password).toBe("different");
  });

  it("rejects locally on empty userId/password", async () => {
    const client = new JummonCatalogClient({ tokenSource: fakeTokenSource() });
    await expect(client.setPassword("", "x")).rejects.toBeInstanceOf(S2SError);
    await expect(client.setPassword("u-1", "")).rejects.toBeInstanceOf(S2SError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
