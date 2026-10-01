import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildJummonUser, buildJummonUserAsync } from "./mapUser";
import { __clearRichClaimsCacheForTests } from "./internal/richClaims";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe("buildJummonUser (sync, unchanged 3-arg public API)", () => {
  it("keeps the EXACT pre-migration fallback order (accessClaims then idClaims) when no richClaims is passed", () => {
    const user = buildJummonUser(
      { sub: "u1", permissions: ["from:idtoken"], roles: ["FromIdToken"] },
      { permissions: ["from:accesstoken"], roles: ["FromAccessToken"] },
      "acme",
    );
    expect(user.permissions).toEqual(["from:accesstoken"]);
    expect(user.roles).toEqual(["FromAccessToken"]);
  });

  it("prefers richClaims.permissions/roles over accessClaims/idClaims when passed", () => {
    const user = buildJummonUser(
      { sub: "u1", permissions: ["from:idtoken"] },
      { permissions: ["from:accesstoken"] },
      "acme",
      { permissions: ["catalog:roles:create"], roles: ["Admin"] },
    );
    expect(user.permissions).toEqual(["catalog:roles:create"]);
    expect(user.roles).toEqual(["Admin"]);
  });

  it("falls back to accessClaims/idClaims when richClaims is null (userinfo unreachable)", () => {
    const user = buildJummonUser(
      { sub: "u1", roles: ["FromIdToken"] },
      { permissions: ["from:accesstoken"] },
      "acme",
      null,
    );
    expect(user.permissions).toEqual(["from:accesstoken"]);
    expect(user.roles).toEqual(["FromIdToken"]);
  });

  it("public field shape/type is unchanged: permissions/roles stay string[], never a Promise", () => {
    const user = buildJummonUser({ sub: "u1" }, {}, "acme", { permissions: ["a:b:c"] });
    expect(Array.isArray(user.permissions)).toBe(true);
    expect(user.permissions).not.toBeInstanceOf(Promise);
  });
});

describe("buildJummonUser — idp/federated (#261)", () => {
  it("maps a token with an idp claim to idp:<value> and federated:true, preferring richClaims over accessClaims/idClaims", () => {
    const user = buildJummonUser(
      { sub: "u1", idp: "from:idtoken" },
      { idp: "from:accesstoken" },
      "acme",
      { idp: "google-workspace" },
    );
    expect(user.idp).toBe("google-workspace");
    expect(user.federated).toBe(true);
  });

  it("falls back to accessClaims then idClaims for idp when richClaims is absent, same precedence as roles/permissions", () => {
    const user = buildJummonUser({ sub: "u1", idp: "from:idtoken" }, { idp: "from:accesstoken" }, "acme", null);
    expect(user.idp).toBe("from:accesstoken");
    expect(user.federated).toBe(true);
  });

  it("yields idp:null and federated:false when no claim set carries an idp", () => {
    const user = buildJummonUser({ sub: "u1" }, {}, "acme", null);
    expect(user.idp).toBeNull();
    expect(user.federated).toBe(false);
  });

  it("treats an empty-string idp claim as absent — not federated", () => {
    const user = buildJummonUser({ sub: "u1" }, {}, "acme", { idp: "" });
    expect(user.idp).toBeNull();
    expect(user.federated).toBe(false);
  });
});

describe("buildJummonUserAsync (issue #8 SDK migration — userinfo PRIMARY, JWT fallback)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    __clearRichClaimsCacheForTests();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("prefers userinfo's permissions over the JWT access_token's permissions claim", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          issuer: "https://idm.jummon.dev/map-tenant-1/oidc",
          token_endpoint: "https://idm.jummon.dev/map-tenant-1/oidc/oauth/token",
          userinfo_endpoint: "https://idm.jummon.dev/map-tenant-1/oidc/userinfo",
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ permissions: ["catalog:roles:create"] }));

    const user = await buildJummonUserAsync(
      { sub: "u1" },
      { permissions: ["stale:jwt:claim"] },
      "map-tenant-1",
      "idm.jummon.dev",
      "at-live",
    );

    expect(user.permissions).toEqual(["catalog:roles:create"]);
  });

  it("degrades gracefully to the JWT decode when userinfo is unreachable — never harder-fails than the pre-migration behavior", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    const user = await buildJummonUserAsync(
      { sub: "u1", permissions: ["from:idtoken"] },
      { permissions: ["from:accesstoken"] },
      "map-tenant-2",
      "idm.jummon.dev",
      "at-live",
    );

    expect(user.permissions).toEqual(["from:accesstoken"]);
  });

  it("skips the network call entirely and falls back straight to JWT claims when there is no access_token", async () => {
    const user = await buildJummonUserAsync(
      { sub: "u1", permissions: ["from:idtoken"] },
      {},
      "map-tenant-3",
      "idm.jummon.dev",
      undefined,
    );

    expect(user.permissions).toEqual(["from:idtoken"]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
