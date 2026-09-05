import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { S2SError } from "./errors";
import { S2STokenSource } from "./tokenSource";

function generateKeyPairPem(): { privateKeyPem: string; publicKey: crypto.KeyObject } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey,
  };
}

function decodeAssertion(clientAssertion: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: Buffer;
  signingInput: string;
} {
  const parts = clientAssertion.split(".");
  const headerB64 = parts[0] ?? "";
  const payloadB64 = parts[1] ?? "";
  const sigB64 = parts[2] ?? "";
  const fromB64url = (s: string) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  return {
    header: JSON.parse(fromB64url(headerB64).toString("utf8")),
    payload: JSON.parse(fromB64url(payloadB64).toString("utf8")),
    signature: fromB64url(sigB64),
    signingInput: `${headerB64}.${payloadB64}`,
  };
}

describe("S2STokenSource — construction", () => {
  it("throws invalid_config when neither privateKey nor clientSecret is given", () => {
    expect(
      () =>
        new S2STokenSource({
          clientId: "sa-1",
          tenant: "prummo",
        }),
    ).toThrowError(S2SError);
  });

  it("throws invalid_config when BOTH privateKey and clientSecret are given", () => {
    const { privateKeyPem } = generateKeyPairPem();
    expect(
      () =>
        new S2STokenSource({
          clientId: "sa-1",
          tenant: "prummo",
          privateKey: privateKeyPem,
          clientSecret: "shh",
        }),
    ).toThrowError(S2SError);
  });

  it("throws key_parse_failed on garbage privateKey", () => {
    expect(
      () =>
        new S2STokenSource({
          clientId: "sa-1",
          tenant: "prummo",
          privateKey: "not a key",
        }),
    ).toThrowError(S2SError);
  });
});

describe("S2STokenSource — client_assertion shape (private_key_jwt)", () => {
  const { privateKeyPem, publicKey } = generateKeyPairPem();
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("signs iss/sub=clientId, aud=https://<issuerHost>/<tenant>/oidc, and posts X-Tenant-Id", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "tok-1", expires_in: 3600 }), { status: 200 }),
    );

    const source = new S2STokenSource({
      clientId: "prummo-sa",
      privateKey: privateKeyPem,
      tenant: "prummo",
      issuerHost: "idm.jummon.com",
      scope: "identity:users:create",
      audience: "catalog-api",
    });

    const token = await source.getToken();
    expect(token).toBe("tok-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.com/prummo/oidc/oauth/token");
    expect((init.headers as Record<string, string>)["X-Tenant-Id"]).toBe("prummo");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/x-www-form-urlencoded");

    const form = new URLSearchParams(init.body as string);
    expect(form.get("grant_type")).toBe("client_credentials");
    expect(form.get("scope")).toBe("identity:users:create");
    expect(form.get("audience")).toBe("catalog-api");
    expect(form.get("client_assertion_type")).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );

    const assertion = form.get("client_assertion");
    expect(assertion).toBeTruthy();
    const { header, payload, signature, signingInput } = decodeAssertion(assertion as string);

    expect(header.alg).toBe("RS256");
    expect(payload.iss).toBe("prummo-sa");
    expect(payload.sub).toBe("prummo-sa");
    // aud = the OIDC ISSUER, never the literal token endpoint URL.
    expect(payload.aud).toBe("https://idm.jummon.com/prummo/oidc");
    expect(payload.exp).toBe((payload.iat as number) + 60);
    expect(typeof payload.jti).toBe("string");

    const verified = crypto.verify(
      "RSA-SHA256",
      Buffer.from(signingInput, "utf8"),
      publicKey,
      signature,
    );
    expect(verified).toBe(true);
  });

  it("strips a scheme/trailing-slash from issuerHost before composing aud/tokenUrl", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "tok-1", expires_in: 3600 }), { status: 200 }),
    );
    const source = new S2STokenSource({
      clientId: "sa-1",
      privateKey: privateKeyPem,
      tenant: "acme",
      issuerHost: "https://idm.jummon.com/",
    });
    await source.getToken();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm.jummon.com/acme/oidc/oauth/token");
    const form = new URLSearchParams(init.body as string);
    const { payload } = decodeAssertion(form.get("client_assertion") as string);
    expect(payload.aud).toBe("https://idm.jummon.com/acme/oidc");
  });

  it("honors an explicit tokenUrl override", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "tok-1", expires_in: 3600 }), { status: 200 }),
    );
    const source = new S2STokenSource({
      clientId: "sa-1",
      privateKey: privateKeyPem,
      tenant: "acme",
      tokenUrl: "https://idm-dev.jummon.dev/acme/oidc/oauth/token",
    });
    await source.getToken();
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://idm-dev.jummon.dev/acme/oidc/oauth/token");
  });
});

describe("S2STokenSource — client_secret fallback", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("posts client_id/client_secret instead of a client_assertion", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "tok-1", expires_in: 3600 }), { status: 200 }),
    );
    const source = new S2STokenSource({
      clientId: "sa-1",
      clientSecret: "top-secret",
      tenant: "acme",
    });
    await source.getToken();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const form = new URLSearchParams(init.body as string);
    expect(form.get("client_id")).toBe("sa-1");
    expect(form.get("client_secret")).toBe("top-secret");
    expect(form.get("client_assertion")).toBeNull();
  });
});

describe("S2STokenSource — cache, refresh, and fail-closed", () => {
  const { privateKeyPem } = generateKeyPairPem();
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("serves the cached token without re-minting before 0.8*TTL has elapsed", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ access_token: "tok-1", expires_in: 1000 }), { status: 200 }),
    );
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    await source.getToken();
    vi.advanceTimersByTime(799_000); // just under 0.8 * 1000s
    const token = await source.getToken();

    expect(token).toBe("tok-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("re-mints once past 0.8*TTL", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "tok-1", expires_in: 1000 }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "tok-2", expires_in: 1000 }), { status: 200 }),
      );
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    await source.getToken();
    vi.advanceTimersByTime(801_000); // just over 0.8 * 1000s
    const token = await source.getToken();

    expect(token).toBe("tok-2");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("coalesces concurrent callers into a single in-flight mint", async () => {
    let resolveFetch!: (value: Response) => void;
    fetchMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      }),
    );
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    const p1 = source.getToken();
    const p2 = source.getToken();
    resolveFetch(new Response(JSON.stringify({ access_token: "tok-1", expires_in: 3600 }), { status: 200 }));

    const [t1, t2] = await Promise.all([p1, p2]);
    expect(t1).toBe("tok-1");
    expect(t2).toBe("tok-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("serves a stale-but-not-hard-expired token when a re-mint fails", async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "tok-1", expires_in: 1000 }), { status: 200 }),
      )
      .mockRejectedValueOnce(new Error("network down"));
    const onStaleTokenServed = vi.fn();
    const source = new S2STokenSource({
      clientId: "sa-1",
      privateKey: privateKeyPem,
      tenant: "acme",
      onStaleTokenServed,
    });

    await source.getToken();
    vi.advanceTimersByTime(801_000); // past soft, still under hard (1000s)
    const token = await source.getToken();

    expect(token).toBe("tok-1");
    expect(onStaleTokenServed).toHaveBeenCalledTimes(1);
  });

  it("fails closed (throws) when the mint fails and nothing is cached yet", async () => {
    fetchMock.mockRejectedValue(new Error("network down"));
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    await expect(source.getToken()).rejects.toThrow();
  });

  it("throws http_error on a non-2xx token-endpoint response", async () => {
    fetchMock.mockResolvedValue(new Response("bad client", { status: 401 }));
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    await expect(source.getToken()).rejects.toMatchObject({ code: "http_error", status: 401 });
  });

  it("throws invalid_response when the token endpoint omits access_token/expires_in", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));
    const source = new S2STokenSource({ clientId: "sa-1", privateKey: privateKeyPem, tenant: "acme" });

    await expect(source.getToken()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
