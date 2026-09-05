# @jummon/s2s

Server-side helper for Jummon **service-account** (S2S) integrations —
extracted from the backend-proxied integration pain every integrator
(Prummo first, see
`engineering-team/initiatives/headless-embeddable-auth/PRUMMO-INTEGRATION-GUIDE.md`
§8.1) has had to hand-roll: `private_key_jwt` client-assertion signing +
guessing catalog-api's request-body field names.

This is a **Node-only, server-side** package. It uses `node:crypto` and
global `fetch` — never import it into a browser bundle. If you're building
a customer-facing login UI, you want
[`@jummon/auth`](../../README.md) instead; the two packages share no
runtime code on purpose (see [Packaging](#packaging) below).

## Install

```bash
npm install @jummon/s2s
```

Requires Node >= 18 (global `fetch`, Web Crypto-compatible `node:crypto`).

## 1. Mint tokens — `S2STokenSource`

```ts
import { S2STokenSource } from "@jummon/s2s";

const tokenSource = new S2STokenSource({
  clientId: process.env.JUMMON_SA_CLIENT_ID!,
  // JWK JSON or PEM — returned ONCE by
  // POST /catalog/clients/{id}/credentials/jwt-keys. Store in your vault,
  // never in source control or logs.
  privateKey: process.env.JUMMON_SA_PRIVATE_KEY!,
  tenant: "prummo",
  issuerHost: "idm.jummon.com", // omit for prod default; "idm-dev.jummon.dev" in dev
  // scope / audience: as instructed at provisioning time, if any.
});

const accessToken = await tokenSource.getToken();
```

- **Caches and proactively refreshes** at 80% of the issued token's TTL —
  never mints on every call.
- **Fails closed**, with one carve-out: if a mint fails but a
  previously-issued token hasn't hard-expired yet, that stale token is
  served instead of throwing (`onStaleTokenServed` lets you observe this).
- **Coalesces concurrent callers** into a single in-flight mint — no
  thundering herd against the token endpoint.
- Construct **one `S2STokenSource` per (callee, scope/audience) pair** you
  call. Never share one instance across two different audiences.

**`client_secret` fallback** (documented bridge for backends that can't
yet sign a JWT assertion — guide §8.1.1; migrate to `private_key_jwt` when
you can):

```ts
const tokenSource = new S2STokenSource({
  clientId: process.env.JUMMON_SA_CLIENT_ID!,
  clientSecret: process.env.JUMMON_SA_CLIENT_SECRET!,
  tenant: "prummo",
});
```

## 2. Call catalog-api — `JummonCatalogClient`

Thin wrappers with the **correct field names baked in** — no more silently
dropped `email` fields or guessed body shapes.

```ts
import { JummonCatalogClient } from "@jummon/s2s";

const catalog = new JummonCatalogClient({ tokenSource, apiHost: "api.jummon.com" });

// Create a user WITH a password (backend-proxied / password onboarding).
const { user } = await catalog.createUser({
  firstName: "Jane",
  lastName: "Doe",
  email: "jane@example.com", // -> personal_email on the wire, never "email"
  password: "…",
  clientId: "prummo-app", // REQUIRED for a service-account caller
});

// Passwordless onboarding — create without a password, then invite with
// full control over required_actions/link_type/redirect_to.
const { user: invited } = await catalog.createUser({
  email: "jane@example.com",
  clientId: "prummo-app",
});
const { magicLink } = await catalog.invite({
  userId: invited.id,
  clientId: "prummo-app",
  redirectTo: "prummoapp://auth/callback",
  linkType: "passwordless-only",
  requiredActions: ["configure-passwordless"], // otp-configure is still added server-side — see below
});

// Set/reset a password directly.
await catalog.setPassword(user.id, "new-password");
```

### Gotchas this wrapper bakes in for you

- `personal_email` (or `company_email`), **never** `email` — a bare
  `email` on `POST /catalog/users` is silently ignored by the binder.
- `client_id` is **required** for any non-interactive (service-account)
  caller on both `createUser` and `invite` — omitting it 400s
  `INVITE_CLIENT_ID_REQUIRED`; this wrapper throws locally (`S2SError`,
  `invalid_config`) before making the network call, so you fail fast.
- `createUser` sets `onboarding: "password"` automatically once you pass
  `password` — you don't have to remember the pairing.
- `invite`'s `requiredActions: []` is treated identically to "omitted" by
  catalog-api (falls back to the full first-time set) — list what you want
  explicitly. `otp-configure` is re-added unconditionally server-side as a
  mandatory first-login floor, even if you don't list it.
- `setPassword(userId, password)` sends the same value for both `password`
  and `confirmation_password` (both are required by catalog-api) — pass a
  third argument only if you genuinely captured two independent inputs.

The service-account's token needs the corresponding permission via a
role/grant: `identity:users:create` for `createUser`, the `MAGIC_LINK_CREATE`
operation for `invite`, `UserPasswordUpdate` for `setPassword` — provisioning
one is out of scope for this package (see the Prummo guide §8.1 sidebar for
the MCP/Cockpit walkthrough).

## Error handling

Every failure — local validation, network, timeout, non-2xx response —
throws an `S2SError` with a stable `code` (`invalid_config`,
`key_parse_failed`, `mint_failed`, `mint_timeout`, `request_timeout`,
`http_error`, `invalid_response`) and, for HTTP failures, a `status`.
Switch on `code`, not `message`.

## Packaging

`@jummon/s2s` lives in this monorepo (`jummon-auth-sdk`) as a sibling
package to `@jummon/auth`, under `packages/s2s/`, with its **own**
`package.json`, `tsconfig.json`, `tsup.config.ts`, and `vitest.config.ts` —
entirely independent tooling, so it never gets pulled into `@jummon/auth`'s
browser build. It ships the same way `@jummon/auth` does: `gh release
create` on this repo triggers the trusted-publisher (OIDC, tokenless)
GitHub Actions workflow — see the root repo's `.github/workflows/publish.yml`
for the mechanism; `@jummon/s2s` needs its own workflow file (or a
path-filtered job) once this package is promoted to publish. See the repo
root's `CLAUDE.md`/session notes for the one-time npm Trusted Publisher
setup this requires for the `@jummon/s2s` package name.
