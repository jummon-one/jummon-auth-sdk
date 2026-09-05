import { base64UrlToBytes } from "./internal/base64";

/**
 * Best-effort, unverified decode of a JWT payload. This SDK never verifies
 * a signature client-side (the token was minted for us, over TLS, by the
 * auth-engine we just talked to) — this exists only to surface claims
 * (roles[], permissions[]) that already rode the token, not to establish
 * trust. Never use this output as an authorization decision on its own;
 * resource servers must still validate the token themselves.
 */
export function decodeJwtPayload(token: string | undefined | null): Record<string, unknown> | null {
  if (!token) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length < 2) {
    return null;
  }
  try {
    const payload = new TextDecoder().decode(base64UrlToBytes(parts[1] as string));
    const parsed: unknown = JSON.parse(payload);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
