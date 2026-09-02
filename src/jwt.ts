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
    const payload = base64UrlDecode(parts[1] as string);
    const parsed: unknown = JSON.parse(payload);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function base64UrlDecode(segment: string): string {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  if (typeof atob === "function") {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  // Non-browser fallback (SSR build tooling, tests).
  return Buffer.from(padded, "base64").toString("utf-8");
}
