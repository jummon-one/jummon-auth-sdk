/**
 * Typed errors for @jummon/s2s. Every failure path resolves to an S2SError
 * with a stable `code` — consumers should switch on `code`, never on
 * `message` (message text is free to change). Mirrors the taxonomy shape of
 * `@jummon/auth`'s `JummonAuthError` (../../src/errors.ts) for a consistent
 * feel across both packages, but this is a fully separate, server-only
 * class — no shared runtime dependency between the two.
 */

export type S2SErrorCode =
  | "invalid_config"
  | "key_parse_failed"
  | "mint_failed"
  | "mint_timeout"
  | "request_timeout"
  | "http_error"
  | "invalid_response";

export class S2SError extends Error {
  readonly code: S2SErrorCode;
  // `Error.cause` (ES2022 lib) already declares this member — `override`
  // is required, not optional, once `lib` includes ES2022.
  override readonly cause?: unknown;
  /** HTTP status, when the failure came from an upstream response. */
  readonly status?: number;

  constructor(code: S2SErrorCode, message: string, options?: { cause?: unknown; status?: number }) {
    super(message);
    this.name = "S2SError";
    this.code = code;
    this.cause = options?.cause;
    this.status = options?.status;
    Object.setPrototypeOf(this, S2SError.prototype);
  }
}
