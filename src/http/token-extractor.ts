import type { HttpRequestView } from './request-adapter';

/** Reads the end user's access token from a request; `undefined` when there is none. */
export type TokenExtractor = (request: HttpRequestView) => string | undefined;

/** `Authorization: Bearer <token>` — the default. The scheme is case-insensitive. */
export const bearer =
  (headerName = 'authorization'): TokenExtractor =>
  (request) => {
    const value = request.header(headerName);
    const match = value ? /^Bearer\s+(\S+)\s*$/i.exec(value) : null;
    return match?.[1];
  };

/** A raw token in a header of its own, e.g. `fromTokenHeader('x-user-token')`. */
export const fromTokenHeader =
  (headerName: string): TokenExtractor =>
  (request) => {
    const value = request.header(headerName)?.trim();
    return value ? value : undefined;
  };

/** The first extractor that finds a token wins. */
export const firstOf =
  (...extractors: TokenExtractor[]): TokenExtractor =>
  (request) => {
    for (const extract of extractors) {
      const token = extract(request);
      if (token) return token;
    }
    return undefined;
  };
