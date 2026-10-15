import { createHash } from 'node:crypto';
import type { AuthorizeRequest } from '../client/contract';

/** JSON with object keys sorted at every depth, so `{a,b}` and `{b,a}` hash alike. */
export const stableStringify = (value: unknown): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
};

/**
 * The whole request, hashed: token, action, resource and environment. The
 * token is never stored or logged in the clear — only inside this digest.
 */
export const decisionKey = (request: AuthorizeRequest): string =>
  createHash('sha256').update(stableStringify(request)).digest('hex');

/**
 * Seconds-since-epoch `exp` from a JWT, read WITHOUT verifying it. Used only
 * to SHORTEN a cache TTL, so a forged claim can do no more than make an entry
 * expire sooner. Never used to decide anything.
 */
export const tokenExpiresAtMs = (token: string): number | undefined => {
  const payload = token.split('.')[1];
  if (!payload) return undefined;
  try {
    const exp = (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { exp?: unknown })
      .exp;
    return typeof exp === 'number' && Number.isFinite(exp) ? exp * 1000 : undefined;
  } catch {
    return undefined;
  }
};

/** `min(ttlMs, token lifetime left)`; 0 means "do not cache". */
export const cacheTtlFor = (token: string, ttlMs: number, now = Date.now()): number => {
  const expiresAt = tokenExpiresAtMs(token);
  if (expiresAt === undefined) return ttlMs;
  return Math.max(0, Math.min(ttlMs, expiresAt - now));
};
