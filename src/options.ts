import type { HttpException } from '@nestjs/common';
import { inspect } from 'node:util';
import type { AuthorizeResponse } from './client/contract';
import type { IamAuthzError } from './client/errors';
import type { DecisionCache } from './decision/decision-cache';
import type { HttpRequestView } from './http/request-adapter';
import type { TokenExtractor } from './http/token-extractor';

export const IAM_AUTHZ_OPTIONS = Symbol('IAM_AUTHZ_OPTIONS');

/** What a guard or `@Authz()` check produced, for `onDecision`. Never carries the token. */
export interface DecisionEvent {
  action: string;
  resourceType: string;
  allowed: boolean;
  userId?: string;
  cached: boolean;
  latencyMs: number;
  /** Set when no decision was had; `allowed` is then false. */
  error?: IamAuthzError;
}

/** Why a request was not let through — the input to `exceptionFactory`. */
export type AuthzFailure =
  | { kind: 'missing-token' }
  | { kind: 'undeclared-route' }
  | { kind: 'denied'; decision: AuthorizeResponse }
  | { kind: 'unauthenticated'; error: IamAuthzError }
  | { kind: 'misconfigured'; error: IamAuthzError }
  | { kind: 'unavailable'; error: IamAuthzError };

export interface DecisionCacheOptions {
  /** How long a decision is reused. Keep it short: the service cannot invalidate it. */
  ttlMs: number;
  /** In-memory LRU bound. Default 10 000. Ignored with a custom `store`. */
  maxEntries?: number;
  /** Replace the in-memory store, e.g. with Redis shared across replicas. */
  store?: DecisionCache;
}

export interface IamAuthzOptions {
  /** The service's base URL including its global prefix, e.g. `https://iam.example.com/api/iam`. */
  baseUrl: string;
  /** The `X-API-Key` this service authenticates with. Never logged. */
  apiKey: string;
  /** Per-call timeout. Default 2000 ms. A timeout denies. */
  timeoutMs?: number;
  /**
   * Reuse decisions for a short time. OFF by default: a revoked token or a
   * removed role then takes up to `ttlMs` to reach this service.
   */
  cache?: false | DecisionCacheOptions;
  /** Where the end user's token is read from. Default: `Authorization: Bearer`. */
  tokenExtractor?: TokenExtractor;
  /** Extra `env.*` attributes for every check. `ip` is always the request's own and cannot be set here. */
  environment?: (request: HttpRequestView) => Record<string, unknown>;
  /** Observability hook: one call per decision (or failure). Errors thrown here are swallowed. */
  onDecision?: (event: DecisionEvent) => void;
  /** Turn a failure into the exception the route throws. Default: 401 / 403 / 500 / 503, see README. */
  exceptionFactory?: (failure: AuthzFailure) => HttpException | Error;
  /**
   * Install the guard globally, DENY BY DEFAULT: an HTTP route with neither
   * `@Authorize` nor `@SkipAuthorize` is refused with 403. Default false.
   */
  global?: boolean;
}

/** A secret that does not print: `JSON.stringify`, `inspect` and template strings all redact it. */
export class Secret {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toJSON(): string {
    return '[redacted]';
  }

  toString(): string {
    return '[redacted]';
  }

  [inspect.custom](): string {
    return '[redacted]';
  }
}

export interface ResolvedIamAuthzOptions
  extends Omit<IamAuthzOptions, 'apiKey' | 'timeoutMs' | 'baseUrl'> {
  baseUrl: string;
  apiKey: Secret;
  timeoutMs: number;
}

export const DEFAULT_TIMEOUT_MS = 2000;

/** Validates at module init, so a misconfigured service fails at boot, not on its first request. */
export const resolveOptions = (options: IamAuthzOptions): ResolvedIamAuthzOptions => {
  if (!options || typeof options !== 'object') {
    throw new Error('IamAuthzModule: options are required');
  }
  if (typeof options.apiKey !== 'string' || options.apiKey.trim() === '') {
    throw new Error('IamAuthzModule: `apiKey` is required');
  }
  let url: URL;
  try {
    url = new URL(options.baseUrl);
  } catch {
    throw new Error('IamAuthzModule: `baseUrl` must be an absolute URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('IamAuthzModule: `baseUrl` must be http(s)');
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('IamAuthzModule: `timeoutMs` must be a positive number');
  }
  if (options.cache && (!Number.isFinite(options.cache.ttlMs) || options.cache.ttlMs <= 0)) {
    throw new Error('IamAuthzModule: `cache.ttlMs` must be a positive number');
  }
  return {
    ...options,
    baseUrl: url.toString().replace(/\/+$/, ''),
    apiKey: new Secret(options.apiKey),
    timeoutMs,
  };
};
