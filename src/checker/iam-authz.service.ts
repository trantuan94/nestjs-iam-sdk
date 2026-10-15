import { Inject, Injectable, Logger } from '@nestjs/common';
import { AuthorizationClient, IAM_AUTHZ_CLIENT } from '../client/iam-authz.client';
import type {
  AuthorizeEnvironment,
  AuthorizeRequest,
  AuthorizeResource,
  AuthorizeResponse,
} from '../client/contract';
import {
  IamAuthzError,
  IamMisconfigurationError,
  IamUnauthenticatedError,
  IamUnavailableError,
} from '../client/errors';
import { InMemoryDecisionCache, type DecisionCache } from '../decision/decision-cache';
import { cacheTtlFor, decisionKey } from '../decision/decision-key';
import { InFlight } from '../decision/in-flight';
import { viewOf, type HttpRequestView } from '../http/request-adapter';
import { bearer } from '../http/token-extractor';
import {
  IAM_AUTHZ_OPTIONS,
  type AuthzFailure,
  type DecisionEvent,
  type ResolvedIamAuthzOptions,
} from '../options';
import { AuthzFailureSignal, defaultException } from './failure';
import { recordDecision } from './request-decisions';

const failureOf = (error: unknown): AuthzFailure => {
  if (error instanceof IamUnauthenticatedError) return { kind: 'unauthenticated', error };
  if (error instanceof IamMisconfigurationError) return { kind: 'misconfigured', error };
  if (error instanceof IamUnavailableError) return { kind: 'unavailable', error };
  // Anything else — a bug in a resolver, a cache store that threw — is not a
  // decision either, and is refused like an unavailable service.
  return {
    kind: 'unavailable',
    error: new IamUnavailableError(`Authorization failed: ${(error as Error)?.message ?? String(error)}`),
  };
};

/**
 * Asks IAM about one action on one resource, for one request. The guard
 * (`@Authorize`) and the in-handler checker (`@Authz()`) both go through here,
 * so a decision is reached, cached, observed and refused in exactly one way.
 *
 * FAIL-CLOSED, with no option otherwise: only a decision the service gave can
 * let a request through.
 */
@Injectable()
export class IamAuthz {
  private readonly logger = new Logger('IamAuthz');
  private readonly inFlight = new InFlight<AuthorizeResponse>();
  private readonly cache: DecisionCache | undefined;
  private readonly cacheTtlMs: number;

  constructor(
    @Inject(IAM_AUTHZ_OPTIONS) private readonly options: ResolvedIamAuthzOptions,
    @Inject(IAM_AUTHZ_CLIENT) private readonly client: AuthorizationClient,
  ) {
    const cache = options.cache;
    this.cache = cache ? (cache.store ?? new InMemoryDecisionCache(cache.maxEntries)) : undefined;
    this.cacheTtlMs = cache ? cache.ttlMs : 0;
  }

  /**
   * `true` / `false` for an answered question. A refusal of the CREDENTIAL, a
   * misconfiguration or an unavailable service still THROW — returning `false`
   * for those would let a caller render "not permitted" for an outage.
   */
  async check(
    request: unknown,
    action: string,
    resource: AuthorizeResource,
    environment?: AuthorizeEnvironment,
  ): Promise<boolean> {
    return (await this.decide(request, action, resource, environment)).allowed;
  }

  /** Like `check`, and a denial throws too (403 by default). Resolves with the decision. */
  async assert(
    request: unknown,
    action: string,
    resource: AuthorizeResource,
    environment?: AuthorizeEnvironment,
  ): Promise<AuthorizeResponse> {
    const decision = await this.decide(request, action, resource, environment);
    if (!decision.allowed) throw this.exceptionFor({ kind: 'denied', decision });
    return decision;
  }

  /** The decision for one requirement, recorded on the request; throws the rendered exception on any failure. */
  async decide(
    request: unknown,
    action: string,
    resource: AuthorizeResource,
    environment?: AuthorizeEnvironment,
  ): Promise<AuthorizeResponse> {
    try {
      const decision = await this.decideOrSignal(viewOf(request), action, resource, environment);
      recordDecision(request, decision);
      return decision;
    } catch (error) {
      if (error instanceof AuthzFailureSignal) throw this.exceptionFor(error.failure);
      throw error;
    }
  }

  /** Same as `decide`, but failures surface as `AuthzFailureSignal` — for the guard, which renders them itself. */
  async decideOrSignal(
    view: HttpRequestView,
    action: string,
    resource: AuthorizeResource,
    environment?: AuthorizeEnvironment,
  ): Promise<AuthorizeResponse> {
    const token = (this.options.tokenExtractor ?? bearer())(view);
    if (!token) throw new AuthzFailureSignal({ kind: 'missing-token' });

    if (!resource || typeof resource.type !== 'string' || resource.type === '') {
      throw new AuthzFailureSignal({
        kind: 'misconfigured',
        error: new IamMisconfigurationError(`Authorization of '${action}' resolved no resource type`),
      });
    }

    const request: AuthorizeRequest = {
      token,
      resource,
      action,
      environment: {
        ...(this.options.environment?.(view) ?? {}),
        ...(environment ?? {}),
        // Last, so neither the options nor the call site can claim another IP.
        // `undefined` lets the service fall back to the connection's address.
        ip: view.ip(),
      },
    };

    const startedAt = Date.now();
    try {
      const { decision, cached } = await this.answer(request);
      this.observe({
        action,
        resourceType: resource.type,
        allowed: decision.allowed,
        userId: decision.userId,
        cached,
        latencyMs: Date.now() - startedAt,
      });
      return decision;
    } catch (error) {
      const failure = failureOf(error);
      const iamError = (failure as { error?: IamAuthzError }).error;
      this.observe({
        action,
        resourceType: resource.type,
        allowed: false,
        cached: false,
        latencyMs: Date.now() - startedAt,
        error: iamError,
      });
      if (failure.kind === 'misconfigured') {
        this.logger.error(
          `Authorization of '${action}' on '${resource.type}' is misconfigured: ${iamError?.message}`,
        );
      } else if (failure.kind === 'unavailable') {
        this.logger.warn(`Authorization of '${action}' on '${resource.type}' denied: ${iamError?.message}`);
      }
      throw new AuthzFailureSignal(failure);
    }
  }

  exceptionFor(failure: AuthzFailure): Error {
    return (this.options.exceptionFactory ?? defaultException)(failure);
  }

  private async answer(
    request: AuthorizeRequest,
  ): Promise<{ decision: AuthorizeResponse; cached: boolean }> {
    const key = decisionKey(request);
    const hit = await this.cacheGet(key);
    if (hit) return { decision: hit, cached: true };
    const decision = await this.inFlight.run(key, async () => {
      const fresh = await this.client.authorize(request);
      await this.cacheSet(key, fresh, cacheTtlFor(request.token, this.cacheTtlMs));
      return fresh;
    });
    return { decision, cached: false };
  }

  // A cache that fails is a cache that misses: it can make the SDK slower,
  // never turn a decision the service gave into a refusal (or the reverse).
  private async cacheGet(key: string): Promise<AuthorizeResponse | undefined> {
    if (!this.cache) return undefined;
    try {
      return await this.cache.get(key);
    } catch (error) {
      this.logger.warn(`Decision cache read failed: ${(error as Error)?.message ?? String(error)}`);
      return undefined;
    }
  }

  private async cacheSet(key: string, decision: AuthorizeResponse, ttlMs: number): Promise<void> {
    if (!this.cache || ttlMs <= 0) return;
    try {
      await this.cache.set(key, decision, ttlMs);
    } catch (error) {
      this.logger.warn(`Decision cache write failed: ${(error as Error)?.message ?? String(error)}`);
    }
  }

  private observe(event: DecisionEvent): void {
    if (!this.options.onDecision) return;
    try {
      this.options.onDecision(event);
    } catch (error) {
      this.logger.warn(`onDecision threw: ${(error as Error)?.message ?? String(error)}`);
    }
  }
}
