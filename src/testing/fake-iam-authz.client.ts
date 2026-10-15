import type { AuthorizationClient } from '../client/iam-authz.client';
import type { AuthorizeRequest, AuthorizeResponse } from '../client/contract';
import {
  IamMisconfigurationError,
  IamUnauthenticatedError,
  IamUnavailableError,
} from '../client/errors';

export interface FakeRule {
  effect: 'allow' | 'deny';
  /** A full code, or `*` for any action. */
  action: string;
  /** The rule applies only when every listed attribute equals the resource's. */
  match?: Record<string, unknown>;
}

/** Allows `action`, optionally only for resources whose attributes `match`. */
export const allow = (action: string, match?: Record<string, unknown>): FakeRule => ({
  effect: 'allow',
  action,
  match,
});

/** Denies `action`, optionally only for resources whose attributes `match`. */
export const deny = (action: string, match?: Record<string, unknown>): FakeRule => ({
  effect: 'deny',
  action,
  match,
});

export type FakeFailure = 'unauthenticated' | 'misconfigured' | 'unavailable';

/**
 * Stands in for IAM in a resource service's tests. The FIRST matching rule
 * decides; no matching rule denies, as IAM does when nothing grants the code.
 * Every call is recorded in `calls`, token included, so a test can assert
 * exactly what would have been sent.
 */
export class FakeIamAuthzClient implements AuthorizationClient {
  readonly calls: AuthorizeRequest[] = [];
  private failure: { kind: FakeFailure; remaining: number } | undefined;

  constructor(
    private rules: FakeRule[] = [],
    private userId = 'test-user',
  ) {}

  setRules(rules: FakeRule[]): this {
    this.rules = rules;
    return this;
  }

  /** The next `times` calls (default: all of them) fail the way IAM would. */
  failWith(kind: FakeFailure, times = Number.POSITIVE_INFINITY): this {
    this.failure = { kind, remaining: times };
    return this;
  }

  reset(): this {
    this.calls.length = 0;
    this.failure = undefined;
    return this;
  }

  async authorize(request: AuthorizeRequest): Promise<AuthorizeResponse> {
    this.calls.push(request);
    if (this.failure && this.failure.remaining > 0) {
      this.failure.remaining -= 1;
      throw this.errorFor(this.failure.kind);
    }
    const rule = this.rules.find(
      (r) =>
        (r.action === '*' || r.action === request.action) &&
        Object.entries(r.match ?? {}).every(([key, value]) => request.resource[key] === value),
    );
    return {
      allowed: rule?.effect === 'allow',
      userId: this.userId,
      action: request.action,
      resourceType: request.resource.type,
    };
  }

  private errorFor(kind: FakeFailure): Error {
    switch (kind) {
      case 'unauthenticated':
        return new IamUnauthenticatedError({ code: 'TOKEN_REVOKED', description: 'Token has been revoked' });
      case 'misconfigured':
        return new IamMisconfigurationError('IAM answered 400: resource type is not registered', 400);
      case 'unavailable':
        return new IamUnavailableError('IAM answered 503', 503);
    }
  }
}
