import {
  ForbiddenException,
  type HttpException,
  InternalServerErrorException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { IamUnavailableError } from '../client/errors';
import type { AuthzFailure } from '../options';

/**
 * The default answer for each failure. Bodies are deliberately thin: the
 * resource service's own exception filter shapes them, and nothing about the
 * IAM call (a description naming a resource type, the key's state) leaks to
 * the end user — except the IAM code on a 401, which tells a client whether to
 * sign in again or complete MFA.
 */
export const defaultException = (failure: AuthzFailure): HttpException => {
  switch (failure.kind) {
    case 'missing-token':
      return new UnauthorizedException({
        statusCode: 401,
        code: 'MISSING_ACCESS_TOKEN',
        message: 'An access token is required',
      });
    case 'unauthenticated':
      return new UnauthorizedException({
        statusCode: 401,
        code: failure.error.code ?? 'UNAUTHORIZED',
        message: failure.error.message,
      });
    case 'denied':
      return new ForbiddenException({
        statusCode: 403,
        code: 'FORBIDDEN',
        message: `Not permitted: ${failure.decision.action}`,
      });
    case 'undeclared-route':
      return new ForbiddenException({
        statusCode: 403,
        code: 'FORBIDDEN',
        message: 'This route declares no authorization',
      });
    case 'misconfigured':
      return new InternalServerErrorException({
        statusCode: 500,
        code: 'AUTHORIZATION_MISCONFIGURED',
        message: 'Authorization is misconfigured',
      });
    case 'unavailable':
      return new ServiceUnavailableException({
        statusCode: 503,
        code: 'AUTHORIZATION_UNAVAILABLE',
        message: 'Authorization is temporarily unavailable',
        ...(failure.error instanceof IamUnavailableError &&
        failure.error.retryAfterSeconds !== undefined
          ? { retryAfterSeconds: failure.error.retryAfterSeconds }
          : {}),
      });
  }
};

/** Thrown internally so the guard and `@Authz()` can render a failure the same way. */
export class AuthzFailureSignal extends Error {
  constructor(readonly failure: AuthzFailure) {
    super(failure.kind);
    this.name = 'AuthzFailureSignal';
  }
}

export const retryAfterOf = (failure: AuthzFailure): number | undefined =>
  failure.kind === 'unavailable' && failure.error instanceof IamUnavailableError
    ? failure.error.retryAfterSeconds
    : undefined;
