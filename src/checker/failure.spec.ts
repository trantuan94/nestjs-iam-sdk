import { IamUnauthenticatedError, IamUnavailableError } from '../client/errors';
import { defaultException, retryAfterOf } from './failure';

const decision = { allowed: false, userId: 'u', action: 'invoices:read', resourceType: 'invoices' };

describe('defaultException', () => {
  it.each([
    [{ kind: 'missing-token' as const }, 401, 'MISSING_ACCESS_TOKEN'],
    [{ kind: 'unauthenticated' as const, error: new IamUnauthenticatedError({ code: 'TOKEN_REVOKED', description: 'revoked' }) }, 401, 'TOKEN_REVOKED'],
    [{ kind: 'unauthenticated' as const, error: new IamUnauthenticatedError({}) }, 401, 'UNAUTHORIZED'],
    [{ kind: 'denied' as const, decision }, 403, 'FORBIDDEN'],
    [{ kind: 'undeclared-route' as const }, 403, 'FORBIDDEN'],
    [{ kind: 'misconfigured' as const, error: new IamUnavailableError('x') }, 500, 'AUTHORIZATION_MISCONFIGURED'],
    [{ kind: 'unavailable' as const, error: new IamUnavailableError('x') }, 503, 'AUTHORIZATION_UNAVAILABLE'],
  ])('%j → %i %s', (failure, status, code) => {
    const exception = defaultException(failure);

    expect(exception.getStatus()).toBe(status);
    expect(exception.getResponse()).toMatchObject({ statusCode: status, code, message: expect.any(String) });
    expect((exception.getResponse() as { message: string }).message).not.toBe('');
  });

  it('carries the retry hint only when IAM gave one', () => {
    expect(
      defaultException({ kind: 'unavailable', error: new IamUnavailableError('x', 429, 7) }).getResponse(),
    ).toMatchObject({ retryAfterSeconds: 7 });
    expect(
      defaultException({ kind: 'unavailable', error: new IamUnavailableError('x', 503) }).getResponse(),
    ).not.toHaveProperty('retryAfterSeconds');
  });

  it('names the action on a denial, never the resource or the user', () => {
    expect(defaultException({ kind: 'denied', decision }).getResponse()).toEqual({
      statusCode: 403,
      code: 'FORBIDDEN',
      message: 'Not permitted: invoices:read',
    });
  });
});

describe('retryAfterOf', () => {
  it('reads it from an unavailable failure only', () => {
    const error = new IamUnavailableError('x', 429, 3);

    expect(retryAfterOf({ kind: 'unavailable', error })).toBe(3);
    expect(retryAfterOf({ kind: 'misconfigured', error })).toBeUndefined();
    expect(retryAfterOf({ kind: 'unavailable', error: new IamUnauthenticatedError({}) })).toBeUndefined();
  });
});
