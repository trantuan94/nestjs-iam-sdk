import { FakeIam, iamError } from '../../test/fake-iam';
import { resolveOptions } from '../options';
import { IamAuthzClient, isTokenRefusal } from './iam-authz.client';
import { IamMisconfigurationError, IamUnauthenticatedError, IamUnavailableError } from './errors';

const REQUEST = { token: 't', action: 'invoices:read', resource: { type: 'invoices' } };

describe('IamAuthzClient', () => {
  const iam = new FakeIam();
  let client: IamAuthzClient;

  beforeAll(async () => {
    const baseUrl = await iam.start();
    client = new IamAuthzClient(resolveOptions({ baseUrl, apiKey: 'iam_secret_value', timeoutMs: 200 }));
  });
  afterAll(() => iam.stop());
  beforeEach(() => iam.reset());

  it('resolves with exactly the four decision fields', async () => {
    iam.answer = () => ({
      status: 200,
      body: { allowed: true, userId: 'u', action: 'invoices:read', resourceType: 'invoices', extra: 'x' },
    });

    await expect(client.authorize(REQUEST)).resolves.toEqual({
      allowed: true,
      userId: 'u',
      action: 'invoices:read',
      resourceType: 'invoices',
    });
  });

  it.each([
    [{ allowed: 'yes', userId: 'u', action: 'a:b', resourceType: 'a' }],
    [{ allowed: true, action: 'a:b', resourceType: 'a' }],
    [{ allowed: true, userId: 'u', resourceType: 'a' }],
    [{ allowed: true, userId: 'u', action: 'a:b' }],
    [null],
  ])('refuses a 200 that is not a decision (%j)', async (body) => {
    iam.answer = () => ({ status: 200, body });

    await expect(client.authorize(REQUEST)).rejects.toBeInstanceOf(IamUnavailableError);
  });

  it.each([
    [400, 'BAD_REQUEST', IamMisconfigurationError],
    [400, 'VALIDATION_EXCEPTION', IamMisconfigurationError],
    [403, 'FORBIDDEN', IamMisconfigurationError],
    [404, 'NOT_FOUND', IamMisconfigurationError],
    [429, 'TOO_MANY_REQUESTS', IamUnavailableError],
    [500, 'INTERNAL_SERVER_ERROR', IamUnavailableError],
    [502, 'BAD_GATEWAY', IamUnavailableError],
  ])('maps %i %s', async (status, code, type) => {
    iam.answer = () => ({ status, body: iamError(status, code, 'x') });

    await expect(client.authorize(REQUEST)).rejects.toBeInstanceOf(type);
  });

  it('keeps the service code and request id on a refused token', async () => {
    iam.answer = () => ({ status: 401, body: iamError(401, 'TOKEN_REVOKED', 'Token has been revoked') });

    const error = await client.authorize(REQUEST).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(IamUnauthenticatedError);
    expect(error).toMatchObject({ code: 'TOKEN_REVOKED', requestId: expect.any(String) });
  });

  it('times out as unavailable', async () => {
    iam.answer = () => ({ status: 200, delayMs: 1000, body: {} });

    await expect(client.authorize(REQUEST)).rejects.toThrow(/did not answer within 200ms/);
  });

  it('treats an unreachable service as unavailable', async () => {
    const dead = new IamAuthzClient(resolveOptions({ baseUrl: 'http://127.0.0.1:1/api/iam', apiKey: 'k' }));

    await expect(dead.authorize(REQUEST)).rejects.toThrow(/IAM could not be reached/);
  });

  it.each([
    ['7', 7],
    ['0', 0],
    ['1.2', 2],
    ['soon', undefined],
  ])('reads Retry-After %s', async (header, seconds) => {
    iam.answer = () => ({ status: 503, body: {}, headers: { 'retry-after': header } });

    const error = (await client.authorize(REQUEST).catch((e: unknown) => e)) as IamUnavailableError;

    expect(error.retryAfterSeconds).toBe(seconds);
  });

  it('reads an HTTP-date Retry-After', async () => {
    const at = new Date(Date.now() + 30_000).toUTCString();
    iam.answer = () => ({ status: 503, body: {}, headers: { 'retry-after': at } });

    const error = (await client.authorize(REQUEST).catch((e: unknown) => e)) as IamUnavailableError;

    expect(error.retryAfterSeconds).toBeGreaterThan(25);
    expect(error.retryAfterSeconds).toBeLessThanOrEqual(31);
  });

  it('never puts the API key in an error', async () => {
    iam.answer = () => ({ status: 401, body: iamError(401, 'UNAUTHORIZED_EXCEPTION', 'Invalid or expired API key') });

    const error = (await client.authorize(REQUEST).catch((e: unknown) => e)) as Error;

    expect(`${error.message} ${JSON.stringify(error)}`).not.toContain('iam_secret_value');
  });

  // The fake parses any body; the real service (Fastify) refuses a body without
  // its content type, which only this assertion would notice going missing.
  it('sends JSON, declared as JSON, with the API key', async () => {
    await client.authorize(REQUEST);

    const [call] = iam.calls;
    expect(call!.headers['content-type']).toBe('application/json');
    expect(call!.headers['accept']).toBe('application/json');
    expect(call!.headers['x-api-key']).toBe('iam_secret_value');
    expect(call!.body).toEqual(REQUEST);
  });

  it('sends one attempt, never retrying', async () => {
    iam.answer = () => ({ status: 503, body: {} });

    await client.authorize(REQUEST).catch(() => undefined);

    expect(iam.calls).toHaveLength(1);
  });
});

/**
 * The line between "the user's token was refused" (401 to the user) and "this
 * service's API key was" (500, loud). Both are `UNAUTHORIZED_EXCEPTION`, and an
 * unknown 401 must land on the loud side.
 */
describe('isTokenRefusal', () => {
  it.each([
    [{ code: 'INVALID_JWT' }, true],
    [{ code: 'TOKEN_REVOKED' }, true],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'Multiple factors authentication is required' }, true],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'Namespace not found' }, true],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'Invalid or expired API key' }, false],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'Missing X-API-Key header' }, false],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'User is not active' }, false],
    [{ code: 'UNAUTHORIZED_EXCEPTION', description: 'something new' }, false],
    // The descriptions count only under UNAUTHORIZED_EXCEPTION.
    [{ code: 'BAD_REQUEST', description: 'Namespace not found' }, false],
    [{ description: 'Multiple factors authentication is required' }, false],
    [{}, false],
  ])('%j → %s', (body, expected) => {
    expect(isTokenRefusal(body)).toBe(expected);
  });
});
