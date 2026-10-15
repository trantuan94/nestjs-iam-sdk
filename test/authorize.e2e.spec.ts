import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { ExpressAdapter } from '@nestjs/platform-express';
import { ExampleAppModule } from '../examples/shared/app.module';
import type { IamAuthzOptions, DecisionEvent } from '../src';
import { FakeIam, iamError } from './fake-iam';

/**
 * The example resource service, booted on Express AND on Fastify, against a
 * fake IAM over real HTTP. Every case runs on both: the request adapter is the
 * one place they differ, and this is what proves it.
 */
const ADAPTERS = [
  ['express', () => new ExpressAdapter()],
  ['fastify', () => new FastifyAdapter()],
] as const;

const TOKEN = 'header.payload.signature';

describe.each(ADAPTERS)('on %s', (_name, adapter) => {
  const iam = new FakeIam();
  let baseUrl: string;
  let app: INestApplication;
  let url: string;
  const events: DecisionEvent[] = [];

  const boot = async (overrides: Partial<IamAuthzOptions> = {}) => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        ExampleAppModule.with({
          baseUrl,
          apiKey: 'iam_test_key',
          timeoutMs: 300,
          global: true,
          onDecision: (e) => events.push(e),
          ...overrides,
        }),
      ],
    }).compile();
    app = moduleRef.createNestApplication(adapter(), { logger: false });
    await app.listen(0, '127.0.0.1');
    url = (await app.getUrl()).replace('[::1]', '127.0.0.1');
  };

  const call = (path: string, init: RequestInit & { token?: string | null } = {}) => {
    const { token = TOKEN, headers, ...rest } = init;
    return fetch(`${url}${path}`, {
      ...rest,
      headers: {
        // Only with a body: Fastify answers 400 to an empty JSON body.
        ...(rest.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(headers as Record<string, string>),
      },
    });
  };

  beforeAll(async () => {
    baseUrl = await iam.start();
  });
  afterAll(() => iam.stop());
  beforeEach(async () => {
    iam.reset();
    events.length = 0;
    await boot();
  });
  afterEach(() => app.close());

  describe('@Authorize', () => {
    it('lets an allowed request through, with the user IAM verified', async () => {
      const res = await call('/invoices/inv-1', { headers: { 'x-tenant': 'ns-acme' } });

      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toEqual({ id: 'inv-1', readBy: 'user-1' });
    });

    it('sends the contract: token, resource from the route, action, and the API key', async () => {
      await call('/invoices/inv-1', { headers: { 'x-tenant': 'ns-acme' } });

      expect(iam.calls).toHaveLength(1);
      const [sent] = iam.calls;
      expect(sent!.path).toBe('/api/iam/auth/authorize');
      expect(sent!.headers['x-api-key']).toBe('iam_test_key');
      expect(sent!.body).toMatchObject({
        token: TOKEN,
        action: 'invoices:read',
        resource: { type: 'invoices', id: 'inv-1', namespaceId: 'ns-acme' },
      });
    });

    it('forwards the end user IP, which the caller cannot override', async () => {
      await call('/invoices/inv-1');

      expect(iam.calls[0]!.body.environment.ip).toMatch(/127\.0\.0\.1/);
    });

    it('leaves out attributes that resolve to nothing', async () => {
      await call('/invoices/inv-1');

      expect(iam.calls[0]!.body.resource).not.toHaveProperty('namespaceId');
    });

    it('reads a resource attribute from the body', async () => {
      await call('/invoices', { method: 'POST', body: JSON.stringify({ amount: 42 }) });

      expect(iam.calls[0]!.body.resource).toEqual({ type: 'invoices', amount: 42 });
    });

    it('answers 403 when IAM says no', async () => {
      iam.answer = (c) => ({
        status: 200,
        body: { allowed: false, userId: 'user-1', action: c.body.action, resourceType: 'invoices' },
      });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(403);
    });

    it('answers 401 without asking IAM when there is no token', async () => {
      const res = await call('/invoices/inv-1', { token: null });

      expect(res.status).toBe(401);
      await expect(res.json()).resolves.toMatchObject({ code: 'MISSING_ACCESS_TOKEN' });
      expect(iam.calls).toHaveLength(0);
    });

    it.each([
      ['TOKEN_REVOKED', 'Token has been revoked'],
      ['INVALID_JWT', 'Invalid or expired token'],
      ['UNAUTHORIZED_EXCEPTION', 'Multiple factors authentication is required'],
    ])('passes a refused token through as 401 %s', async (code, description) => {
      iam.answer = () => ({ status: 401, body: iamError(401, code, description) });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(401);
      await expect(res.json()).resolves.toMatchObject({ code });
    });

    // A bad API key is this service's fault, and must not send the user to sign in again.
    it.each([['Invalid or expired API key'], ['Missing X-API-Key header'], ['User is not active']])(
      'answers 500 when IAM refuses the API key (%s)',
      async (description) => {
        iam.answer = () => ({ status: 401, body: iamError(401, 'UNAUTHORIZED_EXCEPTION', description) });

        const res = await call('/invoices/inv-1');

        expect(res.status).toBe(500);
        await expect(res.json()).resolves.toMatchObject({ code: 'AUTHORIZATION_MISCONFIGURED' });
      },
    );

    it('answers 500 for an unregistered resource type, without leaking its description', async () => {
      iam.answer = () => ({
        status: 400,
        body: iamError(400, 'BAD_REQUEST', "Resource type 'invoices' is not registered"),
      });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(500);
      expect(await res.text()).not.toContain('not registered');
    });

    it('answers 503 with Retry-After when IAM is overloaded', async () => {
      iam.answer = () => ({ status: 429, body: iamError(429, 'TOO_MANY_REQUESTS', 'slow down'), headers: { 'retry-after': '7' } });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(503);
      expect(res.headers.get('retry-after')).toBe('7');
    });

    it('answers 503 when IAM does not answer in time — never lets it through', async () => {
      iam.answer = (c) => ({
        status: 200,
        delayMs: 1000,
        body: { allowed: true, userId: 'user-1', action: c.body.action, resourceType: 'invoices' },
      });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(503);
    });

    it('answers 503 for a 200 that is not a decision', async () => {
      iam.answer = () => ({ status: 200, raw: '<html>proxy error</html>' });

      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(503);
    });

    it('requires every @Authorize on a route, asked in parallel', async () => {
      iam.answer = (c) => ({
        status: 200,
        body: { allowed: c.body.action !== 'emails:send', userId: 'user-1', action: c.body.action, resourceType: c.body.resource.type },
      });

      const res = await call('/invoices/inv-1/send', { method: 'POST' });

      expect(res.status).toBe(403);
      expect(iam.calls.map((c) => c.body.action).sort()).toEqual(['emails:send', 'invoices:read']);
    });

    it('reports every decision to onDecision, without the token', async () => {
      await call('/invoices/inv-1');

      expect(events).toEqual([
        expect.objectContaining({ action: 'invoices:read', resourceType: 'invoices', allowed: true, cached: false }),
      ]);
      expect(JSON.stringify(events)).not.toContain(TOKEN);
    });
  });

  describe('@Authz in the handler', () => {
    it('checks against the loaded record', async () => {
      const res = await call('/invoices/inv-1/approve', { method: 'PATCH' });

      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toEqual({ approved: 'inv-1', by: 'user-1' });
      expect(iam.calls[0]!.body).toMatchObject({
        action: 'invoices:approve',
        resource: { type: 'invoices', id: 'inv-1', namespaceId: 'ns-acme', ownerId: 'user-2', amount: 1500 },
      });
    });

    it('fails closed from the handler too when IAM is unavailable', async () => {
      iam.answer = () => ({ status: 503, body: iamError(503, 'SERVICE_UNAVAILABLE', 'down') });

      const res = await call('/invoices/inv-1/approve', { method: 'PATCH' });

      expect(res.status).toBe(503);
    });

    it('throws 403 from assert() on a denial', async () => {
      iam.answer = (c) => ({
        status: 200,
        body: { allowed: false, userId: 'user-1', action: c.body.action, resourceType: 'invoices' },
      });

      const res = await call('/invoices/inv-1/approve', { method: 'PATCH' });

      expect(res.status).toBe(403);
    });
  });

  describe('global mode (deny by default)', () => {
    it('refuses a route that declares nothing, without asking IAM', async () => {
      const res = await call('/invoices');

      expect(res.status).toBe(403);
      expect(iam.calls).toHaveLength(0);
    });

    it('lets an exempt controller through', async () => {
      const res = await call('/health', { token: null });

      expect(res.status).toBe(200);
    });

    it('leaves an undeclared route open when not global', async () => {
      await app.close();
      await boot({ global: false });

      const res = await call('/invoices');

      expect(res.status).toBe(200);
    });
  });

  describe('decision cache', () => {
    it('is off by default: every request asks IAM', async () => {
      await call('/invoices/inv-1');
      await call('/invoices/inv-1');

      expect(iam.calls).toHaveLength(2);
    });

    it('reuses a decision within its TTL when switched on', async () => {
      await app.close();
      await boot({ cache: { ttlMs: 5_000 } });

      await call('/invoices/inv-1');
      await call('/invoices/inv-1');

      expect(iam.calls).toHaveLength(1);
      expect(events.map((e) => e.cached)).toEqual([false, true]);
    });

    it('never caches a failure', async () => {
      await app.close();
      await boot({ cache: { ttlMs: 5_000 } });
      iam.answer = () => ({ status: 503, body: iamError(503, 'SERVICE_UNAVAILABLE', 'down') });

      await call('/invoices/inv-1');
      iam.reset();
      const res = await call('/invoices/inv-1');

      expect(res.status).toBe(200);
      expect(iam.calls).toHaveLength(1);
    });
  });
});
