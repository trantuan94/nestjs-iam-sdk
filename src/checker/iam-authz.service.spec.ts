import { Logger } from '@nestjs/common';
import { IamMisconfigurationError, IamUnavailableError } from '../client/errors';
import type { AuthorizeRequest } from '../client/contract';
import type { DecisionCache } from '../decision/decision-cache';
import { resolveOptions, type DecisionEvent, type IamAuthzOptions } from '../options';
import { IamAuthz } from './iam-authz.service';

const request = (headers: Record<string, string> = { authorization: 'Bearer tok' }) => ({
  headers,
  params: {},
  query: {},
  ip: '10.0.0.9',
});

const answer = (allowed: boolean) => (r: AuthorizeRequest) =>
  Promise.resolve({ allowed, userId: 'u-1', action: r.action, resourceType: r.resource.type });

const build = (options: Partial<IamAuthzOptions> = {}, authorize: jest.Mock = jest.fn(answer(true))) => {
  const authz = new IamAuthz(resolveOptions({ baseUrl: 'http://iam.test', apiKey: 'k', ...options }), { authorize });
  return { authz, authorize };
};

describe('IamAuthz', () => {
  let logs: jest.SpyInstance[];
  beforeEach(() => {
    logs = [
      jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined),
      jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined),
    ];
  });
  afterEach(() => logs.forEach((l) => l.mockRestore()));

  describe('check()', () => {
    it.each([[true], [false]])('answers %s for a decision', async (allowed) => {
      const { authz } = build({}, jest.fn(answer(allowed)));

      await expect(authz.check(request(), 'invoices:read', { type: 'invoices' })).resolves.toBe(allowed);
    });

    // false is an ANSWER; an outage is not one, and must not read as "not permitted".
    it('still throws when there is no decision', async () => {
      const { authz } = build({}, jest.fn(() => Promise.reject(new IamUnavailableError('down', 503))));

      await expect(authz.check(request(), 'invoices:read', { type: 'invoices' })).rejects.toMatchObject({
        status: 503,
      });
    });
  });

  describe('assert()', () => {
    it('resolves with the decision', async () => {
      const { authz } = build();

      await expect(authz.assert(request(), 'invoices:read', { type: 'invoices' })).resolves.toMatchObject({
        allowed: true,
        userId: 'u-1',
      });
    });

    it('throws 403 on a denial, with a FORBIDDEN body', async () => {
      const { authz } = build({}, jest.fn(answer(false)));

      await expect(authz.assert(request(), 'invoices:read', { type: 'invoices' })).rejects.toMatchObject({
        status: 403,
        response: { code: 'FORBIDDEN', message: 'Not permitted: invoices:read' },
      });
    });

    it('throws 401 without asking IAM when there is no token', async () => {
      const { authz, authorize } = build();

      await expect(authz.assert(request({}), 'invoices:read', { type: 'invoices' })).rejects.toMatchObject({
        status: 401,
      });
      expect(authorize).not.toHaveBeenCalled();
    });

    it('refuses a resource with no type as misconfigured, without asking IAM', async () => {
      const { authz, authorize } = build();

      await expect(authz.assert(request(), 'invoices:read', {} as never)).rejects.toMatchObject({ status: 500 });
      await expect(authz.assert(request(), 'invoices:read', { type: '' })).rejects.toMatchObject({ status: 500 });
      await expect(authz.assert(request(), 'invoices:read', { type: 7 } as never)).rejects.toMatchObject({
        status: 500,
      });
      expect(authorize).not.toHaveBeenCalled();
    });

    it('renders through exceptionFactory when one is given', async () => {
      const exceptionFactory = jest.fn(() => new Error('custom'));
      const { authz } = build({ exceptionFactory }, jest.fn(answer(false)));

      await expect(authz.assert(request(), 'invoices:read', { type: 'invoices' })).rejects.toThrow('custom');
      expect(exceptionFactory).toHaveBeenCalledWith(expect.objectContaining({ kind: 'denied' }));
    });

    it('treats an unexpected error as unavailable, never as a decision', async () => {
      const { authz } = build({}, jest.fn(() => Promise.reject(new TypeError('boom'))));

      await expect(authz.assert(request(), 'invoices:read', { type: 'invoices' })).rejects.toMatchObject({
        status: 503,
      });
    });
  });

  describe('the environment sent', () => {
    it('merges the options, then the call site, and the request IP last', async () => {
      const { authz, authorize } = build({ environment: () => ({ region: 'eu', ip: 'spoofed-by-options' }) });

      await authz.check(request(), 'invoices:read', { type: 'invoices' }, { channel: 'web', ip: 'spoofed-by-call' });

      expect(authorize.mock.calls[0]![0].environment).toEqual({ region: 'eu', channel: 'web', ip: '10.0.0.9' });
    });
  });

  describe('onDecision', () => {
    it('reports a decision', async () => {
      const events: DecisionEvent[] = [];
      const { authz } = build({ onDecision: (e) => events.push(e) });

      await authz.check(request(), 'invoices:read', { type: 'invoices' });

      expect(events).toEqual([
        {
          action: 'invoices:read',
          resourceType: 'invoices',
          allowed: true,
          userId: 'u-1',
          cached: false,
          latencyMs: expect.any(Number),
        },
      ]);
      expect(events[0]!.latencyMs).toBeGreaterThanOrEqual(0);
      expect(events[0]!.latencyMs).toBeLessThan(5_000);
    });

    it('reports a failure as not allowed, not cached, with the error', async () => {
      const events: DecisionEvent[] = [];
      const error = new IamMisconfigurationError('bad key', 401);
      const { authz } = build({ onDecision: (e) => events.push(e) }, jest.fn(() => Promise.reject(error)));

      await authz.check(request(), 'invoices:read', { type: 'invoices' }).catch(() => undefined);

      expect(events).toEqual([expect.objectContaining({ allowed: false, cached: false, error })]);
      expect(events[0]!.latencyMs).toBeLessThan(5_000);
    });

    it('survives a hook that throws', async () => {
      const { authz } = build({
        onDecision: () => {
          throw new Error('metrics down');
        },
      });

      await expect(authz.check(request(), 'invoices:read', { type: 'invoices' })).resolves.toBe(true);
    });
  });

  describe('logging', () => {
    it('logs a misconfiguration as an error, an outage as a warning', async () => {
      const [error, warn] = logs;
      const failing = jest
        .fn()
        .mockRejectedValueOnce(new IamMisconfigurationError('bad key', 401))
        .mockRejectedValueOnce(new IamUnavailableError('down', 503));
      const { authz } = build({}, failing);

      await authz.check(request(), 'invoices:read', { type: 'invoices' }).catch(() => undefined);
      expect(error).toHaveBeenCalledWith(expect.stringContaining('misconfigured: bad key'));
      expect(warn).not.toHaveBeenCalled();

      await authz.check(request(), 'invoices:read', { type: 'invoices' }).catch(() => undefined);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('denied: down'));
    });
  });

  describe('a cache store that fails', () => {
    const failingStore = (fail: 'get' | 'set'): DecisionCache => ({
      get: () => (fail === 'get' ? Promise.reject(new Error('redis down')) : undefined),
      set: () => (fail === 'set' ? Promise.reject(new Error('redis down')) : undefined),
    });

    it.each([['get'], ['set']] as const)('on %s is a miss, not a refusal', async (fail) => {
      const { authz, authorize } = build({ cache: { ttlMs: 1_000, store: failingStore(fail) } });

      await expect(authz.check(request(), 'invoices:read', { type: 'invoices' })).resolves.toBe(true);
      expect(authorize).toHaveBeenCalledTimes(1);
    });

    it('reports a hit as cached', async () => {
      const events: DecisionEvent[] = [];
      const { authz, authorize } = build({ cache: { ttlMs: 1_000 }, onDecision: (e) => events.push(e) });

      await authz.check(request(), 'invoices:read', { type: 'invoices' });
      await authz.check(request(), 'invoices:read', { type: 'invoices' });

      expect(authorize).toHaveBeenCalledTimes(1);
      expect(events.map((e) => e.cached)).toEqual([false, true]);
    });
  });
});
