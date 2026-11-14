import { FakeIam, iamError } from '../../test/fake-iam';
import { resolveOptions } from '../options';
import {
  IamMisconfigurationError,
  IamPermissionDeniedError,
  IamUnavailableError,
} from '../client/errors';
import { IamServiceClient } from './iam-service.client';

const ACCOUNT = {
  id: '0190c2d4-7f3a-7b1e-9c2d-4e5f6a7b8c9d',
  identifier: 'ada',
  status: 'ACTIVE',
  isVerified: true,
  createdAt: '2026-01-02T03:04:05.000Z',
};
const ROLE = { id: 'r-1', code: 'editor', name: 'Editor' };
const PAGE = { total: 1, page: 1, limit: 20, totalPages: 1, hasNext: false, hasPrev: false };

describe('IamServiceClient', () => {
  const iam = new FakeIam();
  let client: IamServiceClient;

  beforeAll(async () => {
    const baseUrl = await iam.start();
    client = new IamServiceClient(resolveOptions({ baseUrl, apiKey: 'iam_secret_value', timeoutMs: 200 }));
  });
  afterAll(() => iam.stop());
  beforeEach(() => iam.reset());

  const answer = (status: number, body: unknown) => {
    iam.answer = () => ({ status, body });
  };

  describe('requests', () => {
    it.each<[string, () => Promise<unknown>, string, string, unknown]>([
      ['introspectToken', () => client.introspectToken('tok'), 'POST', '/api/iam/service/tokens/introspect', { token: 'tok' }],
      ['getAccount', () => client.getAccount('u 1'), 'GET', '/api/iam/service/accounts/u%201', ''],
      ['getContact', () => client.getContact('ada'), 'POST', '/api/iam/service/accounts/contact', { identifier: 'ada' }],
      ['getContactById', () => client.getContactById('u1'), 'GET', '/api/iam/service/accounts/u1/contact', ''],
      ['getAccountRoles', () => client.getAccountRoles('u1'), 'GET', '/api/iam/service/accounts/u1/roles', ''],
      ['getAccountPermissions', () => client.getAccountPermissions('u1'), 'GET', '/api/iam/service/accounts/u1/permissions', ''],
      ['listRoles', () => client.listRoles({ page: 2, searchKey: 'ed' }), 'GET', '/api/iam/service/roles?page=2&searchKey=ed', ''],
      ['listResourceTypes', () => client.listResourceTypes(), 'GET', '/api/iam/service/resource-types', ''],
    ])('%s calls %s %s with the API key', async (_, call, method, path, body) => {
      answer(500, iamError(500, 'INTERNAL_SERVER_ERROR', 'x'));

      await call().catch(() => undefined);

      expect(iam.calls).toHaveLength(1);
      expect(iam.calls[0]).toMatchObject({ method, path, body });
      expect(iam.calls[0]!.headers['x-api-key']).toBe('iam_secret_value');
    });
  });

  describe('transport', () => {
    it('leaves an unset query value out, and sends no query when none is set', async () => {
      answer(500, iamError(500, 'INTERNAL_SERVER_ERROR', 'x'));

      await client.listRoles({ page: undefined, searchKey: 'ed' }).catch(() => undefined);
      await client.listRoles({}).catch(() => undefined);

      expect(iam.calls.map((c) => c.path)).toEqual(['/api/iam/service/roles?searchKey=ed', '/api/iam/service/roles']);
    });

    it('declares a JSON body only when it sends one', async () => {
      answer(500, iamError(500, 'INTERNAL_SERVER_ERROR', 'x'));

      await client.getAccount('u1').catch(() => undefined);
      await client.getContact('ada').catch(() => undefined);

      expect(iam.calls[0]!.headers['content-type']).toBeUndefined();
      expect(iam.calls[1]!.headers['content-type']).toBe('application/json');
      expect(iam.calls.every((c) => c.headers['accept'] === 'application/json')).toBe(true);
    });

    it.each<[string, string, number | undefined]>([
      ['seconds', '7', 7],
      ['fractional seconds, rounded up', '1.2', 2],
      ['an HTTP date in the past, as zero', new Date(Date.now() - 60_000).toUTCString(), 0],
      ['garbage, as unknown', 'soon', undefined],
    ])('reads Retry-After as %s', async (_, header, seconds) => {
      iam.answer = () => ({ status: 503, body: iamError(503, 'SERVICE_UNAVAILABLE', 'x'), headers: { 'retry-after': header } });

      const error = (await client.listRoles().catch((e: unknown) => e)) as IamUnavailableError;

      expect(error.retryAfterSeconds).toBe(seconds);
    });

    it('reads a future HTTP date as the seconds until it', async () => {
      const at = new Date(Date.now() + 30_000).toUTCString();
      iam.answer = () => ({ status: 503, body: iamError(503, 'SERVICE_UNAVAILABLE', 'x'), headers: { 'retry-after': at } });

      const error = (await client.listRoles().catch((e: unknown) => e)) as IamUnavailableError;

      expect(error.retryAfterSeconds).toBeGreaterThan(25);
      expect(error.retryAfterSeconds).toBeLessThanOrEqual(31);
    });

    it('treats a non-JSON error body as an envelope with nothing in it', async () => {
      iam.answer = () => ({ status: 400, raw: '<html>bad gateway</html>' });

      const error = await client.listRoles().catch((e: unknown) => e);

      expect(error).toBeInstanceOf(IamMisconfigurationError);
      expect(error).toMatchObject({ message: 'IAM answered 400', code: undefined });
    });

    it('treats an unreachable service as unavailable', async () => {
      const dead = new IamServiceClient(resolveOptions({ baseUrl: 'http://127.0.0.1:1/api/iam', apiKey: 'k' }));

      await expect(dead.getAccount('u1')).rejects.toThrow(/IAM could not be reached/);
    });
  });

  describe('answers', () => {
    it('reads an account, naming its five fields', async () => {
      answer(200, { ...ACCOUNT, password: 'hash' });

      await expect(client.getAccount(ACCOUNT.id)).resolves.toEqual(ACCOUNT);
    });

    it('reads an introspection, active or not', async () => {
      const active = { active: true, sub: 'u1', identifier: 'ada', sessionId: null, mfaCleared: true, exp: 1 };
      answer(200, { ...active, extra: 'x' });
      await expect(client.introspectToken('t')).resolves.toEqual(active);

      answer(200, { active: false, sub: 'leak' });
      await expect(client.introspectToken('t')).resolves.toEqual({ active: false });
    });

    it('reads a contact, roles, permissions and pages', async () => {
      answer(200, { email: null, firstName: 'Ada', lastName: null });
      await expect(client.getContact('ada')).resolves.toEqual({ email: null, firstName: 'Ada', lastName: null });

      answer(200, { roles: [ROLE] });
      await expect(client.getAccountRoles('u1')).resolves.toEqual([ROLE]);

      answer(200, { permissions: ['a:read', 'b:write'] });
      await expect(client.getAccountPermissions('u1')).resolves.toEqual(['a:read', 'b:write']);

      answer(200, { ...PAGE, data: [ROLE] });
      await expect(client.listRoles()).resolves.toEqual({ ...PAGE, data: [ROLE] });

      const type = { id: 't1', code: 'products', name: 'Products', description: null, allowedActions: ['read'] };
      answer(200, { ...PAGE, data: [type] });
      await expect(client.listResourceTypes()).resolves.toEqual({ ...PAGE, data: [type] });
    });

    it.each<[string, () => Promise<unknown>, unknown]>([
      ['an account missing a field', () => client.getAccount('u1'), { ...ACCOUNT, isVerified: 'yes' }],
      ['an introspection with no sub', () => client.introspectToken('t'), { active: true, identifier: 'a' }],
      ['roles that are not a list', () => client.getAccountRoles('u1'), { roles: ROLE }],
      ['a page with no total', () => client.listRoles(), { data: [] }],
      ['nothing', () => client.getContact('a'), null],
    ])('refuses a 200 that is %s as unavailable', async (_, call, body) => {
      answer(200, body);

      await expect(call()).rejects.toBeInstanceOf(IamUnavailableError);
    });
  });

  // Every field of every shape, one at a time: a 200 missing it, or carrying
  // the wrong type, is not the contract. A shape check that skipped a field
  // would let a body through that the caller then trusts.
  describe('shape checks, field by field', () => {
    const ACTIVE = { active: true, sub: 'u1', identifier: 'ada', sessionId: 's1', mfaCleared: true, exp: 1 };
    const TYPE = { id: 't1', code: 'products', name: 'Products', description: 'd', allowedActions: ['read'] };
    const CONTACT = { email: 'a@x.io', firstName: 'A', lastName: 'L' };
    const cases: [string, () => Promise<unknown>, (body: unknown) => unknown, Record<string, unknown>][] = [
      ['getAccount', () => client.getAccount('u1'), (b) => b, ACCOUNT],
      ['introspectToken', () => client.introspectToken('t'), (b) => b, ACTIVE],
      ['getContact', () => client.getContact('a'), (b) => b, CONTACT],
      ['getAccountRoles', () => client.getAccountRoles('u1'), (b) => ({ roles: [b] }), ROLE],
      ['lookupAccounts', () => client.lookupAccounts(['a']), (b) => ({ accounts: [b] }), ACCOUNT],
      ['listRoles', () => client.listRoles(), (b) => ({ ...PAGE, data: [b] }), ROLE],
      ['listResourceTypes', () => client.listResourceTypes(), (b) => ({ ...PAGE, data: [b] }), TYPE],
      ['listRoles (page)', () => client.listRoles(), (b) => ({ ...(b as object), data: [ROLE] }), PAGE],
    ];
    const WRONG: Record<string, unknown> = { string: 42, number: 'x', boolean: 'yes', object: 'x' };

    it.each(cases.flatMap(([name, call, wrap, valid]) =>
      Object.entries(valid).flatMap(([key, value]) => {
        const without = Object.fromEntries(Object.entries(valid).filter(([k]) => k !== key));
        const kind = Array.isArray(value) ? 'object' : value === null ? 'object' : typeof value;
        return [
          [`${name}: ${key} missing`, call, wrap(without)],
          [`${name}: ${key} as ${typeof WRONG[kind]}`, call, wrap({ ...valid, [key]: WRONG[kind] })],
        ] as [string, () => Promise<unknown>, unknown][];
      }),
    ))('refuses %s', async (_, call, body) => {
      answer(200, body);

      await expect(call()).rejects.toBeInstanceOf(IamUnavailableError);
    });

    it.each(cases.map(([name, call, wrap, valid]) => [name, call, wrap(valid)] as const))(
      'accepts the valid %s body the table above breaks',
      async (_, call, body) => {
        answer(200, body);

        await expect(call()).resolves.toBeDefined();
      },
    );

    it.each<[string, unknown]>([
      ['an array for an object', [ACCOUNT]],
      ['a non-string in allowedActions', { ...PAGE, data: [{ ...TYPE, allowedActions: [1] }] }],
      ['a non-string permission', { permissions: ['a', 1] }],
    ])('refuses %s', async (name, body) => {
      answer(200, body);
      const call = name.includes('allowedActions')
        ? client.listResourceTypes()
        : name.includes('permission')
          ? client.getAccountPermissions('u1')
          : client.getAccount('u1');

      await expect(call).rejects.toBeInstanceOf(IamUnavailableError);
    });

    it('accepts null where the contract allows it', async () => {
      answer(200, { ...ACTIVE, sessionId: null });
      await expect(client.introspectToken('t')).resolves.toMatchObject({ sessionId: null });

      answer(200, { email: null, firstName: null, lastName: null });
      await expect(client.getContact('a')).resolves.toEqual({ email: null, firstName: null, lastName: null });

      answer(200, { ...PAGE, data: [{ ...TYPE, description: null }] });
      await expect(client.listResourceTypes()).resolves.toMatchObject({ data: [{ description: null }] });
    });
  });

  describe('a by-id miss', () => {
    it.each<[string, () => Promise<unknown>]>([
      ['getAccount', () => client.getAccount('u1')],
      ['getContactById', () => client.getContactById('u1')],
      ['getAccountRoles', () => client.getAccountRoles('u1')],
      ['getAccountPermissions', () => client.getAccountPermissions('u1')],
    ])('%s answers null for ACCOUNT_NOT_FOUND', async (_, call) => {
      answer(404, iamError(404, 'ACCOUNT_NOT_FOUND', "No such account in this API key's project"));

      await expect(call()).resolves.toBeNull();
    });

    it('treats a 404 NOT_FOUND — an unknown route — as misconfiguration, not a miss', async () => {
      answer(404, iamError(404, 'NOT_FOUND', 'Cannot GET /service/accounts/u1'));

      await expect(client.getAccount('u1')).rejects.toBeInstanceOf(IamMisconfigurationError);
    });
  });

  describe('refusals', () => {
    it('names the missing permission on API_KEY_PERMISSION_DENIED', async () => {
      answer(403, iamError(403, 'API_KEY_PERMISSION_DENIED', 'x'));

      const error = await client.getAccountRoles('u1').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(IamPermissionDeniedError);
      expect(error).toBeInstanceOf(IamMisconfigurationError);
      expect(error).toMatchObject({ permission: 'roles:read', status: 403, code: 'API_KEY_PERMISSION_DENIED' });
    });

    it.each([
      [401, 'UNAUTHORIZED_EXCEPTION', IamMisconfigurationError],
      [400, 'VALIDATION_EXCEPTION', IamMisconfigurationError],
      [403, 'FORBIDDEN', IamMisconfigurationError],
      [429, 'RATE_LIMITED', IamUnavailableError],
      [500, 'INTERNAL_SERVER_ERROR', IamUnavailableError],
      [503, 'SERVICE_UNAVAILABLE', IamUnavailableError],
    ])('maps %i %s', async (status, code, type) => {
      answer(status, iamError(status, code, 'x'));

      const error = await client.listRoles().catch((e: unknown) => e);

      expect(error).toBeInstanceOf(type);
      expect(error).not.toBeInstanceOf(IamPermissionDeniedError);
    });

    it('keeps Retry-After on a 429', async () => {
      iam.answer = () => ({ status: 429, body: iamError(429, 'RATE_LIMITED', 'x'), headers: { 'retry-after': '7' } });

      await expect(client.listRoles()).rejects.toMatchObject({ retryAfterSeconds: 7 });
    });

    it('times out as unavailable', async () => {
      iam.answer = () => ({ status: 200, delayMs: 1000, body: {} });

      await expect(client.getAccount('u1')).rejects.toThrow(/did not answer within 200ms/);
    });
  });

  describe('revokeSessions', () => {
    it('POSTs to the account, answers true on 204, and sends no body', async () => {
      iam.answer = () => ({ status: 204 });

      await expect(client.revokeSessions('u 1')).resolves.toBe(true);
      expect(iam.calls[0]).toMatchObject({
        method: 'POST',
        path: '/api/iam/service/accounts/u%201/sessions/revoke',
        body: '',
      });
      expect(iam.calls[0]!.headers['content-type']).toBeUndefined();
    });

    it('answers false for ACCOUNT_NOT_FOUND, and misconfiguration for any other 404', async () => {
      answer(404, iamError(404, 'ACCOUNT_NOT_FOUND', 'x'));
      await expect(client.revokeSessions('u1')).resolves.toBe(false);

      answer(404, iamError(404, 'NOT_FOUND', 'Cannot POST'));
      await expect(client.revokeSessions('u1')).rejects.toBeInstanceOf(IamMisconfigurationError);
    });

    it('names sessions:revoke when the key is not granted it', async () => {
      answer(403, iamError(403, 'API_KEY_PERMISSION_DENIED', 'x'));

      await expect(client.revokeSessions('u1')).rejects.toMatchObject({ permission: 'sessions:revoke' });
    });

    it.each([[200], [500], [503]])('does not take %i for done', async (status) => {
      answer(status, status === 200 ? {} : iamError(status, 'X', 'x'));

      await expect(client.revokeSessions('u1')).rejects.toBeInstanceOf(
        status === 200 ? IamMisconfigurationError : IamUnavailableError,
      );
    });
  });

  describe('lookupAccounts', () => {
    it('sends nothing for no identifiers', async () => {
      await expect(client.lookupAccounts([])).resolves.toEqual([]);
      expect(iam.calls).toHaveLength(0);
    });

    it('sends at most 100 identifiers a call, in order, and joins the answers', async () => {
      const identifiers = Array.from({ length: 250 }, (_, i) => `user-${i}`);
      iam.answer = (call) => ({
        status: 200,
        body: { accounts: [{ ...ACCOUNT, identifier: (call.body as { identifiers: string[] }).identifiers[0] }] },
      });

      const found = await client.lookupAccounts(identifiers);

      expect(iam.calls.map((c) => (c.body as { identifiers: string[] }).identifiers.length)).toEqual([100, 100, 50]);
      expect(found.map((a) => a.identifier)).toEqual(['user-0', 'user-100', 'user-200']);
    });
  });

  describe('syncResourceTypes', () => {
    const PRODUCTS = { code: 'products', name: 'Products', allowedActions: ['read', 'create'] };
    const RESULT = {
      code: 'products',
      outcome: 'created',
      addedActions: ['read', 'create'],
      removedActions: [],
      undeclaredActions: [],
      fieldsChanged: [],
    };

    it('PUTs the manifest, without prune or dryRun unless asked, and answers the results', async () => {
      answer(200, { dryRun: false, prune: false, results: [RESULT] });

      await expect(client.syncResourceTypes([PRODUCTS])).resolves.toEqual({
        dryRun: false,
        prune: false,
        results: [RESULT],
      });
      expect(iam.calls[0]).toMatchObject({
        method: 'PUT',
        path: '/api/iam/service/resource-types',
        body: { resourceTypes: [PRODUCTS] },
      });
      expect(iam.calls[0]!.headers['x-api-key']).toBe('iam_secret_value');
    });

    it('sends prune in the body and dryRun in the query', async () => {
      answer(200, { dryRun: true, prune: true, results: [] });

      await client.syncResourceTypes([], { prune: true, dryRun: true });

      expect(iam.calls[0]).toMatchObject({
        path: '/api/iam/service/resource-types?dryRun=true',
        body: { resourceTypes: [], prune: true },
      });
    });

    it('names resource-types:sync when the key is not granted it', async () => {
      answer(403, iamError(403, 'API_KEY_PERMISSION_DENIED', 'x'));

      const failure = client.syncResourceTypes([PRODUCTS]);

      await expect(failure).rejects.toBeInstanceOf(IamPermissionDeniedError);
      await expect(failure).rejects.toMatchObject({ permission: 'resource-types:sync' });
    });

    it.each<[string, unknown]>([
      ['no results', { dryRun: false, prune: false }],
      ['an outcome it does not know', { dryRun: false, prune: false, results: [{ ...RESULT, outcome: 'merged' }] }],
      ['a field it does not know', { dryRun: false, prune: false, results: [{ ...RESULT, fieldsChanged: ['code'] }] }],
    ])('does not take a 200 with %s for an answer', async (_, body) => {
      answer(200, body);

      await expect(client.syncResourceTypes([PRODUCTS])).rejects.toBeInstanceOf(IamUnavailableError);
    });

    it('answers a refused manifest (400) as misconfiguration, and a 503 as unavailable', async () => {
      answer(400, iamError(400, 'VALIDATION_EXCEPTION', 'code is reserved by the platform'));
      await expect(client.syncResourceTypes([PRODUCTS])).rejects.toBeInstanceOf(IamMisconfigurationError);

      answer(503, iamError(503, 'X', 'x'));
      await expect(client.syncResourceTypes([PRODUCTS])).rejects.toBeInstanceOf(IamUnavailableError);
    });

    it('refuses more than 100 types before sending anything', async () => {
      const many = Array.from({ length: 101 }, (_, i) => ({ ...PRODUCTS, code: `t${i}` }));

      await expect(client.syncResourceTypes(many)).rejects.toBeInstanceOf(RangeError);
      expect(iam.calls).toHaveLength(0);
    });
  });
});
