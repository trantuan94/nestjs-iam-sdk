import { Test } from '@nestjs/testing';
import { IamPermissionDeniedError, IamUnavailableError } from '../client/errors';
import { IamServiceClient } from '../service/iam-service.client';
import { FakeIamServiceClient } from './fake-iam-service.client';
import { IamAuthzTestingModule } from './iam-authz-testing.module';

const DATA = {
  accounts: [
    {
      id: 'u1',
      identifier: 'Ada',
      contact: { email: 'ada@example.com', firstName: 'Ada' },
      roles: ['editor'],
      permissions: ['b:write', 'a:read'],
    },
    { id: 'u2', identifier: 'blocked', status: 'BLOCKED', contact: { email: 'b@example.com' } },
    { id: 'u3', identifier: 'Twin' },
    { id: 'u4', identifier: 'twin' },
  ],
  roles: [
    { id: 'r1', code: 'editor', name: 'Editor' },
    { id: 'r2', code: 'viewer', name: 'Viewer' },
  ],
  tokens: {
    good: { active: true as const, sub: 'u1', identifier: 'Ada', sessionId: 's1', mfaCleared: true, exp: 1 },
  },
};

describe('FakeIamServiceClient', () => {
  let fake: FakeIamServiceClient;

  beforeEach(() => {
    fake = new FakeIamServiceClient(DATA);
  });

  it('answers accounts by id, null for an unknown one', async () => {
    await expect(fake.getAccount('u1')).resolves.toMatchObject({ id: 'u1', identifier: 'Ada', status: 'ACTIVE' });
    await expect(fake.getAccount('nobody')).resolves.toBeNull();
  });

  it('looks up ignoring case, and drops an identifier shared by case alone', async () => {
    const found = await fake.lookupAccounts(['ada', 'TWIN', 'nobody']);

    expect(found.map((a) => a.id)).toEqual(['u1']);
  });

  it('answers contact as IAM does: no address for a blocked account', async () => {
    await expect(fake.getContact('ADA')).resolves.toEqual({
      email: 'ada@example.com',
      firstName: 'Ada',
      lastName: null,
    });
    await expect(fake.getContactById('u2')).resolves.toEqual({ email: null, firstName: null, lastName: null });
    await expect(fake.getContactById('nobody')).resolves.toBeNull();
  });

  it('answers roles and sorted permissions of an account', async () => {
    await expect(fake.getAccountRoles('u1')).resolves.toEqual([{ id: 'r1', code: 'editor', name: 'Editor' }]);
    await expect(fake.getAccountPermissions('u1')).resolves.toEqual(['a:read', 'b:write']);
  });

  it('pages and searches a listing', async () => {
    await expect(fake.listRoles({ searchKey: 'VIEW' })).resolves.toMatchObject({
      data: [{ code: 'viewer' }],
      total: 1,
    });
    await expect(fake.listRoles({ limit: 1, page: 2 })).resolves.toMatchObject({
      data: [{ code: 'viewer' }],
      total: 2,
      totalPages: 2,
      hasPrev: true,
      hasNext: false,
    });
  });

  it('introspects a listed token, and nothing else', async () => {
    await expect(fake.introspectToken('good')).resolves.toMatchObject({ active: true, sub: 'u1' });
    await expect(fake.introspectToken('other')).resolves.toEqual({ active: false });
  });

  it('signs a known account out, recording it, and answers false for an unknown one', async () => {
    await expect(fake.revokeSessions('u1')).resolves.toBe(true);
    await expect(fake.revokeSessions('nobody')).resolves.toBe(false);

    expect(fake.revokedSessions).toEqual(['u1']);
  });

  describe('syncResourceTypes', () => {
    const ORDERS = { code: 'orders', name: 'Orders', allowedActions: ['read'] };

    it('creates, then adds actions, then reports nothing to do — and lists the result', async () => {
      await expect(fake.syncResourceTypes([ORDERS])).resolves.toMatchObject({
        results: [{ code: 'orders', outcome: 'created', addedActions: ['read'] }],
      });
      await expect(fake.syncResourceTypes([{ ...ORDERS, allowedActions: ['read', 'create'] }])).resolves.toMatchObject({
        results: [{ outcome: 'updated', addedActions: ['create'] }],
      });
      await expect(fake.syncResourceTypes([{ ...ORDERS, allowedActions: ['create'] }])).resolves.toMatchObject({
        results: [{ outcome: 'unchanged', undeclaredActions: ['read'] }],
      });

      expect(fake.syncedResourceTypes).toHaveLength(3);
      await expect(fake.listResourceTypes()).resolves.toMatchObject({
        data: [{ code: 'orders', allowedActions: ['read', 'create'] }],
      });
    });

    it('reports a type the manifest leaves out as undeclared, and keeps it', async () => {
      fake.setData({
        resourceTypes: [{ id: 't', code: 'stale', name: 'Stale', description: null, allowedActions: ['x'] }],
      });

      await expect(fake.syncResourceTypes([], { prune: true })).resolves.toEqual({
        dryRun: false,
        prune: true,
        results: [
          {
            code: 'stale',
            outcome: 'undeclared',
            addedActions: [],
            removedActions: [],
            undeclaredActions: ['x'],
            fieldsChanged: [],
          },
        ],
      });
      await expect(fake.listResourceTypes()).resolves.toMatchObject({ total: 1 });
    });

    it('a dry run answers the same and changes nothing', async () => {
      await expect(fake.syncResourceTypes([ORDERS], { dryRun: true })).resolves.toMatchObject({
        dryRun: true,
        results: [{ outcome: 'created' }],
      });

      expect(fake.syncedResourceTypes).toEqual([]);
      await expect(fake.listResourceTypes()).resolves.toMatchObject({ total: 0 });
    });

    it('needs resource-types:sync', async () => {
      fake.setData({ permissions: ['permissions:read'] });

      await expect(fake.syncResourceTypes([ORDERS])).rejects.toMatchObject({ permission: 'resource-types:sync' });
    });
  });

  it('refuses a call the fake key is not granted, naming the permission', async () => {
    fake.setData({ ...DATA, permissions: ['accounts:read'] });

    await expect(fake.getAccount('u1')).resolves.not.toBeNull();
    await expect(fake.getAccountRoles('u1')).rejects.toMatchObject({ permission: 'roles:read' });
    await expect(fake.getAccountRoles('u1')).rejects.toBeInstanceOf(IamPermissionDeniedError);
  });

  it('fails the next calls on request, and records every call', async () => {
    fake.failWith('unavailable', 1);

    await expect(fake.getAccount('u1')).rejects.toBeInstanceOf(IamUnavailableError);
    await expect(fake.getAccount('u1')).resolves.not.toBeNull();
    expect(fake.calls.map((c) => c.method)).toEqual(['getAccount', 'getAccount']);
  });

  it('stands in for IamServiceClient in IamAuthzTestingModule', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [IamAuthzTestingModule.forRoot({ service: DATA })],
    }).compile();

    const client = moduleRef.get(IamServiceClient);

    expect(client).toBe(moduleRef.get(FakeIamServiceClient));
    await expect(client.getAccount('u1')).resolves.toMatchObject({ id: 'u1' });
  });
});
