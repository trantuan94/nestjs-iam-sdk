import { viewOf } from '../http/request-adapter';
import { assertResourceSpec, fromBody, fromHeader, fromParam, fromQuery, fromRequest, resolveResource } from './resolvers';

const request = viewOf({
  headers: { 'x-tenant': 'ns-1', 'x-list': ['first', 'second'] },
  params: { id: 'inv-1' },
  query: { status: 'open' },
  body: { invoice: { ownerId: 'u-2' }, amount: 10 },
  ip: '10.0.0.1',
});

describe('resolvers', () => {
  it('reads each part of the request', async () => {
    await expect(
      resolveResource(
        {
          type: 'invoices',
          id: fromParam('id'),
          namespaceId: fromHeader('X-Tenant'),
          status: fromQuery('status'),
          ownerId: fromBody('invoice.ownerId'),
          amount: fromBody('amount'),
          ip: fromRequest((r) => r.ip()),
          fixed: 'literal',
        },
        request,
      ),
    ).resolves.toEqual({
      type: 'invoices',
      id: 'inv-1',
      namespaceId: 'ns-1',
      status: 'open',
      ownerId: 'u-2',
      amount: 10,
      ip: '10.0.0.1',
      fixed: 'literal',
    });
  });

  it('takes the first of a repeated header', () => {
    expect(fromHeader('x-list').resolve(request)).toBe('first');
  });

  it('leaves out what resolves to nothing — absent, not undefined', async () => {
    const resource = await resolveResource({ type: 'invoices', id: fromParam('missing'), x: fromBody('a.b.c') }, request);

    expect(Object.keys(resource)).toEqual(['type']);
  });

  it('passes a literal object attribute through untouched', async () => {
    await expect(resolveResource({ type: 'invoices', tags: { a: 1 }, flag: false }, request)).resolves.toStrictEqual({
      type: 'invoices',
      tags: { a: 1 },
      flag: false,
    });
  });

  it('accepts a function of the request', async () => {
    await expect(resolveResource((r) => ({ type: 'invoices', id: r.param('id') }), request)).resolves.toEqual({
      type: 'invoices',
      id: 'inv-1',
    });
  });
});

describe('assertResourceSpec — at decoration time', () => {
  it.each([['read'], ['invoices:'], [':read'], ['invoices read'], ['bad action:read'], ['invoices:read extra'], [42]])(
    'rejects the action %j',
    (action) => {
    expect(() => assertResourceSpec(action as string, { type: 'invoices' })).toThrow(/full permission code/);
  });

  it('rejects a resource with no type', () => {
    expect(() => assertResourceSpec('invoices:read', { type: '' })).toThrow(/resource.type/);
    expect(() => assertResourceSpec('invoices:read', undefined as never)).toThrow(/resource is required/);
    expect(() => assertResourceSpec('invoices:read', 'invoices' as never)).toThrow(/resource is required/);
    expect(() => assertResourceSpec('invoices:read', { type: 42 } as never)).toThrow(/resource.type/);
  });

  it('accepts a type resolver, and a function spec', () => {
    expect(() => assertResourceSpec('invoices:read', { type: fromParam('type') as never })).not.toThrow();
    expect(() => assertResourceSpec('invoices:read', () => ({ type: 'invoices' }))).not.toThrow();
  });
});
