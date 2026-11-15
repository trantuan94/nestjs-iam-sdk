import { FakeIamAuthzClient, allow, deny } from './fake-iam-authz.client';

describe('FakeIamAuthzClient', () => {
  const request = (attributes: Record<string, unknown>) => ({
    token: 't',
    action: 'invoices:read',
    resource: { type: 'invoices', id: 'inv-1', attributes },
  });

  it("matches a rule on the resource's keys and, by dotted path, on its attributes", async () => {
    const fake = new FakeIamAuthzClient([
      deny('invoices:read', { 'attributes.status': 'void' }),
      allow('invoices:read', { id: 'inv-1' }),
    ]);

    await expect(fake.authorize(request({ status: 'void' }))).resolves.toMatchObject({ allowed: false });
    await expect(fake.authorize(request({ status: 'open' }))).resolves.toMatchObject({ allowed: true });
  });

  it('does not match a dotted path the resource does not have', async () => {
    const fake = new FakeIamAuthzClient([allow('invoices:read', { 'attributes.owner.id': 'u-1' })]);

    await expect(fake.authorize(request({}))).resolves.toMatchObject({ allowed: false });
    await expect(fake.authorize(request({ owner: { id: 'u-1' } }))).resolves.toMatchObject({ allowed: true });
  });
});
