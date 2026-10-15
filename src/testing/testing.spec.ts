import 'reflect-metadata';
import { Controller, Get, Logger, Param, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Authorize, AuthorizedUser, fromParam } from '..';
import { RouteAudit } from '../guard/route-audit';
import { SkipAuthorize } from '../guard/skip-authorize.decorator';
import { allow, deny, FakeIamAuthzClient, IamAuthzTestingModule } from '.';

@Controller('invoices')
class InvoicesController {
  @Get(':id')
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
  read(@Param('id') id: string, @AuthorizedUser() userId: string) {
    return { id, userId };
  }

  @Get(':id/both')
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
  @Authorize('invoices:audit', { type: 'invoices', id: fromParam('id') })
  both() {
    return { ok: true };
  }

  @Get()
  @SkipAuthorize('public listing')
  list() {
    return [];
  }

  @Get('open/undeclared')
  undeclared() {
    return {};
  }
}

/** What a resource service's own spec looks like with the testing entry point. */
describe('IamAuthzTestingModule', () => {
  let app: INestApplication;
  let fake: FakeIamAuthzClient;
  let url: string;

  const boot = async (options: Parameters<typeof IamAuthzTestingModule.forRoot>[0]) => {
    const moduleRef = await Test.createTestingModule({
      imports: [IamAuthzTestingModule.forRoot(options)],
      controllers: [InvoicesController],
    }).compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');
    url = (await app.getUrl()).replace('[::1]', '127.0.0.1');
    fake = moduleRef.get(FakeIamAuthzClient);
  };
  const get = (path: string) => fetch(`${url}${path}`, { headers: { authorization: 'Bearer test-token' } });

  afterEach(() => app.close());

  it('applies the rules, and reports the configured user', async () => {
    await boot({ rules: [deny('invoices:read', { id: 'inv-9' }), allow('invoices:read')], userId: 'u-7' });

    await expect((await get('/invoices/inv-1')).json()).resolves.toEqual({ id: 'inv-1', userId: 'u-7' });
    expect((await get('/invoices/inv-9')).status).toBe(403);
    expect(fake.calls.map((c) => c.resource.id)).toEqual(['inv-1', 'inv-9']);
  });

  it('denies what no rule allows', async () => {
    await boot({ rules: [] });

    expect((await get('/invoices/inv-1')).status).toBe(403);
  });

  it.each([
    ['unauthenticated', 401],
    ['misconfigured', 500],
    ['unavailable', 503],
  ] as const)('fails like IAM would: %s → %i', async (kind, status) => {
    await boot({ rules: [allow('*')] });
    fake.failWith(kind);

    expect((await get('/invoices/inv-1')).status).toBe(status);
  });

  // Several requirements failing differently: the client hears about its
  // credential before anything else — signing in again may fix the rest.
  it('reports the credential problem first when requirements fail differently', async () => {
    await boot({ rules: [allow('*')] });
    fake.failWith('unavailable', 1);
    const second = fake.authorize.bind(fake);
    let n = 0;
    fake.authorize = async (request) => {
      n += 1;
      if (n === 2) throw new (await import('../client/errors')).IamUnauthenticatedError({ code: 'TOKEN_REVOKED' });
      return second(request);
    };

    expect((await get('/invoices/inv-1/both')).status).toBe(401);
  });

  describe('global mode', () => {
    it('refuses an undeclared route and lets an exempt one through', async () => {
      await boot({ rules: [allow('*')], global: true });

      expect((await get('/invoices/open/undeclared')).status).toBe(403);
      expect((await get('/invoices')).status).toBe(200);
    });

    it('lists exempt and undeclared routes at boot', async () => {
      const log = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      try {
        await boot({ rules: [allow('*')], global: true });

        expect(log).toHaveBeenCalledWith(expect.stringContaining('InvoicesController.list — public listing'));
        expect(warn).toHaveBeenCalledWith(expect.stringContaining('InvoicesController.undeclared'));
        expect(app.get(RouteAudit).routes()).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ handler: 'read', status: 'authorized' }),
            expect.objectContaining({ handler: 'list', status: 'skipped', reason: 'public listing' }),
            expect.objectContaining({ handler: 'undeclared', status: 'undeclared' }),
          ]),
        );
      } finally {
        log.mockRestore();
        warn.mockRestore();
      }
    });
  });
});
