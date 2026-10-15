import 'reflect-metadata';
import { Controller, Get, Post } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { Test } from '@nestjs/testing';
import { ApiOperation, DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AUTHORIZE_METADATA } from '../guard/metadata';
import { IamAuthzTestingModule } from '../testing';
import { AccessControl, accessControlOf } from './access-control.decorator';
import { applyAccessControlToSwagger } from './apply-access-control';

describe('@AccessControl', () => {
  class Invoices {
    @AccessControl({ namespace: '*', permissions: 'invoices:read' })
    one() {}

    @AccessControl([
      { namespace: 'acme', permissions: ['invoices:read', 'invoices:approve'] },
      { namespace: 'master', permissions: 'invoices:read' },
    ])
    many() {}
  }

  it('records one policy, normalised to a list of lists', () => {
    expect(accessControlOf(Invoices.prototype.one)).toEqual([{ namespace: '*', permissions: ['invoices:read'] }]);
  });

  it('records several policies in order', () => {
    expect(accessControlOf(Invoices.prototype.many)).toEqual([
      { namespace: 'acme', permissions: ['invoices:read', 'invoices:approve'] },
      { namespace: 'master', permissions: ['invoices:read'] },
    ]);
  });

  // Documentation only: nothing here may take part in a decision.
  it('attaches no guard and no authorization requirement', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, Invoices.prototype.one)).toBeUndefined();
    expect(Reflect.getMetadata(AUTHORIZE_METADATA, Invoices.prototype.one)).toBeUndefined();
  });

  it('answers undefined for a handler without one', () => {
    expect(accessControlOf(() => undefined)).toBeUndefined();
    expect(accessControlOf(undefined)).toBeUndefined();
  });

  it.each([
    [{ namespace: '', permissions: 'invoices:read' }, /namespace/],
    [{ namespace: '  ', permissions: 'invoices:read' }, /namespace/],
    [{ namespace: '*', permissions: [] }, /no permissions/],
    [{ namespace: '*', permissions: '' }, /empty permission/],
    [{ namespace: '*', permissions: ['invoices:read', 42] }, /empty permission/],
    [{ namespace: '*', permissions: '   ' }, /empty permission/],
    [{ namespace: 42, permissions: 'invoices:read' }, /namespace/],
    ['invoices:read', /must be an object/],
    [[], /at least one policy/],
    [null, /must be an object/],
  ])('refuses %j at decoration time', (policies, message) => {
    expect(() => AccessControl(policies as never)({}, 'm', { value: () => undefined })).toThrow(message);
  });
});

describe('applyAccessControlToSwagger', () => {
  @Controller('invoices')
  class InvoicesController {
    @Get()
    @AccessControl({ namespace: 'acme', permissions: ['invoices:read', 'invoices:approve'] })
    @ApiOperation({ summary: 'List', description: 'Lists invoices' })
    list() {}

    @Get('bare')
    @AccessControl([
      { namespace: '*', permissions: 'invoices:read' },
      { namespace: 'master', permissions: 'invoices:export' },
    ])
    bare() {}

    @Post()
    @ApiOperation({ description: 'Creates one' })
    create() {}
  }

  const documentOf = async (applications = 1) => {
    const moduleRef = await Test.createTestingModule({ controllers: [InvoicesController] }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    for (let i = 0; i < applications; i += 1) applyAccessControlToSwagger(app);
    const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
    await app.close();
    return document;
  };

  // The suites share one controller class, whose metadata the helper rewrites:
  // build the reference document once and assert on it.
  let first: Awaited<ReturnType<typeof documentOf>>;
  beforeAll(async () => {
    first = await documentOf(2);
  });

  it("appends the policy to the operation's description, in nestjs-iam-service's format", () => {
    expect(first.paths['/invoices']?.get?.description).toBe(
      'Lists invoices<br><br>***Endpoint policy***<br>Namespace acme: invoices:read, invoices:approve<br>',
    );
    expect(first.paths['/invoices']?.get?.summary).toBe('List');
  });

  it('describes a route that has no @ApiOperation', () => {
    expect(first.paths['/invoices/bare']?.get?.description).toBe(
      '<br><br>***Endpoint policy***<br>Namespace *: invoices:read<br>Namespace master: invoices:export<br>',
    );
  });

  it('is idempotent — applied twice (above) and again, the policy appears once', async () => {
    const again = await documentOf();

    expect(again.paths['/invoices']?.get?.description?.match(/Endpoint policy/g)).toHaveLength(1);
  });

  it('leaves a route without @AccessControl alone', () => {
    expect(first.paths['/invoices']?.post?.description).toBe('Creates one');
  });

  it('works whether or not the app imports IamAuthzModule', async () => {
    @Controller('other')
    class OtherController {
      @Get()
      @AccessControl({ namespace: '*', permissions: 'other:read' })
      read() {}
    }
    const moduleRef = await Test.createTestingModule({
      imports: [IamAuthzTestingModule.forRoot()],
      controllers: [OtherController],
    }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    applyAccessControlToSwagger(app);
    const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
    await app.close();

    expect(document.paths['/other']?.get?.description).toContain('Namespace *: other:read');
  });
});
