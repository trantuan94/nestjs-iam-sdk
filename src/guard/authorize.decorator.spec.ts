import { Controller, Post } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { Test } from '@nestjs/testing';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { IamAuthzTestingModule } from '../testing';
import { Authorize } from './authorize.decorator';
import { IamAuthzGuard } from './iam-authz.guard';
import { AUTHORIZE_METADATA, type AuthorizeRequirement } from './metadata';
import { fromParam } from './resolvers';

class Invoices {
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
  @Authorize('emails:send', { type: 'emails' })
  send() {}

  @Authorize('invoices:read', { type: 'invoices' })
  read() {}
}

describe('@Authorize', () => {
  it('records every requirement, in source order', () => {
    const requirements = Reflect.getMetadata(AUTHORIZE_METADATA, Invoices.prototype.send) as AuthorizeRequirement[];

    expect(requirements.map((r) => r.action)).toEqual(['invoices:read', 'emails:send']);
  });

  it('attaches the guard once, however many requirements there are', () => {
    const guards = Reflect.getMetadata(GUARDS_METADATA, Invoices.prototype.send) as unknown[];

    expect(guards.filter((g) => g === IamAuthzGuard)).toHaveLength(1);
  });

  it('documents the requirements in OpenAPI, as an extension', () => {
    const extensions = Reflect.getMetadata('swagger/apiExtension', Invoices.prototype.send) as Record<string, unknown>;

    expect(extensions['x-iam-authorization']).toEqual([
      { action: 'emails:send', resourceType: 'emails' },
      { action: 'invoices:read', resourceType: 'invoices' },
    ]);
  });

  // The metadata key is @nestjs/swagger's own and unexported, so the pin is
  // behavioural: the document it builds must carry BOTH requirements.
  it('reaches the OpenAPI document @nestjs/swagger builds', async () => {
    @Controller('invoices')
    class InvoicesController {
      @Post(':id/send')
      @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
      @Authorize('emails:send', { type: 'emails' })
      send() {}
    }
    const moduleRef = await Test.createTestingModule({
      imports: [IamAuthzTestingModule.forRoot()],
      controllers: [InvoicesController],
    }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    await app.init();

    const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
    const operation = document.paths['/invoices/{id}/send']?.post as unknown as Record<string, unknown>;
    await app.close();

    expect(operation['x-iam-authorization']).toEqual([
      { action: 'emails:send', resourceType: 'emails' },
      { action: 'invoices:read', resourceType: 'invoices' },
    ]);
    expect(Object.keys(operation['responses'] as object)).toEqual(expect.arrayContaining(['401', '403', '503']));
  });

  it('fails at decoration time on an action that is not a full code', () => {
    expect(() => {
      class Broken {
        @Authorize('read', { type: 'invoices' })
        handler() {}
      }
      return Broken;
    }).toThrow(/full permission code/);
  });
});
