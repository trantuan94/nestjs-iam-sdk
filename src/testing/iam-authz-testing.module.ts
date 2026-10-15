import { DynamicModule, Global, Module } from '@nestjs/common';
import { DiscoveryModule } from '@nestjs/core';
import { IAM_AUTHZ_CLIENT } from '../client/iam-authz.client';
import { CORE_EXPORTS, coreProviders } from '../iam-authz.module';
import { IAM_AUTHZ_OPTIONS, resolveOptions, type IamAuthzOptions } from '../options';
import { FakeIamAuthzClient, type FakeRule } from './fake-iam-authz.client';

export interface IamAuthzTestingOptions
  extends Partial<Omit<IamAuthzOptions, 'baseUrl' | 'apiKey'>> {
  rules?: FakeRule[];
  /** The id every decision reports as the verified user. Default `test-user`. */
  userId?: string;
}

/**
 * The real guard, decorators and `IamAuthz`, with IAM replaced by
 * `FakeIamAuthzClient`. Get the fake with `moduleRef.get(FakeIamAuthzClient)`.
 *
 * ```ts
 * Test.createTestingModule({
 *   imports: [IamAuthzTestingModule.forRoot({ rules: [allow('invoices:read')] })],
 *   controllers: [InvoicesController],
 * })
 * ```
 */
@Global()
@Module({})
export class IamAuthzTestingModule {
  static forRoot(options: IamAuthzTestingOptions = {}): DynamicModule {
    const { rules, userId, ...rest } = options;
    const resolved = resolveOptions({ ...rest, baseUrl: 'http://iam.test', apiKey: 'test-api-key' });
    const fake = new FakeIamAuthzClient(rules, userId);
    return {
      module: IamAuthzTestingModule,
      imports: [DiscoveryModule],
      providers: [
        { provide: IAM_AUTHZ_OPTIONS, useValue: resolved },
        { provide: FakeIamAuthzClient, useValue: fake },
        { provide: IAM_AUTHZ_CLIENT, useExisting: FakeIamAuthzClient },
        ...coreProviders(!!resolved.global),
      ],
      exports: [...CORE_EXPORTS, FakeIamAuthzClient],
    };
  }
}
