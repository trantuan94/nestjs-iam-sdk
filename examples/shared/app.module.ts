import { Module, type DynamicModule } from '@nestjs/common';
import { IamAuthzModule, type IamAuthzOptions } from '../../src';
import { HealthController, InvoicesController } from './invoices.controller';

/** The example resource service, configured per test (or from env in `main.ts`). */
@Module({})
export class ExampleAppModule {
  static with(options: IamAuthzOptions): DynamicModule {
    return {
      module: ExampleAppModule,
      imports: [IamAuthzModule.forRoot(options)],
      controllers: [InvoicesController, HealthController],
    };
  }
}

export const optionsFromEnv = (): IamAuthzOptions => ({
  baseUrl: process.env.IAM_BASE_URL ?? 'http://localhost:3000/api/iam',
  apiKey: process.env.IAM_API_KEY ?? '',
  global: true,
});
