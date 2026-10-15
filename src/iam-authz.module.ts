import { DynamicModule, Global, Module, Provider, type ModuleMetadata } from '@nestjs/common';
import { APP_GUARD, DiscoveryModule } from '@nestjs/core';
import { BindAuthzPipe } from './checker/decorators';
import { IamAuthz } from './checker/iam-authz.service';
import { IAM_AUTHZ_CLIENT, IamAuthzClient } from './client/iam-authz.client';
import { IamAuthzGuard } from './guard/iam-authz.guard';
import { RouteAudit } from './guard/route-audit';
import { IAM_AUTHZ_OPTIONS, resolveOptions, type IamAuthzOptions } from './options';

export interface IamAuthzAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  inject?: unknown[];
  useFactory: (...args: never[]) => IamAuthzOptions | Promise<IamAuthzOptions>;
  /**
   * `global` decides whether a provider is REGISTERED, which happens before the
   * factory runs — so for the async form it is stated here, not in the factory.
   */
  global?: boolean;
}

/** Everything but the options and the client, shared with `IamAuthzTestingModule`. */
export const coreProviders = (global: boolean): Provider[] => [
  IamAuthz,
  IamAuthzGuard,
  BindAuthzPipe,
  RouteAudit,
  ...(global ? [{ provide: APP_GUARD, useExisting: IamAuthzGuard }] : []),
];

export const CORE_EXPORTS = [IamAuthz, IamAuthzGuard, BindAuthzPipe, IAM_AUTHZ_OPTIONS, IAM_AUTHZ_CLIENT];

/**
 * ```ts
 * IamAuthzModule.forRoot({ baseUrl: 'https://iam.example.com/api/iam', apiKey: process.env.IAM_API_KEY })
 * ```
 *
 * Global: import it once, in the root module. The options are validated when
 * the module is built, so a missing key fails the boot, not the first request.
 */
@Global()
@Module({})
export class IamAuthzModule {
  static forRoot(options: IamAuthzOptions): DynamicModule {
    const resolved = resolveOptions(options);
    return {
      module: IamAuthzModule,
      imports: [DiscoveryModule],
      providers: [
        { provide: IAM_AUTHZ_OPTIONS, useValue: resolved },
        { provide: IAM_AUTHZ_CLIENT, useClass: IamAuthzClient },
        ...coreProviders(!!resolved.global),
      ],
      exports: CORE_EXPORTS,
    };
  }

  static forRootAsync(options: IamAuthzAsyncOptions): DynamicModule {
    const global = !!options.global;
    return {
      module: IamAuthzModule,
      imports: [DiscoveryModule, ...(options.imports ?? [])],
      providers: [
        {
          provide: IAM_AUTHZ_OPTIONS,
          inject: (options.inject ?? []) as never[],
          useFactory: async (...args: never[]) => {
            const value = await options.useFactory(...args);
            if (value && value.global !== undefined && !!value.global !== global) {
              throw new Error(
                'IamAuthzModule.forRootAsync: set `global` on the async options, not in the factory',
              );
            }
            return resolveOptions({ ...value, global });
          },
        },
        { provide: IAM_AUTHZ_CLIENT, useClass: IamAuthzClient },
        ...coreProviders(global),
      ],
      exports: CORE_EXPORTS,
    };
  }
}
