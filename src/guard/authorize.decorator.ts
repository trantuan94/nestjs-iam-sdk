import { GUARDS_METADATA } from '@nestjs/common/constants';
import { AUTHORIZE_METADATA, type AuthorizeRequirement } from './metadata';
import { assertResourceSpec, type ResourceSpec } from './resolvers';
import { applySwagger } from './swagger';
import { IamAuthzGuard } from './iam-authz.guard';

/**
 * Requires IAM to allow `action` on `resource` before the handler runs.
 *
 * ```ts
 * @Get(':id')
 * @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
 * ```
 *
 * Several on one handler are ANDed and asked in parallel. The guard is
 * attached once however many there are. For attributes only the RECORD knows
 * (`ownerId`, `amount`), check inside the handler with `@Authz()` instead.
 */
export const Authorize =
  (action: string, resource: ResourceSpec): MethodDecorator =>
  (target, key, descriptor) => {
    assertResourceSpec(action, resource);
    const handler = descriptor.value as object;

    const requirements: AuthorizeRequirement[] =
      (Reflect.getMetadata(AUTHORIZE_METADATA, handler) as AuthorizeRequirement[] | undefined) ?? [];
    // Decorators apply bottom-up; prepend so the array reads in source order.
    Reflect.defineMetadata(AUTHORIZE_METADATA, [{ action, resource }, ...requirements], handler);

    const guards = (Reflect.getMetadata(GUARDS_METADATA, handler) as unknown[] | undefined) ?? [];
    if (!guards.includes(IamAuthzGuard)) {
      Reflect.defineMetadata(GUARDS_METADATA, [...guards, IamAuthzGuard], handler);
    }

    applySwagger({ action, resource }, target, key, descriptor);
    return descriptor;
  };
