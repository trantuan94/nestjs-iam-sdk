import {
  createParamDecorator,
  ExecutionContext,
  Injectable,
  PipeTransform,
  UnauthorizedException,
} from '@nestjs/common';
import type { AuthorizeEnvironment, AuthorizeResource, AuthorizeResponse } from '../client/contract';
import { authorizationOf } from './request-decisions';
import { IamAuthz } from './iam-authz.service';

/**
 * The token holder's id as VERIFIED by IAM, from a decision already taken on
 * this request (`@Authorize`, or `@Authz()` earlier in the handler).
 *
 * Throws 401 if nothing has been decided yet: this is never read from the
 * token itself, whose claims this service has not verified.
 */
export const AuthorizedUser = createParamDecorator((_: unknown, context: ExecutionContext): string => {
  const authorization = authorizationOf(context.switchToHttp().getRequest());
  if (!authorization) {
    throw new UnauthorizedException({
      statusCode: 401,
      code: 'NOT_AUTHORIZED_YET',
      message: '@AuthorizedUser() needs an @Authorize on the route',
    });
  }
  return authorization.userId;
});

/** A checker bound to the current request: its token, IP and environment. */
export interface BoundAuthz {
  /** `true` / `false`; a refused credential or an unavailable IAM still throws. */
  check(action: string, resource: AuthorizeResource, environment?: AuthorizeEnvironment): Promise<boolean>;
  /** Throws on a denial too (403 by default); resolves with the decision. */
  assert(action: string, resource: AuthorizeResource, environment?: AuthorizeEnvironment): Promise<AuthorizeResponse>;
}

const CurrentRequest = createParamDecorator(
  (_: unknown, context: ExecutionContext): unknown => context.switchToHttp().getRequest(),
);

/**
 * Binds `IamAuthz` to the request. A pipe because a param decorator's factory
 * is not a provider: the pipe is, so the checker comes from the application's
 * own injector — two applications in one process each get their own.
 */
@Injectable()
export class BindAuthzPipe implements PipeTransform<unknown, BoundAuthz> {
  constructor(private readonly authz: IamAuthz) {}

  transform(request: unknown): BoundAuthz {
    return {
      check: (action, resource, environment) => this.authz.check(request, action, resource, environment),
      assert: (action, resource, environment) => this.authz.assert(request, action, resource, environment),
    };
  }
}

/**
 * For checks that need the RECORD — ownership, amounts, status — which a guard
 * cannot see because it runs before the handler loads anything.
 *
 * ```ts
 * async approve(@Param('id') id: string, @Authz() authz: BoundAuthz) {
 *   const invoice = await this.invoices.findById(id);
 *   await authz.assert('invoices:approve', { type: 'invoices', id, ownerId: invoice.createdBy });
 * }
 * ```
 */
export const Authz = (): ParameterDecorator => CurrentRequest(BindAuthzPipe);
