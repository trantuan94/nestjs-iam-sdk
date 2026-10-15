import type { ResourceSpec } from './resolvers';

export const AUTHORIZE_METADATA = Symbol.for('@trantuan94/nestjs-iam-sdk:authorize');
export const SKIP_AUTHORIZE_METADATA = Symbol.for('@trantuan94/nestjs-iam-sdk:skip-authorize');

/** One `@Authorize` on a handler. A handler may carry several; all must be allowed. */
export interface AuthorizeRequirement {
  action: string;
  resource: ResourceSpec;
}
