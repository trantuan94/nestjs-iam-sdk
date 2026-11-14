import type { ResourceSpec } from './resolvers';

export const AUTHORIZE_METADATA = Symbol.for('@trantuan94/nestjs-iam-sdk:authorize');
export const SKIP_AUTHORIZE_METADATA = Symbol.for('@trantuan94/nestjs-iam-sdk:skip-authorize');

/** One `@Authorize` on a handler. A handler may carry several; all must be allowed. */
export interface AuthorizeRequirement {
  action: string;
  resource: ResourceSpec;
}

/** What an `@Authorize` asks, as documentation reads it: the action, and the resource type when it is a literal. */
export interface AuthorizationRequirement {
  action: string;
  /** `undefined` when the type is resolved from the request, or the resource is a function. */
  resourceType: string | undefined;
}

/**
 * The `@Authorize` requirements on a handler, in source order; `[]` without one. For a service's own docs — an
 * endpoint policy in Swagger, a wiring spec checking every action is one it declares to IAM — without reading the
 * SDK's metadata key.
 */
export const authorizationRequirementsOf = (handler: unknown): AuthorizationRequirement[] => {
  if (!handler || (typeof handler !== 'function' && typeof handler !== 'object')) return [];
  const requirements = (Reflect.getMetadata(AUTHORIZE_METADATA, handler) as AuthorizeRequirement[] | undefined) ?? [];
  return requirements.map(({ action, resource }) => ({
    action,
    resourceType: typeof resource === 'object' && typeof resource.type === 'string' ? resource.type : undefined,
  }));
};
