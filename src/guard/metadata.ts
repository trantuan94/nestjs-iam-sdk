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

/**
 * What a route ENFORCES under the global guard, read from `@Authorize` (on the handler) and `@SkipAuthorize` (on the
 * handler, else its controller) the way the guard reads them:
 *
 * - `authorized`: IAM must allow every requirement — `@Authorize` wins over an exemption on the controller;
 * - `exempt`: let through, for the stated reason;
 * - `undeclared`: neither — refused with 403 in `global` mode.
 *
 * For a service's own docs and wiring specs, so they classify a route as the guard does without reading the SDK's
 * metadata keys. `controller` is the class the handler is declared on.
 */
export type EndpointPolicy =
  | { kind: 'authorized'; requirements: AuthorizationRequirement[] }
  | { kind: 'exempt'; reason: string }
  | { kind: 'undeclared' };

export const endpointPolicyOf = (handler: unknown, controller: unknown): EndpointPolicy => {
  const requirements = authorizationRequirementsOf(handler);
  if (requirements.length > 0) return { kind: 'authorized', requirements };
  const reason = skipReasonOf(handler) ?? skipReasonOf(controller);
  return reason === undefined ? { kind: 'undeclared' } : { kind: 'exempt', reason };
};

const skipReasonOf = (target: unknown): string | undefined =>
  target && (typeof target === 'function' || typeof target === 'object')
    ? (Reflect.getMetadata(SKIP_AUTHORIZE_METADATA, target) as string | undefined)
    : undefined;
