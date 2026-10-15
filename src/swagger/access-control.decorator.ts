/** One endpoint policy: which namespace, holding which permission codes. */
export interface AccessControlPolicy {
  /** A namespace code, or `*` for any namespace. */
  namespace: string;
  permissions: string | string[];
}

export const ACCESS_CONTROL_METADATA = Symbol.for('@trantuan94/nestjs-iam-sdk:access-control');

const assertPolicy = (policy: AccessControlPolicy): AccessControlPolicy => {
  if (!policy || typeof policy !== 'object') {
    throw new Error('@AccessControl: a policy must be an object');
  }
  if (typeof policy.namespace !== 'string' || policy.namespace.trim() === '') {
    throw new Error('@AccessControl: `namespace` must be a non-empty string (a code, or `*`)');
  }
  const permissions = Array.isArray(policy.permissions) ? policy.permissions : [policy.permissions];
  if (permissions.length === 0) {
    throw new Error(`@AccessControl: namespace '${policy.namespace}' lists no permissions`);
  }
  for (const permission of permissions) {
    if (typeof permission !== 'string' || permission.trim() === '') {
      throw new Error(`@AccessControl: namespace '${policy.namespace}' lists an empty permission`);
    }
  }
  return { namespace: policy.namespace, permissions: [...permissions] };
};

/**
 * DOCUMENTS a route's endpoint policy, as nestjs-iam-service's decorator of
 * the same name does: `applyAccessControlToSwagger(app)` writes it into the
 * operation's Swagger description.
 *
 * **It enforces nothing.** It attaches no guard and never asks IAM. Pair it
 * with `@Authorize` (or `@Authz()` in the handler) for that. Under
 * `global: true`, a route carrying only this is still undeclared, and refused.
 *
 * ```ts
 * @AccessControl({ namespace: '*', permissions: 'invoices:read' })
 * @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
 * ```
 */
export const AccessControl =
  (policies: AccessControlPolicy | AccessControlPolicy[]): MethodDecorator =>
  (_target, _key, descriptor) => {
    const list = (Array.isArray(policies) ? policies : [policies]).map(assertPolicy);
    if (list.length === 0) throw new Error('@AccessControl: at least one policy is required');
    // Normalised — always an array of policies, each listing an array of
    // permissions — so the Swagger helper handles one shape.
    Reflect.defineMetadata(ACCESS_CONTROL_METADATA, list, descriptor.value as object);
    return descriptor;
  };

/** The policies `@AccessControl` recorded on a handler, normalised; `undefined` without one. */
export const accessControlOf = (handler: unknown): AccessControlPolicy[] | undefined =>
  handler && (typeof handler === 'function' || typeof handler === 'object')
    ? (Reflect.getMetadata(ACCESS_CONTROL_METADATA, handler) as AccessControlPolicy[] | undefined)
    : undefined;
