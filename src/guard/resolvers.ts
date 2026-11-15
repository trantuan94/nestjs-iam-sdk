import { AUTHORIZE_RESOURCE_KEYS, type AuthorizeResource } from '../client/contract';
import type { HttpRequestView } from '../http/request-adapter';

const RESOLVER = Symbol('iam-authz-resolver');

/** A value read from the request when the guard runs. */
export interface ValueResolver<T = unknown> {
  readonly [RESOLVER]: true;
  readonly describe: string;
  resolve(request: HttpRequestView): T | undefined;
}

const resolver = <T>(describe: string, resolve: (request: HttpRequestView) => T | undefined): ValueResolver<T> => ({
  [RESOLVER]: true,
  describe,
  resolve,
});

export const isResolver = (value: unknown): value is ValueResolver =>
  !!value && typeof value === 'object' && (value as Record<symbol, unknown>)[RESOLVER] === true;

/** A route parameter, e.g. `fromParam('id')` for `/invoices/:id`. */
export const fromParam = (name: string) => resolver(`param '${name}'`, (r) => r.param(name));

/** A query-string value. */
export const fromQuery = (name: string) => resolver(`query '${name}'`, (r) => r.query(name));

/** A request header. */
export const fromHeader = (name: string) => resolver(`header '${name}'`, (r) => r.header(name));

/**
 * A field of the parsed body. A dotted path reaches into objects:
 * `fromBody('invoice.ownerId')`.
 */
export const fromBody = (path: string) =>
  resolver(`body '${path}'`, (r) =>
    path.split('.').reduce<unknown>(
      (value, key) => (value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined),
      r.body(),
    ),
  );

/** Anything else, computed from the request. */
export const fromRequest = <T>(compute: (request: HttpRequestView) => T | undefined, describe = 'custom') =>
  resolver(describe, compute);

/**
 * Each key a literal or a resolver; `type` is required. The object's own data goes under `attributes`, each of its
 * values a literal or a resolver too (the service's ADR-0068).
 */
export type ResourceTemplate = {
  type: string | ValueResolver<string>;
  id?: string | ValueResolver;
  namespaceId?: string | ValueResolver;
  ownerId?: string | ValueResolver;
  attributes?: Record<string, unknown>;
};

/** The resource of an `@Authorize`: a template, or a function of the request. */
export type ResourceSpec =
  | ResourceTemplate
  | ((request: HttpRequestView) => AuthorizeResource | Promise<AuthorizeResource>);

const resolveEntries = (entries: Record<string, unknown>, request: HttpRequestView): Record<string, unknown> => {
  const resolved: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(entries)) {
    const one = isResolver(value) ? value.resolve(request) : value;
    if (one !== undefined) resolved[key] = one;
  }
  return resolved;
};

/**
 * Turns a spec into the resource sent to IAM. A key — or an attribute — that
 * resolves to `undefined` is left out, not sent as null: `namespaceId` absent
 * and `namespaceId: null` mean different things to the service. `attributes`
 * is sent only when one of them resolves.
 */
export const resolveResource = async (
  spec: ResourceSpec,
  request: HttpRequestView,
): Promise<AuthorizeResource> => {
  if (typeof spec === 'function') return spec(request);
  const { attributes, ...keys } = spec;
  const resource = resolveEntries(keys, request);
  if (attributes) {
    const resolved = resolveEntries(attributes, request);
    if (Object.keys(resolved).length) resource.attributes = resolved;
  }
  return resource as unknown as AuthorizeResource;
};

/** Checks a spec at DECORATION time, so a route missing its type fails at boot rather than on a request. */
export const assertResourceSpec = (action: string, spec: ResourceSpec): void => {
  if (typeof action !== 'string' || !/^\S+:\S+$/.test(action)) {
    throw new Error(
      `@Authorize: action must be a full permission code '<resourceType>:<action>', got '${String(action)}'`,
    );
  }
  if (typeof spec === 'function') return;
  if (!spec || typeof spec !== 'object') {
    throw new Error(`@Authorize('${action}'): a resource is required`);
  }
  const type = spec.type;
  if (!(typeof type === 'string' && type !== '') && !isResolver(type)) {
    throw new Error(`@Authorize('${action}'): resource.type must be a non-empty string or a resolver`);
  }
  // The service refuses any other key; refused here, the route fails at boot rather than on every request
  for (const key of Object.keys(spec)) {
    if (!(AUTHORIZE_RESOURCE_KEYS as readonly string[]).includes(key)) {
      throw new Error(
        `@Authorize('${action}'): resource.${key} is not a resource key — put the object's own data under attributes (attributes.${key})`,
      );
    }
  }
  if (spec.attributes !== undefined && (typeof spec.attributes !== 'object' || Array.isArray(spec.attributes))) {
    throw new Error(`@Authorize('${action}'): resource.attributes must be an object`);
  }
};
