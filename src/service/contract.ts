/**
 * The wire contract of nestjs-iam-service's *Service reads* — the routes under
 * `/service/*` a resource service calls with its API key (ADR-0063 there).
 *
 * Each route needs a permission granted to the key; the key only ever reaches
 * its own (namespace, project). Hand-written, and checked against a snapshot of
 * the service's committed OpenAPI document (`contract/authorize.openapi.json`)
 * by `test/contract.spec.ts`. Refresh it with `npm run contract:update`.
 */

/** The permission codes a key may be granted for these routes. */
export type ServicePermission =
  | 'tokens:introspect'
  | 'accounts:read'
  | 'profiles:read'
  | 'roles:read'
  | 'permissions:read'
  | 'sessions:revoke'
  | 'resource-types:sync';

/** An account as a service sees it: no contact details, no credential. */
export interface ServiceAccount {
  id: string;
  identifier: string;
  /** `ACTIVE`, `CREATED`, `BLOCKED`, … */
  status: string;
  /** Whether the email address was verified. */
  isVerified: boolean;
  /** ISO 8601. */
  createdAt: string;
}

/** An account's contact details. `email: null` when it has none, or is not active. */
export interface AccountContact {
  email: string | null;
  firstName: string | null;
  lastName: string | null;
}

/**
 * Whether an end user's access token is still good. Every refusal —
 * invalid, expired, revoked, an ended session, MFA not cleared, or a user
 * outside the key's project — is `{ active: false }` and nothing more.
 */
export type TokenIntrospection =
  | { active: false }
  | {
      active: true;
      /** The user id, as verified by IAM. */
      sub: string;
      identifier: string;
      /** The session the token was minted for. */
      sessionId: string | null;
      /** Whether the session may pass the MFA gate. */
      mfaCleared: boolean;
      /** Expiry, in seconds since the epoch. */
      exp: number;
    };

export interface ServiceRole {
  id: string;
  code: string;
  name: string;
}

export interface ServiceResourceType {
  id: string;
  code: string;
  name: string;
  description: string | null;
  allowedActions: string[];
}

/** A custom attribute of a resource type, for ABAC conditions. */
export interface ResourceAttributeDefinition {
  type: 'string' | 'number' | 'boolean' | 'string[]';
  /** Default `false`. */
  required?: boolean;
}

/**
 * One resource type as the service serves it, for `syncResourceTypes`. `allowedActions` is the whole set; each
 * action derives the permission code `${code}:${action}`, which grants nothing until an operator puts it in a role.
 */
export interface ResourceTypeDeclaration {
  /** Lowercase alphanumeric with `-` / `_`; not one the platform reserves (`users`, `master`, …). */
  code: string;
  name: string;
  /** Absent keeps the stored description; `null` clears it. */
  description?: string | null;
  allowedActions: string[];
  /** Absent keeps the stored map; present replaces it whole. */
  attributes?: Record<string, ResourceAttributeDefinition>;
}

/**
 * What a sync did to one type. `undeclared`: IAM has it and the manifest does not, with `prune` off.
 * `delete-refused`: `prune` is on but a role holds one of its codes.
 */
export type ResourceTypeSyncOutcome = 'created' | 'updated' | 'unchanged' | 'deleted' | 'delete-refused' | 'undeclared';

export interface ResourceTypeSyncResult {
  code: string;
  outcome: ResourceTypeSyncOutcome;
  addedActions: string[];
  /** Only with `prune`, or by a delete. */
  removedActions: string[];
  /** Carried by IAM, not named by the manifest, kept because `prune` is off. */
  undeclaredActions: string[];
  fieldsChanged: ('name' | 'description' | 'attributes')[];
}

export interface ResourceTypeSync {
  /** True when nothing was written. */
  dryRun: boolean;
  prune: boolean;
  /** The manifest's types in its order, then every type it does not declare, by code. */
  results: ResourceTypeSyncResult[];
}

export interface ResourceTypeSyncOptions {
  /** Also narrow undeclared actions away and delete undeclared types. Default `false`: only adds. */
  prune?: boolean;
  /** Answer what the sync would do, writing nothing. Default `false`. */
  dryRun?: boolean;
}

/** The fields of a declaration, and the ones IAM requires; `test/contract.spec.ts` compares them with the snapshot. */
export const RESOURCE_TYPE_DECLARATION_KEYS = ['code', 'name', 'description', 'allowedActions', 'attributes'] as const;
export const RESOURCE_TYPE_DECLARATION_REQUIRED = ['code', 'name', 'allowedActions'] as const;
export const RESOURCE_TYPE_SYNC_OUTCOMES = [
  'created',
  'updated',
  'unchanged',
  'deleted',
  'delete-refused',
  'undeclared',
] as const satisfies readonly ResourceTypeSyncOutcome[];

/** The most types one sync may declare. */
export const RESOURCE_TYPE_SYNC_MAX = 100;

/** One page of a listing. */
export interface Page<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface ListQuery {
  /** 1-based. */
  page?: number;
  /** At most 100. */
  limit?: number;
  /** Case-insensitive partial match on code or name. */
  searchKey?: string;
}

/** The most identifiers one `POST /service/accounts/lookup` may name. */
export const ACCOUNT_LOOKUP_MAX = 100;

/**
 * The response fields this SDK reads, by schema name in the service's OpenAPI
 * document; `test/contract.spec.ts` compares them with the snapshot.
 */
export const SERVICE_RESPONSE_KEYS = {
  ServiceAccountResponseDto: ['id', 'identifier', 'status', 'isVerified', 'createdAt'],
  AccountContactResponseDto: ['email', 'firstName', 'lastName'],
  TokenIntrospectionResponseDto: ['active', 'sub', 'identifier', 'sessionId', 'mfaCleared', 'exp'],
  ServiceRoleResponseDto: ['id', 'code', 'name'],
  ServiceResourceTypeResponseDto: ['id', 'code', 'name', 'description', 'allowedActions'],
  AccountPermissionsResponseDto: ['permissions'],
  AccountRolesResponseDto: ['roles'],
  AccountLookupResponseDto: ['accounts'],
  SyncResourceTypesResponseDto: ['dryRun', 'prune', 'results'],
  ResourceTypeSyncResultDto: ['code', 'outcome', 'addedActions', 'removedActions', 'undeclaredActions', 'fieldsChanged'],
} as const;

/** Each route the client calls, with the permission it needs and what it answers on success. */
export const SERVICE_ROUTES = [
  { method: 'post', path: '/service/tokens/introspect', permission: 'tokens:introspect', answers: 200 },
  { method: 'get', path: '/service/accounts/{userId}', permission: 'accounts:read', answers: 200 },
  { method: 'post', path: '/service/accounts/lookup', permission: 'accounts:read', answers: 200 },
  { method: 'post', path: '/service/accounts/contact', permission: 'profiles:read', answers: 200 },
  { method: 'get', path: '/service/accounts/{userId}/contact', permission: 'profiles:read', answers: 200 },
  { method: 'get', path: '/service/roles', permission: 'roles:read', answers: 200 },
  { method: 'get', path: '/service/accounts/{userId}/roles', permission: 'roles:read', answers: 200 },
  { method: 'get', path: '/service/accounts/{userId}/permissions', permission: 'permissions:read', answers: 200 },
  { method: 'get', path: '/service/resource-types', permission: 'permissions:read', answers: 200 },
  { method: 'post', path: '/service/accounts/{userId}/sessions/revoke', permission: 'sessions:revoke', answers: 204 },
  { method: 'put', path: '/service/resource-types', permission: 'resource-types:sync', answers: 200 },
] as const satisfies readonly {
  method: string;
  path: string;
  permission: ServicePermission;
  /** The status the route answers on success: 200 with a body, or 204 for a write that answers none. */
  answers: 200 | 204;
}[];
