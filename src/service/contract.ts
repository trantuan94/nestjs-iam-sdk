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
  | 'permissions:read';

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
} as const;

/** Each route the client calls, with the permission it needs. */
export const SERVICE_ROUTES = [
  { method: 'post', path: '/service/tokens/introspect', permission: 'tokens:introspect' },
  { method: 'get', path: '/service/accounts/{userId}', permission: 'accounts:read' },
  { method: 'post', path: '/service/accounts/lookup', permission: 'accounts:read' },
  { method: 'post', path: '/service/accounts/contact', permission: 'profiles:read' },
  { method: 'get', path: '/service/accounts/{userId}/contact', permission: 'profiles:read' },
  { method: 'get', path: '/service/roles', permission: 'roles:read' },
  { method: 'get', path: '/service/accounts/{userId}/roles', permission: 'roles:read' },
  { method: 'get', path: '/service/accounts/{userId}/permissions', permission: 'permissions:read' },
  { method: 'get', path: '/service/resource-types', permission: 'permissions:read' },
] as const satisfies readonly { method: string; path: string; permission: ServicePermission }[];
