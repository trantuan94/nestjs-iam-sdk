/**
 * The wire contract of nestjs-iam-service's `POST /auth/authorize`.
 *
 * Hand-written, and checked against a snapshot of the service's committed
 * OpenAPI document (`contract/authorize.openapi.json`) by
 * `test/contract.spec.ts`. Refresh the snapshot with `npm run contract:update`.
 */

/**
 * The resource acted on (the service's ADR-0068): the platform's keys at the
 * top, the object's own data under `attributes`, which ABAC reads as
 * `resource.attributes.<name>`. Any other key — `projectId` included, which the
 * service sets from the resource type — is refused with a 400.
 */
export interface AuthorizeResource {
  /** A registered resource type code, owned by the user's namespace (or a platform type). */
  type: string;
  /** The object's identifier: conditions read it as `resource.id`, and an ABAC denial records it. */
  id?: string;
  /**
   * The IAM namespace id the RECORD belongs to — a claim the service checks:
   * when present and different from the token holder's namespace, the answer
   * is `allowed: false` (its tenant-isolation gate). Send it whenever you know it.
   */
  namespaceId?: string;
  /** The object's owner (`resource.ownerId`). */
  ownerId?: string;
  /** The object's own data, apart from the keys above so the two cannot collide — a field named `type` here is the object's. */
  attributes?: Record<string, unknown>;
}

/** The keys a resource may have; `test/contract.spec.ts` compares them with the service's `AuthorizeResourceDto`. */
export const AUTHORIZE_RESOURCE_KEYS = ['type', 'id', 'namespaceId', 'ownerId', 'attributes'] as const;

/** Extra ABAC context, read by conditions as `env.<name>`. */
export interface AuthorizeEnvironment {
  /** The END USER's IP. The service cannot observe it; the SDK fills it from the request. */
  ip?: string;
  [attribute: string]: unknown;
}

export interface AuthorizeRequest {
  /** The end user's access token, forwarded as received. */
  token: string;
  resource: AuthorizeResource;
  /** The full permission code, `<resourceType>:<action>` — e.g. `invoices:approve`. */
  action: string;
  environment?: AuthorizeEnvironment;
}

export interface AuthorizeResponse {
  allowed: boolean;
  /** The token holder, as VERIFIED by the service — trust this, not the token's own claims. */
  userId: string;
  action: string;
  resourceType: string;
}

/** The service's error envelope (`ErrorResponseDto`). */
export interface IamErrorBody {
  statusCode?: number;
  code?: string;
  errorCode?: string;
  message?: unknown;
  description?: string;
  requestId?: string;
}

/** The request keys this SDK sends; `test/contract.spec.ts` compares them with the snapshot. */
export const AUTHORIZE_REQUEST_KEYS = ['token', 'resource', 'action', 'environment'] as const;
export const AUTHORIZE_REQUEST_REQUIRED = ['token', 'resource', 'action'] as const;
export const AUTHORIZE_RESPONSE_KEYS = ['allowed', 'userId', 'action', 'resourceType'] as const;
