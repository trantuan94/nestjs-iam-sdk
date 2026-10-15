/**
 * The wire contract of nestjs-iam-service's `POST /auth/authorize`.
 *
 * Hand-written, and checked against a snapshot of the service's committed
 * OpenAPI document (`contract/authorize.openapi.json`) by
 * `test/contract.spec.ts`. Refresh the snapshot with `npm run contract:update`.
 */

/**
 * The resource acted on. Only `type` is required by the service; every other
 * attribute is handed to ABAC as `resource.<name>`.
 */
export interface AuthorizeResource {
  /** A registered resource type code, owned by the user's namespace (or a platform type). */
  type: string;
  id?: string;
  /**
   * The IAM namespace id the RECORD belongs to. When present and different
   * from the token holder's namespace, the answer is `allowed: false` — the
   * service's tenant-isolation gate. Send it whenever you know it.
   */
  namespaceId?: string;
  [attribute: string]: unknown;
}

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
