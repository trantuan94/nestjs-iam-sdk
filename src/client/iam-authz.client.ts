import { Inject, Injectable } from '@nestjs/common';
import { IAM_AUTHZ_OPTIONS, ResolvedIamAuthzOptions } from '../options';
import { AuthorizeRequest, AuthorizeResponse, IamErrorBody } from './contract';
import {
  IamMisconfigurationError,
  IamUnauthenticatedError,
  IamUnavailableError,
} from './errors';

/** What answers an authorization request. The real one is HTTP; `testing` provides a fake. */
export interface AuthorizationClient {
  authorize(request: AuthorizeRequest): Promise<AuthorizeResponse>;
}

export const IAM_AUTHZ_CLIENT = Symbol('IAM_AUTHZ_CLIENT');

/**
 * The 401s that are about the END USER's token. Every other 401 is about the
 * caller's API key (`Missing X-API-Key header`, `Invalid or expired API key`,
 * and the key owner's own admission: `User is not active` / `User not found`).
 *
 * The two share the code `UNAUTHORIZED_EXCEPTION`, so the descriptions are
 * what tells them apart. The direction of the default matters: an unknown 401
 * is treated as MISCONFIGURATION (a loud 500), never passed through as the
 * user's fault — a 401 would send a user to sign in again for a broken key.
 */
const TOKEN_CODES = new Set(['INVALID_JWT', 'TOKEN_REVOKED']);
const TOKEN_DESCRIPTIONS = new Set([
  'Multiple factors authentication is required',
  'Namespace not found',
]);

export const isTokenRefusal = (body: IamErrorBody): boolean =>
  (body.code !== undefined && TOKEN_CODES.has(body.code)) ||
  (body.code === 'UNAUTHORIZED_EXCEPTION' &&
    body.description !== undefined &&
    TOKEN_DESCRIPTIONS.has(body.description));

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

const isDecision = (value: unknown): value is AuthorizeResponse => {
  const v = value as Partial<AuthorizeResponse> | null;
  return (
    !!v &&
    typeof v.allowed === 'boolean' &&
    typeof v.userId === 'string' &&
    typeof v.action === 'string' &&
    typeof v.resourceType === 'string'
  );
};

const retryAfterOf = (header: string | null): number | undefined => {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const at = Date.parse(header);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - Date.now()) / 1000));
};

/**
 * Calls `POST {baseUrl}/auth/authorize`. One attempt, bounded by `timeoutMs`,
 * never retried: the service already fails closed, and a retry only multiplies
 * load on it at the moment it is struggling.
 *
 * Resolves only with a decision the service actually gave; every other outcome
 * is one of the three error classes, and the guard turns all of them into a
 * refusal.
 */
@Injectable()
export class IamAuthzClient implements AuthorizationClient {
  private readonly url: string;

  constructor(@Inject(IAM_AUTHZ_OPTIONS) private readonly options: ResolvedIamAuthzOptions) {
    this.url = `${options.baseUrl}/auth/authorize`;
  }

  async authorize(request: AuthorizeRequest): Promise<AuthorizeResponse> {
    let response: Response;
    try {
      response = await fetch(this.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          'x-api-key': this.options.apiKey.reveal(),
        },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch (error) {
      const timedOut = (error as Error)?.name === 'TimeoutError';
      throw new IamUnavailableError(
        timedOut
          ? `IAM did not answer within ${this.options.timeoutMs}ms`
          : `IAM could not be reached: ${(error as Error)?.message ?? String(error)}`,
      );
    }

    let text = '';
    try {
      text = await response.text();
    } catch (error) {
      throw new IamUnavailableError(
        `IAM's answer could not be read: ${(error as Error)?.message ?? String(error)}`,
        response.status,
      );
    }
    const body = parseJson(text);
    const errorBody = (body && typeof body === 'object' ? body : {}) as IamErrorBody;
    const status = response.status;

    if (status === 200) {
      if (isDecision(body)) {
        return {
          allowed: body.allowed,
          userId: body.userId,
          action: body.action,
          resourceType: body.resourceType,
        };
      }
      throw new IamUnavailableError('IAM answered 200 with a body that is not a decision', status);
    }

    if (status === 401) {
      if (isTokenRefusal(errorBody)) throw new IamUnauthenticatedError(errorBody);
      throw new IamMisconfigurationError(
        `IAM refused this service's credentials: ${errorBody.description ?? 'unauthorized'}`,
        status,
        errorBody,
      );
    }

    if (status === 429 || status >= 500) {
      throw new IamUnavailableError(
        `IAM answered ${status}`,
        status,
        retryAfterOf(response.headers.get('retry-after')),
        errorBody,
      );
    }

    // 400 (an unregistered or foreign resource type, a payload that failed
    // validation), 403, 404 (a `baseUrl` missing its prefix) and anything else:
    // the calling service is wrong, and no end user can fix it.
    throw new IamMisconfigurationError(
      `IAM answered ${status}${errorBody.description ? `: ${errorBody.description}` : ''}`,
      status,
      errorBody,
    );
  }
}
