import type { IamErrorBody } from './contract';

/** Every error the client raises. Branch on the class, never on `message`. */
export abstract class IamAuthzError extends Error {
  protected constructor(
    message: string,
    /** The service's error code, when it answered with one. */
    readonly code?: string,
    /** The service's request id, for correlating with its logs. */
    readonly requestId?: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The END USER's credential was refused: the token is invalid, expired,
 * revoked, or the session has not passed MFA. The user can fix this (sign in
 * again, complete the challenge); it is not a fault of the calling service.
 */
export class IamUnauthenticatedError extends IamAuthzError {
  constructor(body: IamErrorBody) {
    super(body.description ?? 'The access token was refused', body.code, body.requestId);
  }
}

/**
 * The CALLING SERVICE is set up wrong: its API key is missing, invalid or
 * belongs to an inactive user, the resource type is not registered (or is
 * owned by another tenant), the request failed validation, or `baseUrl` points
 * at the wrong place. Nothing the end user does fixes it, so it should be loud.
 */
export class IamMisconfigurationError extends IamAuthzError {
  constructor(
    message: string,
    readonly status?: number,
    body?: IamErrorBody,
  ) {
    super(message, body?.code, body?.requestId);
  }
}

/**
 * No decision could be had: a timeout, a network error, a 429 or a 5xx, or a
 * body that is not the contract. The SDK always denies in this case.
 */
export class IamUnavailableError extends IamAuthzError {
  constructor(
    message: string,
    readonly status?: number,
    /** Seconds, from the service's `Retry-After`, when it sent one. */
    readonly retryAfterSeconds?: number,
    body?: IamErrorBody,
  ) {
    super(message, body?.code, body?.requestId);
  }
}
