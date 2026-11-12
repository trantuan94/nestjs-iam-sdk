import type { IamErrorBody } from '../client/contract';
import { IamUnavailableError } from '../client/errors';
import type { ResolvedIamAuthzOptions } from '../options';

export interface IamCall {
  method: 'GET' | 'POST';
  /** Under `baseUrl`, starting with `/`. */
  path: string;
  /** Sent as JSON. */
  body?: unknown;
  /** Appended as a query string; `undefined` values are left out. */
  query?: Record<string, string | number | undefined>;
}

export interface IamAnswer {
  status: number;
  /** The parsed JSON body, or `undefined` when it was not JSON. */
  body: unknown;
  /** The body read as the service's error envelope — `{}` when it is not one. */
  errorBody: IamErrorBody;
  /** Seconds, from `Retry-After`, when the service sent one. */
  retryAfterSeconds?: number;
}

const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

export const retryAfterOf = (header: string | null): number | undefined => {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const at = Date.parse(header);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - Date.now()) / 1000));
};

const urlOf = (baseUrl: string, call: IamCall): string => {
  const query = Object.entries(call.query ?? {}).filter(
    (entry): entry is [string, string | number] => entry[1] !== undefined,
  );
  if (!query.length) return `${baseUrl}${call.path}`;
  return `${baseUrl}${call.path}?${new URLSearchParams(query.map(([k, v]): [string, string] => [k, String(v)]))}`;
};

/**
 * One call to nestjs-iam-service with this service's API key. One attempt,
 * bounded by `timeoutMs`, never retried: the service already fails closed, and
 * a retry only multiplies load on it at the moment it is struggling.
 *
 * Resolves with whatever the service ANSWERED, at any status — what a status
 * means is the caller's. Rejects only when there was no answer to read: a
 * timeout, a network error, or a body that could not be read, all
 * `IamUnavailableError`.
 */
export const sendToIam = async (
  options: ResolvedIamAuthzOptions,
  call: IamCall,
): Promise<IamAnswer> => {
  let response: Response;
  try {
    response = await fetch(urlOf(options.baseUrl, call), {
      method: call.method,
      headers: {
        ...(call.body === undefined ? {} : { 'content-type': 'application/json' }),
        accept: 'application/json',
        'x-api-key': options.apiKey.reveal(),
      },
      body: call.body === undefined ? undefined : JSON.stringify(call.body),
      signal: AbortSignal.timeout(options.timeoutMs),
    });
  } catch (error) {
    const timedOut = (error as Error)?.name === 'TimeoutError';
    throw new IamUnavailableError(
      timedOut
        ? `IAM did not answer within ${options.timeoutMs}ms`
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
  return {
    status: response.status,
    body,
    errorBody: (body && typeof body === 'object' ? body : {}) as IamErrorBody,
    retryAfterSeconds: retryAfterOf(response.headers.get('retry-after')),
  };
};
