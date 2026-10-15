import type { AuthorizeResponse } from '../client/contract';

const DECISIONS = Symbol.for('@trantuan94/nestjs-iam-sdk:decisions');

/** What the SDK learnt about this request: the decisions taken, and the user the service verified. */
export interface RequestAuthorization {
  /** The token holder as VERIFIED by IAM — the identity to trust. */
  userId: string;
  decisions: AuthorizeResponse[];
}

export const recordDecision = (request: unknown, decision: AuthorizeResponse): void => {
  if (!request || typeof request !== 'object') return;
  const bag = request as Record<symbol, RequestAuthorization | undefined>;
  const current = bag[DECISIONS];
  bag[DECISIONS] = current
    ? { userId: current.userId, decisions: [...current.decisions, decision] }
    : { userId: decision.userId, decisions: [decision] };
};

/** The decisions recorded on a request by the guard or `@Authz()`, if any. */
export const authorizationOf = (request: unknown): RequestAuthorization | undefined =>
  request && typeof request === 'object'
    ? (request as Record<symbol, RequestAuthorization | undefined>)[DECISIONS]
    : undefined;
