export { IamAuthzModule, type IamAuthzAsyncOptions } from './iam-authz.module';
export {
  type IamAuthzOptions,
  type DecisionCacheOptions,
  type DecisionEvent,
  type AuthzFailure,
  IAM_AUTHZ_OPTIONS,
} from './options';

export { Authorize } from './guard/authorize.decorator';
export { SkipAuthorize } from './guard/skip-authorize.decorator';
export { IamAuthzGuard } from './guard/iam-authz.guard';
export {
  fromParam,
  fromQuery,
  fromHeader,
  fromBody,
  fromRequest,
  type ResourceSpec,
  type ResourceTemplate,
  type ValueResolver,
} from './guard/resolvers';

export { IamAuthz } from './checker/iam-authz.service';
export { Authz, AuthorizedUser, type BoundAuthz } from './checker/decorators';
export { authorizationOf, type RequestAuthorization } from './checker/request-decisions';
export { defaultException } from './checker/failure';

export { IamAuthzClient, IAM_AUTHZ_CLIENT, type AuthorizationClient } from './client/iam-authz.client';
export {
  IamAuthzError,
  IamUnauthenticatedError,
  IamMisconfigurationError,
  IamUnavailableError,
} from './client/errors';
export type {
  AuthorizeRequest,
  AuthorizeResponse,
  AuthorizeResource,
  AuthorizeEnvironment,
} from './client/contract';

export { InMemoryDecisionCache, type DecisionCache } from './decision/decision-cache';
export { bearer, fromTokenHeader, firstOf, type TokenExtractor } from './http/token-extractor';
export type { HttpRequestView } from './http/request-adapter';
