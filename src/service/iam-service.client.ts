import { Inject, Injectable } from '@nestjs/common';
import { IAM_AUTHZ_OPTIONS, type ResolvedIamAuthzOptions } from '../options';
import { sendToIam, type IamAnswer, type IamCall } from '../http/iam-transport';
import {
  IamMisconfigurationError,
  IamPermissionDeniedError,
  IamUnavailableError,
} from '../client/errors';
import {
  ACCOUNT_LOOKUP_MAX,
  type AccountContact,
  type ListQuery,
  type Page,
  type ServiceAccount,
  type ServicePermission,
  type ServiceResourceType,
  type ServiceRole,
  type TokenIntrospection,
} from './contract';

/**
 * What a resource service may read of IAM with its API key. The real one is
 * `IamServiceClient`; `@trantuan94/nestjs-iam-sdk/testing` provides
 * `FakeIamServiceClient`.
 *
 * Every method reads only the key's own (namespace, project). A by-id method
 * answers `null` for an id of no account there — unknown, or another
 * project's; IAM answers both alike.
 */
export interface ServiceReadsClient {
  /** `tokens:introspect` — whether an end user's access token is still good. */
  introspectToken(token: string): Promise<TokenIntrospection>;
  /** `accounts:read` — an account by id, or `null`. */
  getAccount(userId: string): Promise<ServiceAccount | null>;
  /** `accounts:read` — the accounts found, ignoring case; a miss is absent. Any number, sent 100 at a time. */
  lookupAccounts(identifiers: readonly string[]): Promise<ServiceAccount[]>;
  /** `profiles:read` — contact details by identifier; `email: null` for any miss. Audited by IAM. */
  getContact(identifier: string): Promise<AccountContact>;
  /** `profiles:read` — contact details by id, or `null` for no such account. Audited by IAM. */
  getContactById(userId: string): Promise<AccountContact | null>;
  /** `roles:read` — the project's roles. */
  listRoles(query?: ListQuery): Promise<Page<ServiceRole>>;
  /** `roles:read` — the roles assigned to an account, or `null`. */
  getAccountRoles(userId: string): Promise<ServiceRole[] | null>;
  /** `permissions:read` — the permission codes an account holds, sorted, or `null`. */
  getAccountPermissions(userId: string): Promise<string[] | null>;
  /** `permissions:read` — the project's resource types and their actions. */
  listResourceTypes(query?: ListQuery): Promise<Page<ServiceResourceType>>;
  /**
   * `sessions:revoke` — sign an account out everywhere: every session and every device's trust, as an operator's
   * Revoke Sessions does (the service's ADR-0065). Its status is untouched, so its holder may sign in again. `true`
   * once ended; `false` for no account of this key's project. Audited by IAM, naming the key.
   */
  revokeSessions(userId: string): Promise<boolean>;
}

// ── shape checks: a 200 that is not the contract is not an answer ───────────

type Guard<T> = (value: unknown) => value is T;

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
const isNullableString = (value: unknown): value is string | null =>
  value === null || typeof value === 'string';
const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((v) => typeof v === 'string');
const arrayOf =
  <T>(guard: Guard<T>): Guard<T[]> =>
  (value): value is T[] =>
    Array.isArray(value) && value.every(guard);

const isAccount: Guard<ServiceAccount> = (v): v is ServiceAccount =>
  isObject(v) &&
  typeof v.id === 'string' &&
  typeof v.identifier === 'string' &&
  typeof v.status === 'string' &&
  typeof v.isVerified === 'boolean' &&
  typeof v.createdAt === 'string';

const isContact: Guard<AccountContact> = (v): v is AccountContact =>
  isObject(v) && isNullableString(v.email) && isNullableString(v.firstName) && isNullableString(v.lastName);

const isIntrospection: Guard<TokenIntrospection> = (v): v is TokenIntrospection =>
  isObject(v) &&
  (v.active === false ||
    (v.active === true &&
      typeof v.sub === 'string' &&
      typeof v.identifier === 'string' &&
      isNullableString(v.sessionId) &&
      typeof v.mfaCleared === 'boolean' &&
      typeof v.exp === 'number'));

const isRole: Guard<ServiceRole> = (v): v is ServiceRole =>
  isObject(v) && typeof v.id === 'string' && typeof v.code === 'string' && typeof v.name === 'string';

const isResourceType: Guard<ServiceResourceType> = (v): v is ServiceResourceType =>
  isObject(v) &&
  typeof v.id === 'string' &&
  typeof v.code === 'string' &&
  typeof v.name === 'string' &&
  isNullableString(v.description) &&
  isStringArray(v.allowedActions);

const pageOf =
  <T>(guard: Guard<T>): Guard<Page<T>> =>
  (v): v is Page<T> =>
    isObject(v) &&
    arrayOf(guard)(v.data) &&
    typeof v.total === 'number' &&
    typeof v.page === 'number' &&
    typeof v.limit === 'number' &&
    typeof v.totalPages === 'number' &&
    typeof v.hasNext === 'boolean' &&
    typeof v.hasPrev === 'boolean';

const field =
  <K extends string, T>(key: K, guard: Guard<T>): Guard<Record<K, T>> =>
  (v): v is Record<K, T> =>
    isObject(v) && guard(v[key]);

// ── named, never spread: what the caller receives is decided here ───────────

const toAccount = (a: ServiceAccount): ServiceAccount => ({
  id: a.id,
  identifier: a.identifier,
  status: a.status,
  isVerified: a.isVerified,
  createdAt: a.createdAt,
});
const toContact = (c: AccountContact): AccountContact => ({
  email: c.email,
  firstName: c.firstName,
  lastName: c.lastName,
});
const toRole = (r: ServiceRole): ServiceRole => ({ id: r.id, code: r.code, name: r.name });
const toResourceType = (t: ServiceResourceType): ServiceResourceType => ({
  id: t.id,
  code: t.code,
  name: t.name,
  description: t.description,
  allowedActions: [...t.allowedActions],
});
const toPage = <T>(page: Page<T>, map: (item: T) => T): Page<T> => ({
  data: page.data.map(map),
  total: page.total,
  page: page.page,
  limit: page.limit,
  totalPages: page.totalPages,
  hasNext: page.hasNext,
  hasPrev: page.hasPrev,
});
const toIntrospection = (t: TokenIntrospection): TokenIntrospection =>
  t.active
    ? {
        active: true,
        sub: t.sub,
        identifier: t.identifier,
        sessionId: t.sessionId,
        mfaCleared: t.mfaCleared,
        exp: t.exp,
      }
    : { active: false };

/** A by-id route answered "no account of this key's project" — the one 404 that is an answer. */
const NO_SUCH_ACCOUNT = Symbol('NO_SUCH_ACCOUNT');

const byId = (userId: string, suffix = ''): string =>
  `/service/accounts/${encodeURIComponent(userId)}${suffix}`;

/**
 * Calls nestjs-iam-service's *Service reads* (`/service/*`) with this
 * service's API key — the same `baseUrl`, `apiKey` and `timeoutMs` as the
 * authorization guard. One attempt per call, never retried.
 *
 * Resolves only with what the service answered under the contract; anything
 * else is one of the SDK's error classes, branched on by class:
 *
 * - `IamPermissionDeniedError` — the key lacks the route's permission;
 * - `IamMisconfigurationError` — the key is refused, the request is invalid,
 *   or `baseUrl` reaches no such route;
 * - `IamUnavailableError` — a timeout, a network error, a 429 or a 5xx, or a
 *   body that is not the contract.
 */
@Injectable()
export class IamServiceClient implements ServiceReadsClient {
  constructor(@Inject(IAM_AUTHZ_OPTIONS) private readonly options: ResolvedIamAuthzOptions) {}

  async introspectToken(token: string): Promise<TokenIntrospection> {
    const body = await this.read(
      'tokens:introspect',
      { method: 'POST', path: '/service/tokens/introspect', body: { token } },
      isIntrospection,
    );
    return toIntrospection(body);
  }

  async getAccount(userId: string): Promise<ServiceAccount | null> {
    const body = await this.readById('accounts:read', byId(userId), isAccount);
    return body === NO_SUCH_ACCOUNT ? null : toAccount(body);
  }

  async lookupAccounts(identifiers: readonly string[]): Promise<ServiceAccount[]> {
    const found: ServiceAccount[] = [];
    // Sequential, not parallel: one lookup should not be a burst against
    // IAM's per-key bucket.
    for (let i = 0; i < identifiers.length; i += ACCOUNT_LOOKUP_MAX) {
      const body = await this.read(
        'accounts:read',
        {
          method: 'POST',
          path: '/service/accounts/lookup',
          body: { identifiers: identifiers.slice(i, i + ACCOUNT_LOOKUP_MAX) },
        },
        field('accounts', arrayOf(isAccount)),
      );
      found.push(...body.accounts.map(toAccount));
    }
    return found;
  }

  async getContact(identifier: string): Promise<AccountContact> {
    const body = await this.read(
      'profiles:read',
      { method: 'POST', path: '/service/accounts/contact', body: { identifier } },
      isContact,
    );
    return toContact(body);
  }

  async getContactById(userId: string): Promise<AccountContact | null> {
    const body = await this.readById('profiles:read', byId(userId, '/contact'), isContact);
    return body === NO_SUCH_ACCOUNT ? null : toContact(body);
  }

  async listRoles(query: ListQuery = {}): Promise<Page<ServiceRole>> {
    const body = await this.read(
      'roles:read',
      { method: 'GET', path: '/service/roles', query: { ...query } },
      pageOf(isRole),
    );
    return toPage(body, toRole);
  }

  async getAccountRoles(userId: string): Promise<ServiceRole[] | null> {
    const body = await this.readById('roles:read', byId(userId, '/roles'), field('roles', arrayOf(isRole)));
    return body === NO_SUCH_ACCOUNT ? null : body.roles.map(toRole);
  }

  async getAccountPermissions(userId: string): Promise<string[] | null> {
    const body = await this.readById(
      'permissions:read',
      byId(userId, '/permissions'),
      field('permissions', isStringArray),
    );
    return body === NO_SUCH_ACCOUNT ? null : [...body.permissions];
  }

  async listResourceTypes(query: ListQuery = {}): Promise<Page<ServiceResourceType>> {
    const body = await this.read(
      'permissions:read',
      { method: 'GET', path: '/service/resource-types', query: { ...query } },
      pageOf(isResourceType),
    );
    return toPage(body, toResourceType);
  }

  async revokeSessions(userId: string): Promise<boolean> {
    const answer = await sendToIam(this.options, { method: 'POST', path: byId(userId, '/sessions/revoke') });
    if (answer.status === 204) return true;
    if (answer.status === 404 && answer.errorBody.code === 'ACCOUNT_NOT_FOUND') return false;
    throw this.refusal('sessions:revoke', answer);
  }

  // ── the one place a status is given its meaning ───────────────────────────

  private async read<T>(permission: ServicePermission, call: IamCall, guard: Guard<T>): Promise<T> {
    const answer = await sendToIam(this.options, call);
    if (answer.status === 200) return this.accept(answer, guard);
    throw this.refusal(permission, answer);
  }

  private async readById<T>(
    permission: ServicePermission,
    path: string,
    guard: Guard<T>,
  ): Promise<T | typeof NO_SUCH_ACCOUNT> {
    const answer = await sendToIam(this.options, { method: 'GET', path });
    if (answer.status === 200) return this.accept(answer, guard);
    // Only this code: a 404 NOT_FOUND is an unknown route — a `baseUrl`
    // missing its prefix, or an IAM without these routes — and is ours to fix.
    if (answer.status === 404 && answer.errorBody.code === 'ACCOUNT_NOT_FOUND') {
      return NO_SUCH_ACCOUNT;
    }
    throw this.refusal(permission, answer);
  }

  private accept<T>(answer: IamAnswer, guard: Guard<T>): T {
    if (guard(answer.body)) return answer.body;
    throw new IamUnavailableError('IAM answered 200 with a body that is not the contract', answer.status);
  }

  private refusal(permission: ServicePermission, answer: IamAnswer): Error {
    const { status, errorBody } = answer;
    if (status === 403 && errorBody.code === 'API_KEY_PERMISSION_DENIED') {
      return new IamPermissionDeniedError(permission, errorBody);
    }
    if (status === 401) {
      return new IamMisconfigurationError(
        `IAM refused this service's credentials: ${errorBody.description ?? 'unauthorized'}`,
        status,
        errorBody,
      );
    }
    if (status === 429 || status >= 500) {
      return new IamUnavailableError(`IAM answered ${status}`, status, answer.retryAfterSeconds, errorBody);
    }
    // 400 (a request that failed validation), any other 403 or 404, and
    // anything else: this service is set up wrong, and no end user can fix it.
    return new IamMisconfigurationError(
      `IAM answered ${status}${errorBody.description ? `: ${errorBody.description}` : ''}`,
      status,
      errorBody,
    );
  }
}
