import type { ServiceReadsClient } from '../service/iam-service.client';
import type {
  AccountContact,
  ListQuery,
  ResourceTypeDeclaration,
  ResourceTypeSync,
  ResourceTypeSyncOptions,
  ResourceTypeSyncResult,
  Page,
  ServiceAccount,
  ServicePermission,
  ServiceRef,
  ServiceResourceType,
  ServiceRole,
  TokenIntrospection,
} from '../service/contract';
import {
  IamMisconfigurationError,
  IamPermissionDeniedError,
  IamUnavailableError,
} from '../client/errors';

/** One account of the fake project: what IAM would know of it. */
export interface FakeServiceAccount extends Partial<Omit<ServiceAccount, 'id' | 'identifier'>> {
  id: string;
  identifier: string;
  contact?: Partial<AccountContact>;
  /** Codes of `roles` held by the account. */
  roles?: string[];
  /** The permission codes it holds. */
  permissions?: string[];
}

/** A resource type of the fake project; `serviceId` absent is a type of no service. */
export type FakeResourceType = Omit<ServiceResourceType, 'serviceId'> & { serviceId?: string | null };

export interface FakeServiceData {
  accounts?: FakeServiceAccount[];
  roles?: ServiceRole[];
  resourceTypes?: FakeResourceType[];
  /**
   * The project service the fake key is bound to, or `null` (the default): a key bound to none. A bound key's sync
   * converges only its service's types and adopts those of no service.
   */
  service?: ServiceRef | null;
  /** Token → its introspection. A token not listed is `{ active: false }`. */
  tokens?: Record<string, TokenIntrospection>;
  /**
   * The permissions the fake key holds. Default: every one. A call needing one
   * not listed fails with `IamPermissionDeniedError`, as IAM's 403 does.
   */
  permissions?: ServicePermission[];
}

export type FakeServiceFailure = 'misconfigured' | 'unavailable';

type FakeState = Required<Omit<FakeServiceData, 'resourceTypes'>> & { resourceTypes: ServiceResourceType[] };

const ALL: ServicePermission[] = [
  'tokens:introspect',
  'accounts:read',
  'profiles:read',
  'roles:read',
  'permissions:read',
  'sessions:revoke',
  'resource-types:sync',
];

/**
 * Stands in for IAM's *Service reads* in a resource service's tests. Holds one
 * project's accounts, roles and resource types in memory and answers as IAM
 * does: identifiers match ignoring case, an unknown id is `null`, a contact
 * with no address is `email: null`. Every call is recorded in `calls`.
 */
export class FakeIamServiceClient implements ServiceReadsClient {
  readonly calls: { method: keyof ServiceReadsClient; args: unknown[] }[] = [];
  /** The accounts `revokeSessions` signed out, in order. */
  readonly revokedSessions: string[] = [];
  /** Every manifest `syncResourceTypes` received, in order (a dry run is not one). */
  readonly syncedResourceTypes: ResourceTypeDeclaration[][] = [];
  private data: FakeState;
  private failure: { kind: FakeServiceFailure; remaining: number } | undefined;

  constructor(data: FakeServiceData = {}) {
    this.data = this.normalise(data);
  }

  /** Replace what the fake knows. */
  setData(data: FakeServiceData): this {
    this.data = this.normalise(data);
    return this;
  }

  /** The next `times` calls (default: all of them) fail the way IAM would. */
  failWith(kind: FakeServiceFailure, times = Number.POSITIVE_INFINITY): this {
    this.failure = { kind, remaining: times };
    return this;
  }

  reset(): this {
    this.calls.length = 0;
    this.revokedSessions.length = 0;
    this.syncedResourceTypes.length = 0;
    this.failure = undefined;
    return this;
  }

  async introspectToken(token: string): Promise<TokenIntrospection> {
    this.enter('introspectToken', 'tokens:introspect', [token]);
    return this.data.tokens[token] ?? { active: false };
  }

  async getAccount(userId: string): Promise<ServiceAccount | null> {
    this.enter('getAccount', 'accounts:read', [userId]);
    const account = this.byId(userId);
    return account ? this.toAccount(account) : null;
  }

  async lookupAccounts(identifiers: readonly string[]): Promise<ServiceAccount[]> {
    this.enter('lookupAccounts', 'accounts:read', [identifiers]);
    const wanted = new Set(identifiers.map((i) => i.trim().toLowerCase()));
    return [...wanted].flatMap((folded) => {
      const matches = this.data.accounts.filter((a) => a.identifier.toLowerCase() === folded);
      // Two accounts sharing an identifier by case alone answer none, as IAM's do.
      return matches.length === 1 ? [this.toAccount(matches[0]!)] : [];
    });
  }

  async getContact(identifier: string): Promise<AccountContact> {
    this.enter('getContact', 'profiles:read', [identifier]);
    const folded = identifier.trim().toLowerCase();
    const matches = this.data.accounts.filter((a) => a.identifier.toLowerCase() === folded);
    return matches.length === 1 ? this.toContact(matches[0]!) : this.noContact();
  }

  async getContactById(userId: string): Promise<AccountContact | null> {
    this.enter('getContactById', 'profiles:read', [userId]);
    const account = this.byId(userId);
    return account ? this.toContact(account) : null;
  }

  async listRoles(query: ListQuery = {}): Promise<Page<ServiceRole>> {
    this.enter('listRoles', 'roles:read', [query]);
    return this.page(this.data.roles, query, (r) => [r.code, r.name]);
  }

  async getAccountRoles(userId: string): Promise<ServiceRole[] | null> {
    this.enter('getAccountRoles', 'roles:read', [userId]);
    const account = this.byId(userId);
    if (!account) return null;
    const held = new Set(account.roles ?? []);
    return this.data.roles
      .filter((r) => held.has(r.code))
      .sort((a, b) => a.code.localeCompare(b.code));
  }

  async getAccountPermissions(userId: string): Promise<string[] | null> {
    this.enter('getAccountPermissions', 'permissions:read', [userId]);
    const account = this.byId(userId);
    return account ? [...new Set(account.permissions ?? [])].sort() : null;
  }

  async listResourceTypes(query: ListQuery = {}): Promise<Page<ServiceResourceType>> {
    this.enter('listResourceTypes', 'permissions:read', [query]);
    return this.page(this.data.resourceTypes, query, (t) => [t.code, t.name]);
  }

  async revokeSessions(userId: string): Promise<boolean> {
    this.enter('revokeSessions', 'sessions:revoke', [userId]);
    if (!this.byId(userId)) return false;
    this.revokedSessions.push(userId);
    return true;
  }

  /**
   * Applies the manifest to the fake's resource types as IAM does without `prune` — creates, adds actions, sets the
   * name and description — and answers what changed; a type it does not declare is `undeclared`. `prune` is only
   * echoed: the fake removes nothing. A dry run answers the same and changes nothing.
   *
   * Scoped to the key's service as IAM is: only the bound service's types (or, bound to none, the types of no
   * service) are converged and reported undeclared; a declared type of no service is `adopted` by a bound key; a
   * code another service holds is a `conflict`, left alone. Sending `service` with a key bound to none fails as
   * IAM's 400 does.
   */
  async syncResourceTypes(
    resourceTypes: readonly ResourceTypeDeclaration[],
    options: ResourceTypeSyncOptions = {},
  ): Promise<ResourceTypeSync> {
    this.enter('syncResourceTypes', 'resource-types:sync', [resourceTypes, options]);
    const bound = this.data.service;
    if (options.service && !bound) {
      throw new IamMisconfigurationError(
        'IAM answered 400: `service` describes the service a key is bound to; this key is bound to none',
        400,
      );
    }
    if (!options.dryRun) this.syncedResourceTypes.push(resourceTypes.map((t) => ({ ...t })));

    const serviceId = bound?.id ?? null;
    const owned = (t: ServiceResourceType) => t.serviceId === serviceId;
    const declared = new Set(resourceTypes.map((t) => t.code));
    const types = [...this.data.resourceTypes];
    const results = resourceTypes.map((declaration): ResourceTypeSyncResult => {
      const index = types.findIndex((t) => t.code === declaration.code);
      const current = types[index];
      const adopting = !!current && current.serviceId === null && serviceId !== null;
      if (current && !owned(current) && !adopting) {
        return {
          code: declaration.code,
          outcome: 'conflict',
          addedActions: [],
          removedActions: [],
          undeclaredActions: [],
          fieldsChanged: [],
        };
      }
      const allowedActions = [...new Set([...(current?.allowedActions ?? []), ...declaration.allowedActions])];
      const description =
        declaration.description === undefined ? (current?.description ?? null) : declaration.description;
      const fieldsChanged: ResourceTypeSyncResult['fieldsChanged'] = [];
      if (current && current.name !== declaration.name) fieldsChanged.push('name');
      if (current && current.description !== description) fieldsChanged.push('description');
      const addedActions = allowedActions.filter((a) => !current?.allowedActions.includes(a));
      const next: ServiceResourceType = {
        id: current?.id ?? `fake-${declaration.code}`,
        code: declaration.code,
        name: declaration.name,
        description,
        allowedActions,
        serviceId,
      };
      if (current) types[index] = next;
      else types.push(next);
      return {
        code: declaration.code,
        outcome: !current
          ? 'created'
          : adopting
            ? 'adopted'
            : addedActions.length || fieldsChanged.length
              ? 'updated'
              : 'unchanged',
        addedActions,
        removedActions: [],
        undeclaredActions: (current?.allowedActions ?? []).filter((a) => !declaration.allowedActions.includes(a)),
        fieldsChanged,
      };
    });
    const undeclared = this.data.resourceTypes
      .filter((t) => owned(t) && !declared.has(t.code))
      .sort((a, b) => a.code.localeCompare(b.code))
      .map(
        (t): ResourceTypeSyncResult => ({
          code: t.code,
          outcome: 'undeclared',
          addedActions: [],
          removedActions: [],
          undeclaredActions: [...t.allowedActions],
          fieldsChanged: [],
        }),
      );

    let service = bound && { ...bound };
    if (!options.dryRun) {
      this.data = { ...this.data, resourceTypes: types };
      if (service && options.service?.name !== undefined) {
        service = { ...service, name: options.service.name };
        this.data = { ...this.data, service };
      }
    }
    return {
      dryRun: !!options.dryRun,
      prune: !!options.prune,
      service,
      results: [...results, ...undeclared],
    };
  }

  // ── internals ─────────────────────────────────────────────────────────────

  private enter(method: keyof ServiceReadsClient, permission: ServicePermission, args: unknown[]): void {
    this.calls.push({ method, args });
    if (this.failure && this.failure.remaining > 0) {
      this.failure.remaining -= 1;
      throw this.failure.kind === 'unavailable'
        ? new IamUnavailableError('IAM answered 503', 503)
        : new IamMisconfigurationError("IAM refused this service's credentials: Invalid or expired API key", 401);
    }
    if (!this.data.permissions.includes(permission)) {
      throw new IamPermissionDeniedError(permission, { code: 'API_KEY_PERMISSION_DENIED' });
    }
  }

  private byId(userId: string): FakeServiceAccount | undefined {
    return this.data.accounts.find((a) => a.id === userId);
  }

  private toAccount(a: FakeServiceAccount): ServiceAccount {
    return {
      id: a.id,
      identifier: a.identifier,
      status: a.status ?? 'ACTIVE',
      isVerified: a.isVerified ?? true,
      createdAt: a.createdAt ?? '2026-01-01T00:00:00.000Z',
    };
  }

  private toContact(a: FakeServiceAccount): AccountContact {
    const status = a.status ?? 'ACTIVE';
    if ((status !== 'ACTIVE' && status !== 'CREATED') || !a.contact?.email) return this.noContact();
    return {
      email: a.contact.email,
      firstName: a.contact.firstName ?? null,
      lastName: a.contact.lastName ?? null,
    };
  }

  private noContact(): AccountContact {
    return { email: null, firstName: null, lastName: null };
  }

  private page<T>(items: T[], query: ListQuery, text: (item: T) => string[]): Page<T> {
    const term = query.searchKey?.toLowerCase();
    const matching = term
      ? items.filter((item) => text(item).some((t) => t.toLowerCase().includes(term)))
      : items;
    const limit = Math.min(Math.max(query.limit ?? 20, 1), 100);
    const page = Math.max(query.page ?? 1, 1);
    const totalPages = Math.ceil(matching.length / limit);
    return {
      data: matching.slice((page - 1) * limit, page * limit),
      total: matching.length,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1,
    };
  }

  private normalise(data: FakeServiceData): FakeState {
    return {
      accounts: data.accounts ?? [],
      roles: data.roles ?? [],
      resourceTypes: (data.resourceTypes ?? []).map((t) => ({ ...t, serviceId: t.serviceId ?? null })),
      tokens: data.tokens ?? {},
      permissions: data.permissions ?? ALL,
      service: data.service ?? null,
    };
  }
}
