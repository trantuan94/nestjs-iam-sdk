# @trantuan94/nestjs-iam-sdk

## 0.7.0

### Minor Changes

- fc03a40: Project services (nestjs-iam-service ADR-0070). A key bound to a project service syncs that service's resource types
  only, and the SDK now reads what such a sync answers:
  
  - `syncResourceTypes` takes `service: { name?, description? }` to describe the bound service, and answers `service`
    (`{ id, code, name }`, or `null` for a key bound to none).
  - Two new outcomes: `adopted` (a type of no service, now the service's) and `conflict` (another service's type, left
    alone). **Upgrade before binding a key to a service**: earlier versions refuse them as an unknown answer.
  - `listResourceTypes` answers each type's `serviceId`.
  - `FakeIamServiceClient` takes `service` (the project service the fake key is bound to) and scopes its sync as IAM
    does; its `resourceTypes` seed takes an optional `serviceId` (`FakeResourceType`).

### Patch Changes

- 6180115: No runtime dependencies. `changeset` and `version` had been listed as dependencies since 0.3.0 — npm packages unrelated
  to the SDK, which nothing in it imports (the release tooling is `@changesets/cli`, a dev dependency). `version` brought
  `request` 2.12.0 and with it critical and high advisories (`form-data` GHSA-fjxv-7rqg-78g4 and GHSA-hmw2-7cc7-3qxx,
  `mime` GHSA-wrvr-8mpx-r7pp, `request` GHSA-p8p7-x288-28g6) into every service that installs the SDK.

## 0.6.0

### Minor Changes

- ddac5be: **Breaking — needs nestjs-iam-service with its ADR-0068.** A resource's own data now goes under `attributes`,
  apart from the keys IAM reads: `{ type, id?, namespaceId?, ownerId?, attributes? }`. IAM's policies read it as
  `resource.attributes.<name>`, so an object field named `type` or `namespaceId` no longer collides with IAM's.
  `@Authorize` refuses any other key when it is applied (move a field into `attributes`); `projectId` is IAM's to
  set. `attributes` values may be resolvers too, and `attributes` is sent only when one resolves. `AuthorizeResource`
  changes accordingly, and `AUTHORIZE_RESOURCE_KEYS` lists its keys. `FakeIamAuthzClient` rules match a dotted path:
  `deny('invoices:approve', { 'attributes.status': 'void' })`.

## 0.5.0

### Minor Changes

- b3658c1: `IamServiceClient.syncResourceTypes(types, { prune, dryRun })`: declare the resource types of the key's project
  with `PUT /service/resource-types`, typically at boot — types created, actions added, name / description /
  attributes set, and without `prune` nothing removed (what IAM has beyond the manifest is reported as
  `undeclared`). Needs `resource-types:sync` (nestjs-iam-service's ADR-0066). `FakeIamServiceClient` applies a
  manifest the same way and records it in `syncedResourceTypes`.
  
  `authorizationRequirementsOf(handler)`: the `@Authorize` requirements on a handler, `{ action, resourceType }[]`,
  for a service that documents what its routes enforce — an endpoint policy in Swagger, or a spec checking each
  action is one it declares to IAM.

## 0.4.0

### Minor Changes

- 89f77eb: `IamServiceClient.revokeSessions(userId)`: sign an account of the key's project out everywhere — every
  session and every device's trust, as an operator's Revoke Sessions does — when a resource service sees a
  compromise. Needs `sessions:revoke` (nestjs-iam-service's ADR-0065); `true` once ended, `false` for no such
  account. `FakeIamServiceClient` records it in `revokedSessions`.

### Patch Changes

- 11219fb: A 403 `API_KEY_PERMISSION_DENIED` from `POST /auth/authorize` — the service's key not granted
  `authorize:check`, which nestjs-iam-service requires since its ADR-0064 — is now an
  `IamPermissionDeniedError` with `permission: 'authorize:check'`. It is still an
  `IamMisconfigurationError`, so the guard answers it as before (500 `AUTHORIZATION_MISCONFIGURED`);
  the error now names what to grant.

## 0.3.0

### Minor Changes

- c55159b: `IamServiceClient`: read nestjs-iam-service's `/service/*` routes with the same API key —
  `introspectToken`, `getAccount`, `lookupAccounts`, `getContact`, `getContactById`, `listRoles`,
  `getAccountRoles`, `getAccountPermissions`, `listResourceTypes`. Each needs a permission granted
  to the key; a missing one throws the new `IamPermissionDeniedError` (a subclass of
  `IamMisconfigurationError`) naming it. A by-id read answers `null` for no account of the key's
  project. `IamAuthzTestingModule` replaces it with `FakeIamServiceClient` (option `service`).
  
  Peer dependencies now accept Nest 12.

## 0.2.0

### Minor Changes

- e2c8448: `@AccessControl({ namespace, permissions })` and `applyAccessControlToSwagger(app)`: document a
  route's endpoint policy in its Swagger description, in nestjs-iam-service's format. Documentation
  only — it attaches no guard and never calls IAM; enforce with `@Authorize` / `@Authz()`.

## 0.1.0

### Minor Changes

- 6a4989b: First release: `IamAuthzModule`, `@Authorize` with request resolvers, `@Authz()` for
  record-level checks, `@AuthorizedUser()`, deny-by-default `global` mode with a boot-time
  route audit, an opt-in decision cache with request coalescing, OpenAPI documentation of
  requirements, and the `/testing` entry point. Fail-closed throughout.
