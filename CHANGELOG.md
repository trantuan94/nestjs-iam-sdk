# @trantuan94/nestjs-iam-sdk

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
