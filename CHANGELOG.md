# @trantuan94/nestjs-iam-sdk

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
