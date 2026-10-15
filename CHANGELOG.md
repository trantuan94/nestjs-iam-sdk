# @trantuan94/nestjs-iam-sdk

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
