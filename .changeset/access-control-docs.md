---
'@trantuan94/nestjs-iam-sdk': minor
---

`@AccessControl({ namespace, permissions })` and `applyAccessControlToSwagger(app)`: document a
route's endpoint policy in its Swagger description, in nestjs-iam-service's format. Documentation
only — it attaches no guard and never calls IAM; enforce with `@Authorize` / `@Authz()`.
