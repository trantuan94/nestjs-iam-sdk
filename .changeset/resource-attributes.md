---
'@trantuan94/nestjs-iam-sdk': minor
---

**Breaking — needs nestjs-iam-service with its ADR-0068.** A resource's own data now goes under `attributes`,
apart from the keys IAM reads: `{ type, id?, namespaceId?, ownerId?, attributes? }`. IAM's policies read it as
`resource.attributes.<name>`, so an object field named `type` or `namespaceId` no longer collides with IAM's.
`@Authorize` refuses any other key when it is applied (move a field into `attributes`); `projectId` is IAM's to
set. `attributes` values may be resolvers too, and `attributes` is sent only when one resolves. `AuthorizeResource`
changes accordingly, and `AUTHORIZE_RESOURCE_KEYS` lists its keys. `FakeIamAuthzClient` rules match a dotted path:
`deny('invoices:approve', { 'attributes.status': 'void' })`.
