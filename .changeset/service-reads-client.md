---
'@trantuan94/nestjs-iam-sdk': minor
---

`IamServiceClient`: read nestjs-iam-service's `/service/*` routes with the same API key —
`introspectToken`, `getAccount`, `lookupAccounts`, `getContact`, `getContactById`, `listRoles`,
`getAccountRoles`, `getAccountPermissions`, `listResourceTypes`. Each needs a permission granted
to the key; a missing one throws the new `IamPermissionDeniedError` (a subclass of
`IamMisconfigurationError`) naming it. A by-id read answers `null` for no account of the key's
project. `IamAuthzTestingModule` replaces it with `FakeIamServiceClient` (option `service`).

Peer dependencies now accept Nest 12.
