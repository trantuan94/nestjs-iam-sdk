---
'@trantuan94/nestjs-iam-sdk': minor
---

`IamServiceClient.syncResourceTypes(types, { prune, dryRun })`: declare the resource types of the key's project
with `PUT /service/resource-types`, typically at boot — types created, actions added, name / description /
attributes set, and without `prune` nothing removed (what IAM has beyond the manifest is reported as
`undeclared`). Needs `resource-types:sync` (nestjs-iam-service's ADR-0066). `FakeIamServiceClient` applies a
manifest the same way and records it in `syncedResourceTypes`.

`authorizationRequirementsOf(handler)`: the `@Authorize` requirements on a handler, `{ action, resourceType }[]`,
for a service that documents what its routes enforce — an endpoint policy in Swagger, or a spec checking each
action is one it declares to IAM.
