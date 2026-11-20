---
'@trantuan94/nestjs-iam-sdk': minor
---

Project services (nestjs-iam-service ADR-0070). A key bound to a project service syncs that service's resource types
only, and the SDK now reads what such a sync answers:

- `syncResourceTypes` takes `service: { name?, description? }` to describe the bound service, and answers `service`
  (`{ id, code, name }`, or `null` for a key bound to none).
- Two new outcomes: `adopted` (a type of no service, now the service's) and `conflict` (another service's type, left
  alone). **Upgrade before binding a key to a service**: earlier versions refuse them as an unknown answer.
- `listResourceTypes` answers each type's `serviceId`.
- `FakeIamServiceClient` takes `service` (the project service the fake key is bound to) and scopes its sync as IAM
  does; its `resourceTypes` seed takes an optional `serviceId` (`FakeResourceType`).
