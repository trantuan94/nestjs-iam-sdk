---
'@trantuan94/nestjs-iam-sdk': minor
---

`IamServiceClient.revokeSessions(userId)`: sign an account of the key's project out everywhere — every
session and every device's trust, as an operator's Revoke Sessions does — when a resource service sees a
compromise. Needs `sessions:revoke` (nestjs-iam-service's ADR-0065); `true` once ended, `false` for no such
account. `FakeIamServiceClient` records it in `revokedSessions`.
