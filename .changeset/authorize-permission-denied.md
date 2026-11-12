---
'@trantuan94/nestjs-iam-sdk': patch
---

A 403 `API_KEY_PERMISSION_DENIED` from `POST /auth/authorize` — the service's key not granted
`authorize:check`, which nestjs-iam-service requires since its ADR-0064 — is now an
`IamPermissionDeniedError` with `permission: 'authorize:check'`. It is still an
`IamMisconfigurationError`, so the guard answers it as before (500 `AUTHORIZATION_MISCONFIGURED`);
the error now names what to grant.
