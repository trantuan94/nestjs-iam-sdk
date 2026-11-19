---
'@trantuan94/nestjs-iam-sdk': patch
---

No runtime dependencies. `changeset` and `version` had been listed as dependencies since 0.3.0 — npm packages unrelated
to the SDK, which nothing in it imports (the release tooling is `@changesets/cli`, a dev dependency). `version` brought
`request` 2.12.0 and with it critical and high advisories (`form-data` GHSA-fjxv-7rqg-78g4 and GHSA-hmw2-7cc7-3qxx,
`mime` GHSA-wrvr-8mpx-r7pp, `request` GHSA-p8p7-x288-28g6) into every service that installs the SDK.
