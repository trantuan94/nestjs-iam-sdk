# @trantuan94/nestjs-iam-sdk

NestJS integration for **nestjs-iam-service**'s authorization endpoint,
`POST /auth/authorize`. One module and one decorator let a resource service ask
IAM whether the end user may do something, and refuse the request if not.

```ts
@Get(':id')
@Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
findOne(@Param('id') id: string, @AuthorizedUser() userId: string) { … }
```

- **Fail-closed, with no option otherwise.** Only a decision IAM actually gave lets a
  request through. A timeout, a 5xx, a 429 or a body that isn't a decision are all refusals.
- **Express and Fastify** are both supported. The same test suite runs on each.
- **The identity is IAM's.** `@AuthorizedUser()` returns the `userId` IAM verified. This
  service never trusts the token's own claims.
- **Optional decision cache**, off by default, plus request coalescing, which is always on.
- **A testing entry point** so your specs need no IAM at all.

## Install

```bash
npm i @trantuan94/nestjs-iam-sdk
```

Peer dependencies are `@nestjs/common` and `@nestjs/core` 10 or 11, `reflect-metadata` and
`rxjs` 7. `@nestjs/swagger` is optional; when present, routes are documented. Node 20 or later
is required: the client uses the built-in `fetch`.

## Before you start

1. **Register the resource type in IAM** under your tenant's namespace, with its actions
   (`invoices` with `read`, `approve`, …). Its permission codes are `invoices:read` and so on.
   Grant them to roles.
2. **Create an API key** for this service (`POST /api-keys` as a user of your namespace), and
   keep it in a secret.
3. **Check IAM's rate limit.** nestjs-iam-service limits every route per caller IP, and that
   includes `/auth/authorize`, where the caller is *your service*. Every authorized request
   is one call, so size the limit for that, or turn on the cache below.

## Quick start

```ts
import { IamAuthzModule } from '@trantuan94/nestjs-iam-sdk';

@Module({
  imports: [
    IamAuthzModule.forRoot({
      baseUrl: 'https://iam.example.com/api/iam',
      apiKey: process.env.IAM_API_KEY!,
      global: true, // recommended: deny by default, see below
    }),
  ],
  controllers: [InvoicesController],
})
export class AppModule {}
```

Or asynchronously, from your config:

```ts
IamAuthzModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    baseUrl: config.getOrThrow('IAM_BASE_URL'),
    apiKey: config.getOrThrow('IAM_API_KEY'),
  }),
  global: true, // stated here, not in the factory: it decides which providers exist
});
```

Options are validated when the module is built. A missing key or a malformed URL fails the
boot, not the first request.

## Authorizing a route — `@Authorize(action, resource)`

`action` is the **full permission code**, `<resourceType>:<action>`. `resource` needs a `type`.
Every other attribute is passed to IAM's ABAC policies as `resource.<name>`.

```ts
import { Authorize, fromBody, fromHeader, fromParam } from '@trantuan94/nestjs-iam-sdk';

@Controller('invoices')
export class InvoicesController {
  @Get(':id')
  @Authorize('invoices:read', {
    type: 'invoices',
    id: fromParam('id'),
    namespaceId: fromHeader('x-tenant'), // see "Tenant isolation"
  })
  findOne() {}

  @Post()
  @Authorize('invoices:create', { type: 'invoices', amount: fromBody('amount') })
  create() {}

  // Several are ANDed, and asked in parallel.
  @Post(':id/send')
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
  @Authorize('emails:send', { type: 'emails' })
  send() {}

  // Or compute the whole resource.
  @Get('by-status')
  @Authorize('invoices:read', (req) => ({ type: 'invoices', status: req.query('status') }))
  byStatus() {}
}
```

| Resolver | Reads |
|---|---|
| `fromParam('id')` | a route parameter |
| `fromQuery('status')` | a query-string value |
| `fromHeader('x-tenant')` | a request header |
| `fromBody('invoice.ownerId')` | a body field, by dotted path |
| `fromRequest((req) => …)` | anything else |

An attribute that resolves to `undefined` is left out of the request, not sent as `null`.
A malformed action (`'read'` instead of `'invoices:read'`) or a missing `type` throws when the
class loads, not later on a request.

### Tenant isolation

If you send `resource.namespaceId`, the IAM namespace id of the **record**, IAM refuses any
user from another namespace before looking at permissions at all. For a custom resource type
that is the *only* thing comparing whose row it is, so send it whenever you know it.

## Checking the record itself — `@Authz()`

A guard runs before your handler has loaded anything. Rules about the record (who owns it,
how large it is, what state it is in) are checked inside the handler:

```ts
import { Authz, SkipAuthorize, type BoundAuthz } from '@trantuan94/nestjs-iam-sdk';

@Patch(':id/approve')
@SkipAuthorize('checked in the handler, against the loaded invoice')
async approve(@Param('id') id: string, @Authz() authz: BoundAuthz) {
  const invoice = await this.invoices.findById(id);
  await authz.assert('invoices:approve', {
    type: 'invoices',
    id,
    namespaceId: invoice.namespaceId,
    ownerId: invoice.createdBy,
    amount: invoice.amount,
  });
  // …
}
```

- `assert()` throws on a denial (403) and resolves with the decision.
- `check()` resolves `true` or `false`. A refused credential, a misconfiguration or an
  unavailable IAM **still throw** from `check()`, because rendering an outage as "not
  permitted" would hide it.
- Outside a controller, inject `IamAuthz` and pass the request: `iamAuthz.assert(req, action, resource)`.

## The user — `@AuthorizedUser()`

This is the `userId` IAM verified while deciding this request. It throws 401 if nothing has
been decided yet, and it never reads the token itself. `authorizationOf(req)` returns every
decision taken on the request.

## Deny by default — `global: true`

The guard becomes an `APP_GUARD`. An HTTP route with **neither** `@Authorize` **nor**
`@SkipAuthorize(reason)` answers 403, so a route someone forgot to protect is closed, not open.

```ts
@Controller('health')
@SkipAuthorize('liveness probe') // a reason is required
export class HealthController {}
```

At boot the module logs every exempt route with its reason, and warns about every route that
declares nothing. Only HTTP is guarded; RPC and WebSocket contexts pass through.

## What the client sees

| Situation | Default answer |
|---|---|
| No token on the request | **401** `MISSING_ACCESS_TOKEN`. IAM is not called |
| IAM refused the token: `INVALID_JWT`, `TOKEN_REVOKED`, MFA not completed | **401**, with IAM's `code`, so a client knows whether to sign in again or finish MFA |
| IAM said `allowed: false` | **403** |
| This service is misconfigured: API key invalid or of an inactive user, resource type not registered or owned by another tenant, payload rejected, wrong `baseUrl` | **500** `AUTHORIZATION_MISCONFIGURED`, logged at error level; no detail reaches the client |
| IAM unavailable: timeout, network error, 429, 5xx, a 200 that isn't a decision | **503** `AUTHORIZATION_UNAVAILABLE`, with `Retry-After` when IAM sent one |

When several requirements on one route fail differently, the client hears about its
credential first: signing in again may fix the rest.

Pass `exceptionFactory: (failure) => …` to render them your way. `failure.kind` is one of
`missing-token`, `unauthenticated`, `denied`, `misconfigured`, `unavailable` and
`undeclared-route`.

## Decision cache

```ts
IamAuthzModule.forRoot({ …, cache: { ttlMs: 3_000, maxEntries: 10_000 } })
```

- **Off by default, and for a reason:** IAM cannot tell your service that a token was revoked
  or a role removed. With the cache on, such a change takes up to `ttlMs` to reach you. Keep
  it short.
- Only decisions are cached, allowed or denied. Errors never are.
- The key is a SHA-256 digest of the token, action, resource and environment. The token is
  never stored in the clear.
- An entry never outlives the token's own `exp`.
- To share the cache across replicas, implement `DecisionCache` (`get` and `set(key, decision, ttlMs)`)
  over Redis and pass it as `cache.store`. A store that throws is treated as a miss.

Independently of the cache, concurrent identical checks share one call to IAM.

## Options

| Option | Default | |
|---|---|---|
| `baseUrl` | required | IAM's base URL **including its global prefix**, e.g. `…/api/iam` |
| `apiKey` | required | sent as `X-API-Key`; redacted from `JSON.stringify`, `inspect` and logs |
| `timeoutMs` | `2000` | per call; there is no retry |
| `cache` | `false` | see above |
| `tokenExtractor` | `bearer()` | also `fromTokenHeader('x-user-token')`, `firstOf(a, b)`, or your own `(req) => token` |
| `environment` | none | `(req) => ({ region })`, extra `env.*` attributes for ABAC |
| `onDecision` | none | `(event) => …`, one call per decision: action, type, allowed, userId, cached, latency, error. Never the token |
| `exceptionFactory` | see above | |
| `global` | `false` | deny by default |

The end user's IP is always sent as `environment.ip`, taken from `req.ip`. Neither the
options nor a call site can override it. Whether `req.ip` honours `X-Forwarded-For` is your
application's own `trust proxy` setting; the SDK does not read that header itself.

## Testing your service

```ts
import { IamAuthzTestingModule, FakeIamAuthzClient, allow, deny } from '@trantuan94/nestjs-iam-sdk/testing';

const moduleRef = await Test.createTestingModule({
  imports: [
    IamAuthzTestingModule.forRoot({
      rules: [deny('invoices:approve', { ownerId: 'u-1' }), allow('invoices:approve'), allow('invoices:read')],
      userId: 'u-1',
    }),
  ],
  controllers: [InvoicesController],
}).compile();

const iam = moduleRef.get(FakeIamAuthzClient);
iam.failWith('unavailable', 1); // the next call fails as IAM would
expect(iam.calls[0].resource).toMatchObject({ type: 'invoices', id: 'inv-1' });
```

The real guard and decorators run; only IAM is replaced. The first matching rule decides,
`allow('*')` matches any action, and anything no rule allows is denied.

## Compatibility

The request and response types are checked against a snapshot of nestjs-iam-service's
OpenAPI document (`contract/authorize.openapi.json`, refreshed with `npm run contract:update`).
The snapshot records the service revision it was taken from.

## License

MIT
