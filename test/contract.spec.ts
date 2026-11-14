import snapshot from '../contract/authorize.openapi.json';
import {
  AUTHORIZE_REQUEST_KEYS,
  AUTHORIZE_REQUEST_REQUIRED,
  AUTHORIZE_RESPONSE_KEYS,
} from '../src/client/contract';
import {
  ACCOUNT_LOOKUP_MAX,
  RESOURCE_TYPE_DECLARATION_KEYS,
  RESOURCE_TYPE_DECLARATION_REQUIRED,
  RESOURCE_TYPE_SYNC_MAX,
  RESOURCE_TYPE_SYNC_OUTCOMES,
  SERVICE_RESPONSE_KEYS,
  SERVICE_ROUTES,
} from '../src/service/contract';

/**
 * The SDK's idea of `POST /auth/authorize` against the service's own OpenAPI
 * document, as snapshotted by `npm run contract:update`.
 *
 * The SDK lives in its own repository, so nothing else notices when the
 * service's DTO changes: refreshing the snapshot is the moment that is found
 * out, and this is what turns it red.
 */
interface Schema {
  type?: string;
  properties?: Record<string, { type?: string; maxItems?: number; nullable?: boolean }>;
  enum?: string[];
  required?: string[];
}

const schemas = snapshot.components.schemas as unknown as Record<string, Schema>;
const operation = snapshot.paths['/auth/authorize'].post as unknown as {
  responses: Record<string, unknown>;
  security?: Record<string, unknown>[];
};

describe('contract with nestjs-iam-service', () => {
  const request = schemas['AuthorizeRequestDto']!;
  const response = schemas['AuthorizeResponseDto']!;

  it('sends exactly the request fields the service declares', () => {
    expect(Object.keys(request.properties ?? {}).sort()).toEqual([...AUTHORIZE_REQUEST_KEYS].sort());
  });

  it('treats as required exactly what the service requires', () => {
    expect([...(request.required ?? [])].sort()).toEqual([...AUTHORIZE_REQUEST_REQUIRED].sort());
  });

  it('agrees on the request field types', () => {
    expect(request.properties).toMatchObject({
      token: { type: 'string' },
      action: { type: 'string' },
      resource: { type: 'object' },
      environment: { type: 'object' },
    });
  });

  it('reads exactly the response fields the service declares, all required', () => {
    expect(Object.keys(response.properties ?? {}).sort()).toEqual([...AUTHORIZE_RESPONSE_KEYS].sort());
    expect([...(response.required ?? [])].sort()).toEqual([...AUTHORIZE_RESPONSE_KEYS].sort());
    expect(response.properties).toMatchObject({
      allowed: { type: 'boolean' },
      userId: { type: 'string' },
      action: { type: 'string' },
      resourceType: { type: 'string' },
    });
  });

  // The client decides allowed/denied only from a 200; anything else is a refusal.
  it('is answered 200, with the decision in the body', () => {
    expect(Object.keys(operation.responses)).toContain('200');
    expect(Object.keys(operation.responses)).not.toContain('201');
  });

  it('is authenticated by X-API-Key', () => {
    expect(JSON.stringify(operation.security ?? [])).toContain('X-API-Key');
  });

  it('declares the error envelope the client parses', () => {
    expect(Object.keys(schemas['ErrorResponseDto']?.properties ?? {})).toEqual(
      expect.arrayContaining(['statusCode', 'code', 'description']),
    );
  });
});

/**
 * The `/service/*` reads `IamServiceClient` calls (ADR-0063 in the service):
 * every route it calls exists with the method it uses, is keyed by X-API-Key
 * and answers 200, and every response field the client reads is one the
 * service declares — no more, no fewer.
 */
describe('contract with nestjs-iam-service: service reads', () => {
  const paths = snapshot.paths as unknown as Record<
    string,
    Record<string, { responses: Record<string, { description?: string }>; security?: unknown[] }>
  >;

  it.each(SERVICE_ROUTES.map((r) => [r.method.toUpperCase(), r.path, r] as const))(
    '%s %s exists, keyed by X-API-Key, answering what the client expects',
    (_, path, route) => {
      const operation = paths[path]?.[route.method];

      expect(operation).toBeDefined();
      expect(Object.keys(operation!.responses)).toContain(String(route.answers));
      expect(JSON.stringify(operation!.security ?? [])).toContain('X-API-Key');
    },
  );

  it.each(Object.entries(SERVICE_RESPONSE_KEYS))(
    'reads exactly the fields %s declares',
    (name, keys) => {
      expect(Object.keys(schemas[name]?.properties ?? {}).sort()).toEqual([...keys].sort());
    },
  );

  it('answers a by-id miss ACCOUNT_NOT_FOUND, the one 404 the client reads as null', () => {
    const byId = SERVICE_ROUTES.filter((r) => r.path.includes('{userId}'));

    expect(byId.length).toBeGreaterThan(0);
    for (const route of byId) {
      expect(paths[route.path]![route.method]!.responses['404']?.description).toContain('ACCOUNT_NOT_FOUND');
    }
  });

  it('caps a lookup at the size the client batches by', () => {
    expect(schemas['AccountLookupRequestDto']?.properties?.['identifiers']?.maxItems).toBe(ACCOUNT_LOOKUP_MAX);
  });
});

describe('contract with nestjs-iam-service: resource type sync', () => {
  it('declares a type with exactly the fields the service takes, requiring the same ones', () => {
    const declaration = schemas['ResourceTypeDeclarationDto'];

    expect(Object.keys(declaration?.properties ?? {}).sort()).toEqual([...RESOURCE_TYPE_DECLARATION_KEYS].sort());
    expect([...(declaration?.required ?? [])].sort()).toEqual([...RESOURCE_TYPE_DECLARATION_REQUIRED].sort());
  });

  it('sends a manifest and prune, the manifest required', () => {
    expect(Object.keys(schemas['SyncResourceTypesDto']?.properties ?? {}).sort()).toEqual(['prune', 'resourceTypes']);
    expect(schemas['SyncResourceTypesDto']?.required).toEqual(['resourceTypes']);
  });

  it('caps a manifest at the size the client refuses beyond', () => {
    expect(schemas['SyncResourceTypesDto']?.properties?.['resourceTypes']?.maxItems).toBe(RESOURCE_TYPE_SYNC_MAX);
  });

  it('knows every outcome the service answers, and no other', () => {
    expect([...(schemas['ResourceTypeSyncOutcome']?.enum ?? [])].sort()).toEqual(
      [...RESOURCE_TYPE_SYNC_OUTCOMES].sort(),
    );
  });
});
