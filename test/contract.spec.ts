import snapshot from '../contract/authorize.openapi.json';
import {
  AUTHORIZE_REQUEST_KEYS,
  AUTHORIZE_REQUEST_REQUIRED,
  AUTHORIZE_RESPONSE_KEYS,
} from '../src/client/contract';

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
  properties?: Record<string, { type?: string }>;
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
