import type { AuthorizeRequirement } from './metadata';

import type * as SwaggerModule from '@nestjs/swagger';

type Swagger = typeof SwaggerModule;

const API_EXTENSION = 'swagger/apiExtension';
const EXTENSION = 'x-iam-authorization';

let swagger: Swagger | null | undefined;

/** `@nestjs/swagger` when the app has it; `null` otherwise. It is an OPTIONAL peer. */
const loadSwagger = (): Swagger | null => {
  if (swagger === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      swagger = require('@nestjs/swagger') as Swagger;
    } catch {
      swagger = null;
    }
  }
  return swagger;
};

const requiredType = (requirement: AuthorizeRequirement): string => {
  const spec = requirement.resource;
  if (typeof spec === 'function') return requirement.action.split(':')[0] ?? 'resource';
  return typeof spec.type === 'string' ? spec.type : spec.type.describe;
};

/**
 * Documents a requirement in the OpenAPI document: the bearer scheme, the
 * three refusals, and an `x-iam-authorization` extension listing what the
 * route requires — an extension rather than the operation's description, which
 * belongs to the app (`@ApiOperation` would overwrite it, or be overwritten).
 */
export const applySwagger = (
  requirement: AuthorizeRequirement,
  target: object,
  key: string | symbol,
  descriptor: PropertyDescriptor,
): void => {
  const s = loadSwagger();
  if (!s) return;
  // Written directly: `ApiExtension` keeps the value already set for a key,
  // so a second `@Authorize` could never extend the list. The key is
  // @nestjs/swagger's `DECORATORS.API_EXTENSION`, which it does not export;
  // `authorize.decorator.spec.ts` fails if a release moves it.
  const extensions =
    (Reflect.getMetadata(API_EXTENSION, descriptor.value) as Record<string, unknown> | undefined) ?? {};
  const existing = extensions[EXTENSION];
  const entries = [
    ...(Array.isArray(existing) ? existing : []),
    { action: requirement.action, resourceType: requiredType(requirement) },
  ];
  Reflect.defineMetadata(API_EXTENSION, { ...extensions, [EXTENSION]: entries }, descriptor.value);

  const decorators: MethodDecorator[] = [
    s.ApiBearerAuth(),
    s.ApiUnauthorizedResponse({ description: 'No access token, or IAM refused it (code says which)' }),
    s.ApiForbiddenResponse({ description: `Requires ${entries.map((e) => `\`${e.action}\``).join(' and ')}` }),
    s.ApiServiceUnavailableResponse({ description: 'IAM could not be asked; the request is denied' }),
  ];
  for (const decorate of decorators) decorate(target, key, descriptor);
};
