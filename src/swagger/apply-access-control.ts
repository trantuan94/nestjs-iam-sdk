import type { INestApplication } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, ModulesContainer } from '@nestjs/core';
import { accessControlOf, type AccessControlPolicy } from './access-control.decorator';

/** @nestjs/swagger's metadata key for `@ApiOperation`. Pinned behaviourally by the spec. */
const API_OPERATION = 'swagger/apiOperation';
const APPLIED = Symbol.for('@trantuan94/nestjs-iam-sdk:access-control-applied');

/** Exactly nestjs-iam-service's rendering, so the two Swagger UIs read alike. */
const renderPolicies = (policies: AccessControlPolicy[]): string =>
  policies
    .map(({ namespace, permissions }) => `Namespace ${namespace}: ${([] as string[]).concat(permissions).join(', ')}<br>`)
    .join('');

const discoveryOf = (app: INestApplication): DiscoveryService => {
  try {
    return app.get(DiscoveryService, { strict: false });
  } catch {
    // The app does not import IamAuthzModule (or DiscoveryModule): build one
    // over the same module graph.
    return new DiscoveryService(app.get(ModulesContainer));
  }
};

/**
 * Writes every `@AccessControl` policy into its operation's Swagger
 * description, under "***Endpoint policy***" — nestjs-iam-service's
 * `injectEndpointPolicyToSwaggerMetadata`, for a resource service.
 *
 * Call it BEFORE `SwaggerModule.createDocument`, which reads the metadata
 * this rewrites:
 *
 * ```ts
 * applyAccessControlToSwagger(app);
 * const document = SwaggerModule.createDocument(app, config);
 * ```
 *
 * Idempotent: a handler is rewritten once however often this runs. Harmless
 * in an app without @nestjs/swagger — it only writes metadata nobody reads.
 */
export const applyAccessControlToSwagger = (app: INestApplication): void => {
  const discovery = discoveryOf(app);
  const scanner = new MetadataScanner();

  for (const wrapper of discovery.getControllers()) {
    const instance = wrapper.instance as object | undefined;
    if (!instance) continue;
    const prototype = Object.getPrototypeOf(instance) as Record<string, unknown>;
    for (const name of scanner.getAllMethodNames(prototype)) {
      const handler = prototype[name] as object;
      const policies = accessControlOf(handler);
      if (!policies || Reflect.getMetadata(APPLIED, handler)) continue;

      const operation = (Reflect.getMetadata(API_OPERATION, handler) as { description?: string } | undefined) ?? {};
      Reflect.defineMetadata(
        API_OPERATION,
        {
          ...operation,
          description: `${operation.description ?? ''}<br><br>***Endpoint policy***<br>${renderPolicies(policies)}`,
        },
        handler,
      );
      Reflect.defineMetadata(APPLIED, true, handler);
    }
  }
};
