import { Inject, Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import { IAM_AUTHZ_OPTIONS, type ResolvedIamAuthzOptions } from '../options';
import { AUTHORIZE_METADATA, SKIP_AUTHORIZE_METADATA } from './metadata';

export interface AuditedRoute {
  controller: string;
  handler: string;
  status: 'authorized' | 'skipped' | 'undeclared';
  reason?: string;
}

/**
 * In `global` mode, lists at boot every route that is exempt (with its reason)
 * and every route that declares nothing — which the guard will refuse with
 * 403. Nothing is silently open, and nothing is silently broken.
 */
@Injectable()
export class RouteAudit implements OnApplicationBootstrap {
  private readonly logger = new Logger('IamAuthz');

  constructor(
    private readonly discovery: DiscoveryService,
    private readonly scanner: MetadataScanner,
    private readonly reflector: Reflector,
    @Inject(IAM_AUTHZ_OPTIONS) private readonly options: ResolvedIamAuthzOptions,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.options.global) return;
    const routes = this.routes();
    for (const route of routes.filter((r) => r.status === 'skipped')) {
      this.logger.log(`Not authorized by IAM: ${route.controller}.${route.handler} — ${route.reason}`);
    }
    for (const route of routes.filter((r) => r.status === 'undeclared')) {
      this.logger.warn(
        `${route.controller}.${route.handler} declares neither @Authorize nor @SkipAuthorize: it will answer 403`,
      );
    }
  }

  routes(): AuditedRoute[] {
    const found: AuditedRoute[] = [];
    for (const wrapper of this.discovery.getControllers()) {
      const instance = wrapper.instance as object | undefined;
      if (!instance) continue;
      const prototype = Object.getPrototypeOf(instance) as object;
      const controller = wrapper.metatype as unknown as object;
      for (const name of this.scanner.getAllMethodNames(prototype)) {
        const handler = (prototype as Record<string, unknown>)[name] as object;
        if (Reflect.getMetadata(METHOD_METADATA, handler) === undefined) continue;
        if (Reflect.getMetadata(PATH_METADATA, handler) === undefined) continue;
        const requirements = this.reflector.get<unknown[] | undefined>(AUTHORIZE_METADATA, handler as never);
        const reason = this.reflector.getAllAndOverride<string | undefined>(SKIP_AUTHORIZE_METADATA, [
          handler as never,
          controller as never,
        ]);
        found.push({
          controller: wrapper.name,
          handler: name,
          status: requirements?.length ? 'authorized' : reason !== undefined ? 'skipped' : 'undeclared',
          ...(reason !== undefined && !requirements?.length ? { reason } : {}),
        });
      }
    }
    return found;
  }
}
