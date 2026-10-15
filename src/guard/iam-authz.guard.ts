import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IamAuthz } from '../checker/iam-authz.service';
import { AuthzFailureSignal, retryAfterOf } from '../checker/failure';
import { recordDecision } from '../checker/request-decisions';
import { setResponseHeader, viewOf } from '../http/request-adapter';
import { IAM_AUTHZ_OPTIONS, type AuthzFailure, type ResolvedIamAuthzOptions } from '../options';
import { AUTHORIZE_METADATA, SKIP_AUTHORIZE_METADATA, type AuthorizeRequirement } from './metadata';
import { resolveResource } from './resolvers';
import type { AuthorizeResource } from '../client/contract';
import { IamMisconfigurationError } from '../client/errors';

/** Requests this guard has already decided; weak, so a finished request is collected. */
const EVALUATED = new WeakSet<object>();

/**
 * Enforces `@Authorize`. On a route it is attached to by the decorator; with
 * `global: true` it is also an APP_GUARD, and then an HTTP route that declares
 * neither `@Authorize` nor `@SkipAuthorize` is refused.
 *
 * Order: token → resource → IAM → record → allowed? Every requirement must be
 * allowed; they are asked in parallel, and the first failure decides the
 * answer (a credential problem outranks a denial, so a client is told to sign
 * in again rather than that it lacks a permission it may well hold).
 */
@Injectable()
export class IamAuthzGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authz: IamAuthz,
    @Inject(IAM_AUTHZ_OPTIONS) private readonly options: ResolvedIamAuthzOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // RPC and WebSocket contexts carry no HTTP request; this SDK authorizes HTTP only.
    if (context.getType() !== 'http') return true;

    // With `global: true` this guard runs twice on a decorated route: once as
    // the APP_GUARD, once as the guard `@Authorize` attaches (the decorator
    // cannot know the module's mode). The first run decides — it throws on any
    // refusal — so a second run on the same request has nothing left to do.
    const request = context.switchToHttp().getRequest<object>();
    if (EVALUATED.has(request)) return true;
    EVALUATED.add(request);

    const requirements =
      this.reflector.get<AuthorizeRequirement[] | undefined>(AUTHORIZE_METADATA, context.getHandler()) ?? [];

    if (requirements.length === 0) {
      const skipped = this.reflector.getAllAndOverride<string | undefined>(SKIP_AUTHORIZE_METADATA, [
        context.getHandler(),
        context.getClass(),
      ]);
      if (skipped !== undefined || !this.options.global) return true;
      this.refuse(context, { kind: 'undeclared-route' });
    }

    const view = viewOf(request);

    const outcomes = await Promise.allSettled(
      requirements.map(async ({ action, resource }) =>
        this.authz.decideOrSignal(view, action, await this.resolve(action, resource, view)),
      ),
    );

    const failures = outcomes.flatMap((o) =>
      o.status === 'rejected' ? [o.reason as AuthzFailureSignal] : [],
    );
    if (failures.length > 0) this.refuse(context, this.mostSevere(failures));

    const decisions = outcomes.flatMap((o) => (o.status === 'fulfilled' ? [o.value] : []));
    for (const decision of decisions) recordDecision(request, decision);

    const denied = decisions.find((d) => !d.allowed);
    if (denied) this.refuse(context, { kind: 'denied', decision: denied });
    return true;
  }

  /** A resolver that throws is a bug in the route, not a decision: refused as misconfigured. */
  private async resolve(
    action: string,
    spec: AuthorizeRequirement['resource'],
    view: ReturnType<typeof viewOf>,
  ): Promise<AuthorizeResource> {
    try {
      return await resolveResource(spec, view);
    } catch (error) {
      throw new AuthzFailureSignal({
        kind: 'misconfigured',
        error: new IamMisconfigurationError(
          `The resource of '${action}' could not be resolved: ${(error as Error)?.message ?? String(error)}`,
        ),
      });
    }
  }

  /** Which failure the client hears about when several requirements failed differently. */
  private mostSevere(signals: AuthzFailureSignal[]): AuthzFailure {
    const rank: Record<AuthzFailure['kind'], number> = {
      'missing-token': 0,
      unauthenticated: 1,
      misconfigured: 2,
      unavailable: 3,
      'undeclared-route': 4,
      denied: 5,
    };
    return signals
      .map((s) => s.failure)
      .sort((a, b) => rank[a.kind] - rank[b.kind])[0] as AuthzFailure;
  }

  private refuse(context: ExecutionContext, failure: AuthzFailure): never {
    const retryAfter = retryAfterOf(failure);
    if (retryAfter !== undefined) {
      setResponseHeader(context.switchToHttp().getResponse(), 'Retry-After', String(retryAfter));
    }
    throw this.authz.exceptionFor(failure);
  }
}
