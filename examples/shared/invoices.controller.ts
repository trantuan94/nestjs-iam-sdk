import { Body, Controller, Get, Param, Patch, Post } from '@nestjs/common';
import {
  Authorize,
  AuthorizedUser,
  Authz,
  BoundAuthz,
  fromBody,
  fromHeader,
  fromParam,
  SkipAuthorize,
} from '../../src';

/** What a resource service's own repository would return. */
const INVOICES: Record<string, { namespaceId: string; createdBy: string; amount: number }> = {
  'inv-1': { namespaceId: 'ns-acme', createdBy: 'user-2', amount: 1500 },
};

/**
 * A resource service's controller, in the shapes the README documents. The
 * e2e suite boots it on Express and on Fastify and runs the same cases.
 */
@Controller('invoices')
export class InvoicesController {
  @Get(':id')
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id'), namespaceId: fromHeader('x-tenant') })
  findOne(@Param('id') id: string, @AuthorizedUser() userId: string) {
    return { id, readBy: userId };
  }

  @Post()
  @Authorize('invoices:create', { type: 'invoices', amount: fromBody('amount') })
  create(@Body() body: { amount: number }) {
    return { created: true, amount: body.amount };
  }

  /** Two requirements: both must be allowed. */
  @Post(':id/send')
  @Authorize('invoices:read', { type: 'invoices', id: fromParam('id') })
  @Authorize('emails:send', { type: 'emails' })
  send(@Param('id') id: string) {
    return { sent: id };
  }

  /** Record-level: ownership and amount are only known once the invoice is loaded. */
  @Patch(':id/approve')
  @SkipAuthorize('checked in the handler, against the loaded invoice')
  async approve(@Param('id') id: string, @Authz() authz: BoundAuthz) {
    const invoice = INVOICES[id];
    const decision = await authz.assert('invoices:approve', {
      type: 'invoices',
      id,
      namespaceId: invoice?.namespaceId,
      ownerId: invoice?.createdBy,
      amount: invoice?.amount,
    });
    return { approved: id, by: decision.userId };
  }

  @Get()
  undeclared() {
    return { listed: true };
  }
}

@Controller('health')
@SkipAuthorize('liveness probe')
export class HealthController {
  @Get()
  health() {
    return { ok: true };
  }
}
