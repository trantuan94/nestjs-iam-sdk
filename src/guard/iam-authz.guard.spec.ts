import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IamAuthz } from '../checker/iam-authz.service';
import { resolveOptions } from '../options';
import { IamAuthzGuard } from './iam-authz.guard';
import { AUTHORIZE_METADATA } from './metadata';

const handler = () => undefined;
Reflect.defineMetadata(AUTHORIZE_METADATA, [{ action: 'invoices:read', resource: { type: 'invoices' } }], handler);

const contextOf = (type: string, request: object = { headers: { authorization: 'Bearer t' } }, response = {}) =>
  ({
    getType: () => type,
    getHandler: () => handler,
    getClass: () => class {},
    switchToHttp: () => ({ getRequest: () => request, getResponse: () => response }),
  }) as unknown as ExecutionContext;

describe('IamAuthzGuard', () => {
  const options = resolveOptions({ baseUrl: 'http://iam.test', apiKey: 'k', global: true });

  it('lets RPC and WebSocket contexts through without asking IAM', async () => {
    const authorize = jest.fn();
    const guard = new IamAuthzGuard(new Reflector(), new IamAuthz(options, { authorize }), options);

    await expect(guard.canActivate(contextOf('rpc'))).resolves.toBe(true);
    await expect(guard.canActivate(contextOf('ws'))).resolves.toBe(true);
    expect(authorize).not.toHaveBeenCalled();
  });

  it('sets no Retry-After on a refusal that is not an outage', async () => {
    const authorize = jest.fn(() =>
      Promise.resolve({ allowed: false, userId: 'u', action: 'invoices:read', resourceType: 'invoices' }),
    );
    const setHeader = jest.fn();
    const guard = new IamAuthzGuard(new Reflector(), new IamAuthz(options, { authorize }), options);

    await expect(
      guard.canActivate(contextOf('http', { headers: { authorization: 'Bearer t' } }, { setHeader })),
    ).rejects.toMatchObject({ status: 403 });
    expect(setHeader).not.toHaveBeenCalled();
  });

  it('refuses a resolver that throws as misconfigured, without asking IAM', async () => {
    const throwing = () => undefined;
    Reflect.defineMetadata(
      AUTHORIZE_METADATA,
      [
        {
          action: 'invoices:read',
          resource: () => {
            throw new Error('no such header');
          },
        },
      ],
      throwing,
    );
    const authorize = jest.fn();
    const guard = new IamAuthzGuard(new Reflector(), new IamAuthz(options, { authorize }), options);
    const context = { ...contextOf('http'), getHandler: () => throwing } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 500 });
    expect(authorize).not.toHaveBeenCalled();
  });

  it('decides a request once, however many times it runs', async () => {
    const authorize = jest.fn(() =>
      Promise.resolve({ allowed: true, userId: 'u', action: 'invoices:read', resourceType: 'invoices' }),
    );
    const guard = new IamAuthzGuard(new Reflector(), new IamAuthz(options, { authorize }), options);
    const request = { headers: { authorization: 'Bearer t' } };

    await guard.canActivate(contextOf('http', request));
    await guard.canActivate(contextOf('http', request));

    expect(authorize).toHaveBeenCalledTimes(1);
  });
});
