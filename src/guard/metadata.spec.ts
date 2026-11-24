import { Authorize } from './authorize.decorator';
import { endpointPolicyOf } from './metadata';
import { SkipAuthorize } from './skip-authorize.decorator';

class Open {
  @SkipAuthorize('liveness probe')
  probe() {}

  @Authorize('reports:read', { type: 'reports' })
  read() {}

  plain() {}
}

@SkipAuthorize('public catalogue')
class Exempt {
  list() {}

  @SkipAuthorize('own reason')
  own() {}

  @Authorize('catalogue:write', { type: 'catalogue' })
  write() {}
}

describe('endpointPolicyOf', () => {
  it('a handler with @Authorize is authorized, with its requirements', () => {
    expect(endpointPolicyOf(Open.prototype.read, Open)).toEqual({
      kind: 'authorized',
      requirements: [{ action: 'reports:read', resourceType: 'reports' }],
    });
  });

  it("an exemption is the handler's, else its controller's", () => {
    expect(endpointPolicyOf(Open.prototype.probe, Open)).toEqual({ kind: 'exempt', reason: 'liveness probe' });
    expect(endpointPolicyOf(Exempt.prototype.list, Exempt)).toEqual({ kind: 'exempt', reason: 'public catalogue' });
    expect(endpointPolicyOf(Exempt.prototype.own, Exempt)).toEqual({ kind: 'exempt', reason: 'own reason' });
  });

  it("@Authorize wins over the controller's exemption, as in the guard", () => {
    expect(endpointPolicyOf(Exempt.prototype.write, Exempt).kind).toBe('authorized');
  });

  it('neither is undeclared, and so is something that is not a handler', () => {
    expect(endpointPolicyOf(Open.prototype.plain, Open)).toEqual({ kind: 'undeclared' });
    expect(endpointPolicyOf(undefined, undefined)).toEqual({ kind: 'undeclared' });
  });
});
