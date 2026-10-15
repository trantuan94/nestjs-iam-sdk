import { InMemoryDecisionCache } from './decision-cache';
import { cacheTtlFor, decisionKey, stableStringify, tokenExpiresAtMs } from './decision-key';
import { InFlight } from './in-flight';

const decision = (allowed = true) => ({ allowed, userId: 'u', action: 'a:b', resourceType: 'a' });

const jwt = (payload: object) =>
  `h.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.s`;

describe('InMemoryDecisionCache', () => {
  let now = 0;
  const cache = () => new InMemoryDecisionCache(2, () => now);

  beforeEach(() => (now = 1_000));

  it('answers until the entry expires, then misses', () => {
    const c = cache();
    c.set('k', decision(), 100);

    now = 1_099;
    expect(c.get('k')).toEqual(decision());
    now = 1_100;
    expect(c.get('k')).toBeUndefined();
  });

  it('evicts the least recently USED entry past its bound', () => {
    const c = cache();
    c.set('a', decision(), 1_000);
    c.set('b', decision(), 1_000);
    c.get('a'); // promote a: b is now the oldest
    c.set('c', decision(), 1_000);

    expect(c.get('a')).toBeDefined();
    expect(c.get('b')).toBeUndefined();
    expect(c.size).toBe(2);
  });

  it('stores nothing for a non-positive TTL', () => {
    const c = cache();
    c.set('k', decision(), 0);

    expect(c.get('k')).toBeUndefined();
  });

  it('refuses a nonsensical bound', () => {
    expect(() => new InMemoryDecisionCache(0)).toThrow();
  });
});

describe('decision key', () => {
  it('does not depend on attribute order', () => {
    const a = decisionKey({ token: 't', action: 'a:b', resource: { type: 'a', id: '1', x: { p: 1, q: 2 } } });
    const b = decisionKey({ resource: { x: { q: 2, p: 1 }, id: '1', type: 'a' }, action: 'a:b', token: 't' });

    expect(a).toBe(b);
  });

  it.each([
    ['token', { token: 'u' }],
    ['action', { action: 'a:c' }],
    ['resource', { resource: { type: 'a', id: '2' } }],
    ['environment', { environment: { ip: '10.0.0.2' } }],
  ])('differs when the %s differs', (_label, change) => {
    const base = { token: 't', action: 'a:b', resource: { type: 'a', id: '1' }, environment: { ip: '10.0.0.1' } };

    expect(decisionKey({ ...base, ...change })).not.toBe(decisionKey(base));
  });

  it('is a digest: the token does not appear in it', () => {
    expect(decisionKey({ token: 'secret-token', action: 'a:b', resource: { type: 'a' } })).not.toContain('secret');
  });

  it('hashes a null attribute, and tells it from an absent one', () => {
    // `null` is not in the declared type, but a resolver can still produce it.
    const withNull = { token: 't', action: 'a:b', resource: { type: 'a', namespaceId: null } } as never;

    expect(() => decisionKey(withNull)).not.toThrow();
    expect(decisionKey(withNull)).not.toBe(decisionKey({ token: 't', action: 'a:b', resource: { type: 'a' } }));
  });

  it('keeps array order: [a, b] is not [b, a]', () => {
    expect(stableStringify(['a', 'b'])).not.toBe(stableStringify(['b', 'a']));
    expect(stableStringify(['a', 'b'])).toBe('["a","b"]');
  });

  it('ignores undefined attributes, as JSON does', () => {
    expect(stableStringify({ a: 1, b: undefined })).toBe(stableStringify({ a: 1 }));
  });
});

describe('cache TTL', () => {
  it('is capped by the token lifetime left', () => {
    const now = 1_000_000;
    const token = jwt({ exp: (now + 2_000) / 1000 });

    expect(cacheTtlFor(token, 5_000, now)).toBe(2_000);
  });

  it('is zero for an expired token, so nothing is cached', () => {
    expect(cacheTtlFor(jwt({ exp: 1 }), 5_000, 10_000)).toBe(0);
  });

  it('is the configured TTL for a token it cannot read', () => {
    expect(cacheTtlFor('opaque', 5_000)).toBe(5_000);
    expect(tokenExpiresAtMs('a.%%%.c')).toBeUndefined();
    expect(tokenExpiresAtMs(jwt({ exp: 'soon' }))).toBeUndefined();
  });
});

describe('InFlight', () => {
  it('shares one call between concurrent identical requests', async () => {
    const inFlight = new InFlight<number>();
    let calls = 0;
    let release!: (n: number) => void;
    const work = () => {
      calls += 1;
      return new Promise<number>((resolve) => (release = resolve));
    };

    const a = inFlight.run('k', work);
    const b = inFlight.run('k', work);
    release(7);

    await expect(Promise.all([a, b])).resolves.toEqual([7, 7]);
    expect(calls).toBe(1);
    expect(inFlight.size).toBe(0);
  });

  it('starts a fresh call once the previous one settled, failure included', async () => {
    const inFlight = new InFlight<number>();
    await inFlight.run('k', () => Promise.reject(new Error('x'))).catch(() => undefined);

    await expect(inFlight.run('k', () => Promise.resolve(2))).resolves.toBe(2);
  });
});
