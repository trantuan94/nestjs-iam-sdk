import { inspect } from 'node:util';
import { resolveOptions, Secret } from './options';

describe('resolveOptions — checked at boot', () => {
  const base = { baseUrl: 'https://iam.example.com/api/iam/', apiKey: 'iam_key' };

  it('normalises the base URL and defaults the timeout', () => {
    const resolved = resolveOptions(base);

    expect(resolved.baseUrl).toBe('https://iam.example.com/api/iam');
    expect(resolved.timeoutMs).toBe(2000);
  });

  it.each([
    [{ ...base, apiKey: '' }, /apiKey/],
    [{ ...base, apiKey: '   ' }, /apiKey/],
    [{ ...base, baseUrl: 'iam.example.com' }, /baseUrl/],
    [{ ...base, baseUrl: 'ftp://iam.example.com' }, /http/],
    [{ ...base, timeoutMs: 0 }, /timeoutMs/],
    [{ ...base, cache: { ttlMs: -1 } }, /ttlMs/],
  ])('refuses %j', (options, message) => {
    expect(() => resolveOptions(options as never)).toThrow(message);
  });
});

describe('Secret', () => {
  it('prints as [redacted] every way a value gets printed', () => {
    const secret = new Secret('iam_live_value');
    const holder = { apiKey: secret };

    expect(JSON.stringify(holder)).not.toContain('iam_live_value');
    expect(inspect(holder)).not.toContain('iam_live_value');
    expect(`${secret}`).toBe('[redacted]');
    expect(secret.reveal()).toBe('iam_live_value');
  });
});
