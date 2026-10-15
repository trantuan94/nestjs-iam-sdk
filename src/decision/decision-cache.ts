import type { AuthorizeResponse } from '../client/contract';

/**
 * Where decisions are reused from. Keys are opaque hashes; a value is a
 * decision the service gave (never an error).
 *
 * The service has no invalidation channel, so a cached decision outlives a
 * revoked token or a removed role for up to its TTL — which is why caching is
 * off by default and should stay short.
 */
export interface DecisionCache {
  get(key: string): Promise<AuthorizeResponse | undefined> | AuthorizeResponse | undefined;
  set(key: string, decision: AuthorizeResponse, ttlMs: number): Promise<void> | void;
}

interface Entry {
  decision: AuthorizeResponse;
  expiresAt: number;
}

/** A bounded LRU with per-entry expiry, for one process. */
export class InMemoryDecisionCache implements DecisionCache {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly maxEntries = 10_000,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new Error('InMemoryDecisionCache: maxEntries must be a positive integer');
    }
  }

  get(key: string): AuthorizeResponse | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Promote: Map iteration order is insertion order, so re-inserting marks it most recent.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.decision;
  }

  set(key: string, decision: AuthorizeResponse, ttlMs: number): void {
    if (ttlMs <= 0) return;
    this.entries.delete(key);
    this.entries.set(key, { decision, expiresAt: this.now() + ttlMs });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value as string;
      this.entries.delete(oldest);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}
