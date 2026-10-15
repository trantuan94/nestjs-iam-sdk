/**
 * Single-flight: concurrent calls with the same key share one promise.
 *
 * Always on, cache or not. Unlike a cache it never serves a decision older
 * than the request asking for it — every caller gets the answer to a call made
 * after it arrived — so it cuts load without making anything stale.
 */
export class InFlight<T> {
  private readonly pending = new Map<string, Promise<T>>();

  run(key: string, work: () => Promise<T>): Promise<T> {
    const existing = this.pending.get(key);
    if (existing) return existing;
    const started = work().finally(() => this.pending.delete(key));
    this.pending.set(key, started);
    return started;
  }

  get size(): number {
    return this.pending.size;
  }
}
