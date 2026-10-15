/**
 * The one place that knows an HTTP request comes from Express or Fastify.
 *
 * Both expose `headers` (lower-cased keys), `params`, `query`, `body` and `ip`
 * under the same names, so reading is uniform; WRITING a response header is
 * where they differ (`res.setHeader` vs `reply.header`). Nothing else in the
 * SDK touches a raw request or response.
 */
export interface HttpRequestView {
  header(name: string): string | undefined;
  param(name: string): string | undefined;
  query(name: string): unknown;
  body(): unknown;
  /** The client IP as the adapter resolved it — honouring the app's own `trust proxy` setting. */
  ip(): string | undefined;
  /** The underlying framework request, for resolvers that need something else. */
  readonly raw: unknown;
}

type Bag = Record<string, unknown> | undefined;

const field = (bag: unknown, name: string): unknown =>
  bag && typeof bag === 'object' ? (bag as Record<string, unknown>)[name] : undefined;

const firstString = (value: unknown): string | undefined => {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0];
  return undefined;
};

export const viewOf = (request: unknown): HttpRequestView => {
  const req = (request ?? {}) as {
    headers?: Bag;
    params?: Bag;
    query?: Bag;
    body?: unknown;
    ip?: string;
  };
  return {
    header: (name) => firstString(field(req.headers, name.toLowerCase())),
    param: (name) => firstString(field(req.params, name)),
    query: (name) => field(req.query, name),
    body: () => req.body,
    ip: () => (typeof req.ip === 'string' && req.ip ? req.ip : undefined),
    raw: request,
  };
};

/** Sets a response header on an Express `Response` or a Fastify `FastifyReply`; a no-op otherwise. */
export const setResponseHeader = (response: unknown, name: string, value: string): void => {
  const res = response as {
    setHeader?: (n: string, v: string) => void;
    header?: (n: string, v: string) => void;
    headersSent?: boolean;
    sent?: boolean;
  } | null;
  if (!res || res.headersSent || res.sent) return;
  if (typeof res.setHeader === 'function') res.setHeader(name, value);
  else if (typeof res.header === 'function') res.header(name, value);
};
