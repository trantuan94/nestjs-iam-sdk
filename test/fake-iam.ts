import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RecordedCall {
  path: string;
  headers: IncomingHttpHeaders;
  body: any;
}

export interface FakeAnswer {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  /** Answer only after this long — to exercise the client's timeout. */
  delayMs?: number;
  /** Send this raw text instead of JSON. */
  raw?: string;
}

/**
 * nestjs-iam-service's `/auth/authorize`, faked over real HTTP, so the client's
 * `fetch`, timeout and parsing run for real. `answer` decides per call; by
 * default it allows, echoing the action and type as the service does.
 */
export class FakeIam {
  readonly calls: RecordedCall[] = [];
  answer: (call: RecordedCall) => FakeAnswer = (call) => ({
    status: 200,
    body: { allowed: true, userId: 'user-1', action: call.body.action, resourceType: call.body.resource?.type },
  });
  private server: Server | undefined;

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        let body: unknown;
        try {
          body = JSON.parse(data);
        } catch {
          body = data;
        }
        const call: RecordedCall = { path: req.url ?? '', headers: req.headers, body };
        this.calls.push(call);
        const answer = this.answer(call);
        const send = () => {
          if (res.destroyed) return;
          res.writeHead(answer.status, { 'content-type': 'application/json', ...(answer.headers ?? {}) });
          res.end(answer.raw ?? (answer.body === undefined ? '' : JSON.stringify(answer.body)));
        };
        if (answer.delayMs) setTimeout(send, answer.delayMs);
        else send();
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const { port } = this.server.address() as AddressInfo;
    return `http://127.0.0.1:${port}/api/iam`;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }

  reset(): void {
    this.calls.length = 0;
    this.answer = new FakeIam().answer;
  }
}

/** The service's error envelope, as `CustomExceptionsFilter` renders it. */
export const iamError = (statusCode: number, code: string, description: string) => ({
  statusCode,
  code,
  errorCode: '9300000',
  message: code,
  description,
  path: '/api/iam/auth/authorize',
  method: 'POST',
  timestamp: new Date().toISOString(),
  requestId: '0192f0aa-0000-7000-8000-000000000000',
});
