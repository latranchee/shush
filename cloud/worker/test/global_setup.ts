// global_setup.ts
// Runs in Node (not workerd): starts a loopback echo upstream the worker
// under test forwards to. Mirrors tests/fixtures echo-server pattern used by
// the local proxy's e2e suite: the response reports exactly what arrived, so
// assertions can prove injection, stripping, and ?key= scrubbing.

import { createServer } from 'node:http';

export const ECHO_PORT = 18999;

export default async function setup(): Promise<() => Promise<void>> {
  const server = createServer((req, res) => {
    if (req.url && req.url.startsWith('/sse')) {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      res.write('data: one\n\n');
      res.write('data: two\n\n');
      res.write('data: [DONE]\n\n');
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          method: req.method,
          url: req.url,
          headers: req.headers,
          body_base64: Buffer.concat(chunks).toString('base64'),
        }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(ECHO_PORT, '127.0.0.1', resolve));
  return async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
}
