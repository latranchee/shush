// helpers.ts
// Shared plumbing for the worker specs: dispatch through the real entry
// point, seed loopback echo providers, and talk to AclDO directly.

import { env } from 'cloudflare:test';
import worker from '../src/index';
import type { Env } from '../src/env';

export const testEnv = env as unknown as Env;

// Must match TEST_ADMIN_TOKEN in vitest.config.ts (kept as a literal here so
// the workerd bundle never imports node:crypto).
export const ADMIN_TOKEN = 'test-admin-token-0123456789';

// Must match ECHO_PORT in global_setup.ts.
export const ECHO_BASE = 'http://127.0.0.1:18999';

export const WORKER_ORIGIN = 'https://shush-cloud.example.workers.dev';

export async function dispatch(request: Request, envOverride?: Record<string, unknown>): Promise<Response> {
  const e = envOverride ? ({ ...testEnv, ...envOverride } as unknown as Env) : testEnv;
  return await worker.fetch(request, e);
}

export function acl() {
  return testEnv.ACL.get(testEnv.ACL.idFromName('acl'));
}

export async function seedEchoProviders(): Promise<void> {
  await testEnv.SHUSH_KV.put(
    'cfg:providers',
    JSON.stringify({
      version: 1,
      providers: {
        echo: { secret: 'echo_key', auth: 'bearer', base_url: ECHO_BASE },
        gecho: { secret: 'gecho_key', auth: 'x-goog-api-key', base_url: ECHO_BASE },
        rawecho: { secret: 'echo_key', auth: 'raw', base_url: ECHO_BASE },
        nokey: { secret: 'missing_secret', auth: 'bearer', base_url: ECHO_BASE },
      },
    }),
  );
}

export async function newMachine(grants: string[], label = 'test-machine') {
  return await acl().createMachine(label, grants);
}

export function adminHeaders(extra?: Record<string, string>): Record<string, string> {
  return { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json', ...extra };
}

export interface EchoReply {
  method: string;
  url: string;
  headers: Record<string, string | string[]>;
  body_base64: string;
}
