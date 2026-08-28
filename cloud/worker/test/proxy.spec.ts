// proxy.spec.ts
// The proxy path invariants: injection, extraction==strip, ?key= scrub,
// method allowlist, body cap, streaming, fail-closed bootstrap, redaction.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ECHO_BASE, WORKER_ORIGIN, adminHeaders, dispatch, newMachine, seedEchoProviders, type EchoReply } from './helpers';

let machineToken = '';

beforeEach(async () => {
  await seedEchoProviders();
  const created = await newMachine(['echo', 'gecho', 'rawecho', 'nokey']);
  machineToken = created.token;
});

async function echoRequest(init: RequestInit & { path?: string; token?: string | null }): Promise<Response> {
  const token = init.token === undefined ? machineToken : init.token;
  const headers = new Headers(init.headers);
  if (token !== null && !headers.has('authorization') && !headers.has('x-api-key') && !headers.has('x-goog-api-key') && !headers.has('api-key')) {
    headers.set('authorization', `Bearer ${token}`);
  }
  return await dispatch(new Request(`${WORKER_ORIGIN}${init.path ?? '/echo/v1/test'}`, { ...init, headers }));
}

describe('credential injection and stripping', () => {
  it('injects the provider secret and strips every client credential header plus cookie', async () => {
    const resp = await echoRequest({
      method: 'POST',
      path: '/echo/v1/complete?foo=bar',
      headers: {
        'authorization': `Bearer ${machineToken}`,
        'x-api-key': 'client-supplied-1',
        'x-goog-api-key': 'client-supplied-2',
        'api-key': 'client-supplied-3',
        'cookie': 'session=stolen',
        'content-type': 'application/json',
        'x-custom-app': 'passes-through',
      },
      body: JSON.stringify({ hello: 'world' }),
    });
    expect(resp.status).toBe(200);
    const echo = (await resp.json()) as EchoReply;
    expect(echo.method).toBe('POST');
    expect(echo.url).toBe('/v1/complete?foo=bar');
    expect(echo.headers['authorization']).toBe('Bearer echo-secret-value');
    expect(echo.headers['x-api-key']).toBeUndefined();
    expect(echo.headers['x-goog-api-key']).toBeUndefined();
    expect(echo.headers['api-key']).toBeUndefined();
    expect(echo.headers['cookie']).toBeUndefined();
    expect(echo.headers['x-custom-app']).toBe('passes-through');
    // The machine token itself must never reach the upstream in any form.
    expect(JSON.stringify(echo)).not.toContain(machineToken.split('.')[2]);
  });

  it('extraction list equals strip list: token is accepted from each credential header', async () => {
    for (const header of ['authorization', 'x-api-key', 'x-goog-api-key', 'api-key']) {
      const value = header === 'authorization' ? `Bearer ${machineToken}` : machineToken;
      const resp = await dispatch(
        new Request(`${WORKER_ORIGIN}/echo/v1/models`, { headers: { [header]: value } }),
      );
      expect(resp.status, `token via ${header}`).toBe(200);
      const echo = (await resp.json()) as EchoReply;
      expect(JSON.stringify(echo.headers)).not.toContain(machineToken.split('.')[2]);
    }
  });

  it('accepts the token via ?key= and scrubs it from the upstream query (Gemini pattern)', async () => {
    const resp = await dispatch(
      new Request(`${WORKER_ORIGIN}/gecho/v1beta/models?key=${machineToken}&alt=sse`),
    );
    expect(resp.status).toBe(200);
    const echo = (await resp.json()) as EchoReply;
    expect(echo.url).toBe('/v1beta/models?alt=sse');
    expect(echo.headers['x-goog-api-key']).toBe('gecho-secret-value');
    expect(JSON.stringify(echo)).not.toContain(machineToken.split('.')[2]);
  });

  it('raw auth mode sends the bare key in Authorization', async () => {
    const resp = await echoRequest({ path: '/rawecho/v1/anything', method: 'GET' });
    const echo = (await resp.json()) as EchoReply;
    expect(echo.headers['authorization']).toBe('echo-secret-value');
  });
});

describe('routing and limits', () => {
  it('401 without any token', async () => {
    const resp = await echoRequest({ token: null });
    expect(resp.status).toBe(401);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('UNAUTHORIZED');
  });

  it('401 on malformed token', async () => {
    const resp = await echoRequest({ token: 'sk-not-a-machine-token' });
    expect(resp.status).toBe(401);
  });

  it('404 on unknown provider', async () => {
    const resp = await echoRequest({ path: '/nonexistent/v1/x' });
    expect(resp.status).toBe(404);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('PROVIDER_NOT_FOUND');
  });

  it('405 on method outside the allowlist', async () => {
    const resp = await echoRequest({ method: 'DELETE' });
    expect(resp.status).toBe(405);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  it('403 PROVIDER_NOT_GRANTED for a machine without the grant', async () => {
    const ungranted = await newMachine(['gecho'], 'narrow');
    const resp = await echoRequest({ token: ungranted.token });
    expect(resp.status).toBe(403);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('PROVIDER_NOT_GRANTED');
  });

  it('413 when Content-Length exceeds the cap', async () => {
    const resp = await echoRequest({
      method: 'POST',
      headers: { 'content-length': String(50 * 1024 * 1024) },
      body: 'small',
    });
    expect(resp.status).toBe(413);
  });

  it('502 SECRET_UNAVAILABLE when the SK_ binding is missing', async () => {
    const resp = await echoRequest({ path: '/nokey/v1/x' });
    expect(resp.status).toBe(502);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('SECRET_UNAVAILABLE');
  });

  it('501 UPGRADE_UNSUPPORTED on websocket upgrade', async () => {
    const resp = await echoRequest({ headers: { upgrade: 'websocket' } });
    expect(resp.status).toBe(501);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('UPGRADE_UNSUPPORTED');
  });
});

describe('fail-closed bootstrap', () => {
  it('503 NOT_CONFIGURED on the proxy path without ADMIN_TOKEN_HASH', async () => {
    const resp = await dispatch(new Request(`${WORKER_ORIGIN}/echo/v1/x`), { ADMIN_TOKEN_HASH: undefined });
    expect(resp.status).toBe(503);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('NOT_CONFIGURED');
  });

  it('503 NOT_CONFIGURED on the admin API without ADMIN_TOKEN_HASH', async () => {
    const resp = await dispatch(
      new Request(`${WORKER_ORIGIN}/api/status`, { headers: adminHeaders() }),
      { ADMIN_TOKEN_HASH: undefined },
    );
    expect(resp.status).toBe(503);
  });
});

describe('streaming', () => {
  it('relays SSE bodies', async () => {
    const resp = await echoRequest({ path: '/echo/sse' });
    expect(resp.status).toBe(200);
    expect(resp.headers.get('content-type')).toContain('text/event-stream');
    const text = await resp.text();
    expect(text).toContain('data: one');
    expect(text).toContain('data: [DONE]');
  });
});

describe('log redaction', () => {
  it('log lines never contain the token secret or the query string', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      await dispatch(new Request(`${WORKER_ORIGIN}/gecho/v1beta/models?key=${machineToken}&topsecretparam=1`));
      await echoRequest({ path: '/echo/v1/x?apikey=inline-cred' });
      const lines = spy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(lines).not.toContain(machineToken.split('.')[2]);
      expect(lines).not.toContain('topsecretparam');
      expect(lines).not.toContain('inline-cred');
      expect(lines).toContain('/v1beta/models');
    } finally {
      spy.mockRestore();
    }
  });
});
