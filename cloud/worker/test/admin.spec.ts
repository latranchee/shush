// admin.spec.ts
// Control plane: auth, machine CRUD via HTTP, provider config PUT with
// version conflict + last-good fallback, login-code handoff, backup/restore.

import { beforeEach, describe, expect, it } from 'vitest';
import { ECHO_BASE, WORKER_ORIGIN, adminHeaders, dispatch, seedEchoProviders } from './helpers';

function api(path: string, init?: RequestInit): Promise<Response> {
  return dispatch(new Request(`${WORKER_ORIGIN}${path}`, init));
}

beforeEach(async () => {
  await seedEchoProviders();
});

describe('admin auth', () => {
  it('rejects missing and wrong tokens', async () => {
    expect((await api('/api/status')).status).toBe(401);
    expect((await api('/api/status', { headers: { authorization: 'Bearer wrong-token' } })).status).toBe(401);
  });

  it('accepts the admin bearer token', async () => {
    const resp = await api('/api/status', { headers: adminHeaders() });
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { machines: unknown[]; providers: { name: string; secret_available: boolean }[] };
    expect(Array.isArray(body.machines)).toBe(true);
    const echo = body.providers.find((p) => p.name === 'echo')!;
    expect(echo.secret_available).toBe(true);
    const nokey = body.providers.find((p) => p.name === 'nokey')!;
    expect(nokey.secret_available).toBe(false);
  });
});

describe('machine lifecycle over HTTP', () => {
  it('create -> grant -> revoke round-trip; token appears exactly once', async () => {
    const created = await api('/api/machines', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ label: 'laptop', grants: ['echo'] }),
    });
    expect(created.status).toBe(201);
    const body = (await created.json()) as { machine: { id: string; grants: string[] }; token: string };
    expect(body.token).toMatch(/^shm\.[a-z0-9]{12}\.[A-Za-z0-9_-]{40,}$/);

    const list = await api('/api/machines', { headers: adminHeaders() });
    const listBody = (await list.json()) as { machines: { id: string }[] };
    expect(listBody.machines.some((m) => m.id === body.machine.id)).toBe(true);
    // Listing never exposes token material.
    expect(JSON.stringify(listBody)).not.toContain(body.token.split('.')[2]);
    expect(JSON.stringify(listBody)).not.toContain('token_hash');

    const granted = await api(`/api/machines/${body.machine.id}/grants`, {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({ grants: ['echo', 'gecho'] }),
    });
    expect(granted.status).toBe(200);

    const revoked = await api(`/api/machines/${body.machine.id}`, { method: 'DELETE', headers: adminHeaders() });
    expect(revoked.status).toBe(200);
  });

  it('label is required', async () => {
    const resp = await api('/api/machines', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({}) });
    expect(resp.status).toBe(400);
  });
});

describe('provider config', () => {
  it('PUT with a stale version is a 409', async () => {
    const stale = await api('/api/providers', {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({ version: 0, providers: { p: { secret: 'p_key', auth: 'bearer', base_url: 'https://api.example.com' } } }),
    });
    expect(stale.status).toBe(409);
    const body = (await stale.json()) as { error: { code: string } };
    expect(body.error.code).toBe('VERSION_CONFLICT');
  });

  it('PUT at the right version bumps it', async () => {
    const resp = await api('/api/providers', {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({ version: 1, providers: { p: { secret: 'p_key', auth: 'bearer', base_url: 'https://api.example.com' } } }),
    });
    expect(resp.status).toBe(200);
    const body = (await resp.json()) as { version: number };
    expect(body.version).toBe(2);
  });

  it('rejects auth_passthrough_paths outright', async () => {
    const resp = await api('/api/providers', {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({
        version: 1,
        providers: { p: { secret: 'p_key', auth: 'bearer', base_url: 'https://api.example.com', auth_passthrough_paths: ['^/x'] } },
      }),
    });
    expect(resp.status).toBe(400);
  });

  it('rejects provider names outside the SK_-bijective grammar', async () => {
    const resp = await api('/api/providers', {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({ version: 1, providers: { 'has-hyphen': { secret: 'p_key', auth: 'bearer', base_url: 'https://api.example.com' } } }),
    });
    expect(resp.status).toBe(400);
  });

  it('a corrupted live config falls back to the last-good copy', async () => {
    const { testEnv } = await import('./helpers');
    // Bump to version 2 through the API so cfg:providers_prev holds version 1.
    await api('/api/providers', {
      method: 'PUT',
      headers: adminHeaders(),
      body: JSON.stringify({ version: 1, providers: { echo: { secret: 'echo_key', auth: 'bearer', base_url: ECHO_BASE } } }),
    });
    await testEnv.SHUSH_KV.put('cfg:providers', 'THIS IS NOT JSON {');
    const status = await api('/api/providers', { headers: adminHeaders() });
    const body = (await status.json()) as { source: string; providers: Record<string, unknown> };
    expect(body.source).toBe('kv_prev');
    expect(body.providers.echo).toBeDefined();
  });
});

describe('login-code handoff', () => {
  it('code mints a session once; the session drives the API; reuse fails', async () => {
    const codeResp = await api('/api/login-code', { method: 'POST', headers: adminHeaders() });
    expect(codeResp.status).toBe(200);
    const { code } = (await codeResp.json()) as { code: string };

    const sessionResp = await api('/api/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    expect(sessionResp.status).toBe(200);
    const { session } = (await sessionResp.json()) as { session: string };

    const status = await api('/api/status', { headers: { 'x-shush-session': session } });
    expect(status.status).toBe(200);

    const reuse = await api('/api/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    expect(reuse.status).toBe(401);
  });
});

describe('backup and restore', () => {
  it('backup carries hashes, never plaintext tokens; restore brings a machine back', async () => {
    const created = await api('/api/machines', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ label: 'backup-me', grants: ['echo'] }),
    });
    const { machine, token } = (await created.json()) as { machine: { id: string }; token: string };

    const backupResp = await api('/api/backup', { headers: adminHeaders() });
    expect(backupResp.status).toBe(200);
    const backup = (await backupResp.json()) as { format: string; machines: { id: string }[] };
    expect(backup.format).toBe('shush-cloud-backup-v1');
    expect(JSON.stringify(backup)).not.toContain(token.split('.')[2]);
    expect(backup.machines.some((m) => m.id === machine.id)).toBe(true);

    await api(`/api/machines/${machine.id}`, { method: 'DELETE', headers: adminHeaders() });
    const restoreResp = await api('/api/restore', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify(backup),
    });
    expect(restoreResp.status).toBe(200);

    // The restored hash still verifies the original token.
    const proxied = await dispatch(
      new Request(`${WORKER_ORIGIN}/echo/v1/models`, { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(proxied.status).toBe(200);
  });
});
