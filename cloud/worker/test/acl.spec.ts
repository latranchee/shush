// acl.spec.ts
// AclDO behaviors that carry the security promises: immediate revocation,
// rotation grace, quotas failing closed, disable, rate limit.

import { beforeEach, describe, expect, it } from 'vitest';
import { WORKER_ORIGIN, acl, dispatch, newMachine, seedEchoProviders } from './helpers';

beforeEach(async () => {
  await seedEchoProviders();
});

function proxyGet(token: string): Promise<Response> {
  return dispatch(new Request(`${WORKER_ORIGIN}/echo/v1/models`, { headers: { authorization: `Bearer ${token}` } }));
}

describe('revocation', () => {
  it('a revoked machine is rejected on the very next request', async () => {
    const { machine, token } = await newMachine(['echo']);
    expect((await proxyGet(token)).status).toBe(200);
    await acl().revokeMachine(machine.id);
    const after = await proxyGet(token);
    expect(after.status).toBe(401);
  });

  it('a disabled machine gets MACHINE_DISABLED and re-enabling restores service', async () => {
    const { machine, token } = await newMachine(['echo']);
    await acl().setDisabled(machine.id, true);
    const denied = await proxyGet(token);
    expect(denied.status).toBe(403);
    const body = (await denied.json()) as { error: { code: string } };
    expect(body.error.code).toBe('MACHINE_DISABLED');
    await acl().setDisabled(machine.id, false);
    expect((await proxyGet(token)).status).toBe(200);
  });
});

describe('rotation', () => {
  it('after rotate, both old and new tokens work during the grace window', async () => {
    const { machine, token: oldToken } = await newMachine(['echo']);
    const rotated = await acl().rotateMachine(machine.id);
    expect(rotated).not.toBeNull();
    expect(rotated!.token).not.toBe(oldToken);
    expect((await proxyGet(rotated!.token)).status).toBe(200);
    expect((await proxyGet(oldToken)).status).toBe(200);
  });

  it('the old token dies when the grace window has passed', async () => {
    const { machine, token: oldToken } = await newMachine(['echo']);
    await acl().rotateMachine(machine.id);
    // Expire the grace window by editing the stored record through the
    // backup/restore path (no clock control inside workerd).
    const records = await acl().exportMachines();
    const record = records.find((r) => r.id === machine.id)!;
    record.prev_expires = Date.now() - 1000;
    await acl().importMachines([record]);
    expect((await proxyGet(oldToken)).status).toBe(401);
  });
});

describe('quota and rate limit', () => {
  it('daily quota fails closed with QUOTA_EXCEEDED', async () => {
    const { machine, token } = await newMachine(['echo']);
    await acl().setQuota(machine.id, 2);
    expect((await proxyGet(token)).status).toBe(200);
    expect((await proxyGet(token)).status).toBe(200);
    const third = await proxyGet(token);
    expect(third.status).toBe(429);
    const body = (await third.json()) as { error: { code: string } };
    expect(body.error.code).toBe('QUOTA_EXCEEDED');
  });

  it('quota zero blocks immediately', async () => {
    const { machine, token } = await newMachine(['echo']);
    await acl().setQuota(machine.id, 0);
    expect((await proxyGet(token)).status).toBe(429);
  });

  it('per-machine rate limit trips within one minute window', async () => {
    const { token } = await newMachine(['echo']);
    // MACHINE_RPM binding is not set in tests -> default 300. Simulate a
    // lower limit via env override on the DO? The DO reads its own env, so
    // instead hammer with the default limit only if cheap: skip the full 300
    // and verify the code path directly through verify().
    const machines = await acl().exportMachines();
    const record = machines.find((m) => `shm.${m.id}.` === token.slice(0, token.lastIndexOf('.') + 1))!;
    record.rl = { window: Math.floor(Date.now() / 60000), count: 999999 };
    await acl().importMachines([record]);
    const resp = await proxyGet(token);
    expect(resp.status).toBe(429);
    const body = (await resp.json()) as { error: { code: string } };
    expect(body.error.code).toBe('RATE_LIMITED');
  });
});

describe('counters', () => {
  it('verify advances today/total counters and last_seen', async () => {
    const { machine, token } = await newMachine(['echo']);
    await proxyGet(token);
    await proxyGet(token);
    const view = (await acl().listMachines()).find((m) => m.id === machine.id)!;
    expect(view.today_count).toBe(2);
    expect(view.total_count).toBe(2);
    expect(view.last_seen).toBeGreaterThan(0);
  });
});
