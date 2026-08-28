// acl.ts
// AclDO: the single source of truth for machines, grants, limits, quotas,
// login codes, and admin sessions.
//
// A Durable Object (not KV) on purpose: revocation must be immediate (KV has
// a 60s cacheTtl floor), rate limiting must be global (the Rate Limiting
// binding is per-colo best-effort), and per-request counter writes would
// violate KV's 1 write/sec/key limit. One DO instance ("acl") serializes all
// of that correctly.

import { DurableObject } from 'cloudflare:workers';
import { MACHINE_ID_RE, hashSecret, randomBase64Url, timingSafeEqualStrings } from './auth';

export const ROTATION_GRACE_MS = 5 * 60 * 1000;
export const LOGIN_CODE_TTL_MS = 2 * 60 * 1000;
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const DEFAULT_MACHINE_RPM = 300;

export interface MachineRecord {
  id: string;
  label: string;
  token_hash: string;
  salt: string;
  prev_token_hash?: string;
  prev_expires?: number;
  created: number;
  last_seen: number;
  grants: string[];
  disabled: boolean;
  daily_quota: number | null;
  counters: { day: string; count: number; total: number };
  rl: { window: number; count: number };
}

// What leaves the DO for list/status calls: everything except hash material.
export interface MachineView {
  id: string;
  label: string;
  created: number;
  last_seen: number;
  grants: string[];
  disabled: boolean;
  daily_quota: number | null;
  today_count: number;
  total_count: number;
  rotation_pending: boolean;
}

export type VerifyResult =
  | { ok: true; machine: { id: string; label: string } }
  | { ok: false; code: 'UNAUTHORIZED' | 'MACHINE_DISABLED' | 'PROVIDER_NOT_GRANTED' | 'RATE_LIMITED' | 'QUOTA_EXCEEDED' };

interface CodeRecord {
  expires: number;
}

interface SessionRecord {
  expires: number;
}

function utcDay(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

function toView(m: MachineRecord, now: number): MachineView {
  return {
    id: m.id,
    label: m.label,
    created: m.created,
    last_seen: m.last_seen,
    grants: [...m.grants],
    disabled: m.disabled,
    daily_quota: m.daily_quota,
    today_count: m.counters.day === utcDay(now) ? m.counters.count : 0,
    total_count: m.counters.total,
    rotation_pending: !!m.prev_token_hash && (m.prev_expires ?? 0) > now,
  };
}

export class AclDO extends DurableObject {
  private machineKey(id: string): string {
    return `machine:${id}`;
  }

  private async getMachine(id: string): Promise<MachineRecord | undefined> {
    if (!MACHINE_ID_RE.test(id)) return undefined;
    return await this.ctx.storage.get<MachineRecord>(this.machineKey(id));
  }

  private async putMachine(m: MachineRecord): Promise<void> {
    await this.ctx.storage.put(this.machineKey(m.id), m);
  }

  private rpmLimit(): number {
    const env = this.env as Record<string, unknown>;
    const raw = env['MACHINE_RPM'];
    const parsed = Number(raw);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : DEFAULT_MACHINE_RPM;
  }

  private newMachineId(): string {
    // 12 lowercase hex chars: within MACHINE_ID_RE, short enough to read in
    // a token, collision-safe at this scale.
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  async createMachine(label: string, grants: string[]): Promise<{ machine: MachineView; token: string }> {
    const now = Date.now();
    const id = this.newMachineId();
    const secret = randomBase64Url(32);
    const salt = randomBase64Url(16);
    const tokenHash = await hashSecret(secret, salt);
    if (!tokenHash) throw new Error('hashing failed');
    const record: MachineRecord = {
      id,
      label: String(label || '').slice(0, 120),
      token_hash: tokenHash,
      salt,
      created: now,
      last_seen: 0,
      grants: [...new Set(grants.map((g) => String(g)))],
      disabled: false,
      daily_quota: null,
      counters: { day: utcDay(now), count: 0, total: 0 },
      rl: { window: 0, count: 0 },
    };
    await this.putMachine(record);
    return { machine: toView(record, now), token: `shm.${id}.${secret}` };
  }

  async listMachines(): Promise<MachineView[]> {
    const now = Date.now();
    const map = await this.ctx.storage.list<MachineRecord>({ prefix: 'machine:' });
    return [...map.values()].map((m) => toView(m, now)).sort((a, b) => a.created - b.created);
  }

  async revokeMachine(id: string): Promise<boolean> {
    const m = await this.getMachine(id);
    if (!m) return false;
    await this.ctx.storage.delete(this.machineKey(id));
    return true;
  }

  async setDisabled(id: string, disabled: boolean): Promise<MachineView | null> {
    const m = await this.getMachine(id);
    if (!m) return null;
    m.disabled = !!disabled;
    await this.putMachine(m);
    return toView(m, Date.now());
  }

  // Rotation: new secret immediately valid; the old hash keeps working for
  // ROTATION_GRACE_MS so an in-flight agent session can be re-pointed without
  // a hard outage window.
  async rotateMachine(id: string): Promise<{ machine: MachineView; token: string } | null> {
    const m = await this.getMachine(id);
    if (!m) return null;
    const now = Date.now();
    const secret = randomBase64Url(32);
    const salt = randomBase64Url(16);
    const tokenHash = await hashSecret(secret, salt);
    if (!tokenHash) throw new Error('hashing failed');
    m.prev_token_hash = m.token_hash;
    m.prev_expires = now + ROTATION_GRACE_MS;
    // Old hash verifies against the old salt, so keep it alongside.
    (m as MachineRecord & { prev_salt?: string }).prev_salt = m.salt;
    m.token_hash = tokenHash;
    m.salt = salt;
    await this.putMachine(m);
    return { machine: toView(m, now), token: `shm.${id}.${secret}` };
  }

  async setGrants(id: string, grants: string[]): Promise<MachineView | null> {
    const m = await this.getMachine(id);
    if (!m) return null;
    m.grants = [...new Set(grants.map((g) => String(g)))];
    await this.putMachine(m);
    return toView(m, Date.now());
  }

  async setQuota(id: string, dailyQuota: number | null): Promise<MachineView | null> {
    const m = await this.getMachine(id);
    if (!m) return null;
    if (dailyQuota !== null && (!Number.isInteger(dailyQuota) || dailyQuota < 0)) return null;
    m.daily_quota = dailyQuota;
    await this.putMachine(m);
    return toView(m, Date.now());
  }

  // The proxy hot path. Order matters: identity first (401 beats every other
  // signal), then disabled, then grant, then limits. Counters advance only on
  // an accepted request.
  async verify(id: string, secret: string, provider: string): Promise<VerifyResult> {
    const m = await this.getMachine(id);
    if (!m) return { ok: false, code: 'UNAUTHORIZED' };

    const now = Date.now();
    const currentHash = await hashSecret(secret, m.salt);
    let matched = !!currentHash && timingSafeEqualStrings(currentHash, m.token_hash);
    if (!matched && m.prev_token_hash && (m.prev_expires ?? 0) > now) {
      const prevSalt = (m as MachineRecord & { prev_salt?: string }).prev_salt ?? m.salt;
      const prevHash = await hashSecret(secret, prevSalt);
      matched = !!prevHash && timingSafeEqualStrings(prevHash, m.prev_token_hash);
    }
    if (!matched) return { ok: false, code: 'UNAUTHORIZED' };

    if (m.disabled) return { ok: false, code: 'MACHINE_DISABLED' };
    if (!m.grants.includes(provider)) return { ok: false, code: 'PROVIDER_NOT_GRANTED' };

    // Fixed one-minute window, global because this DO is the only writer.
    const windowNow = Math.floor(now / 60000);
    if (m.rl.window !== windowNow) {
      m.rl.window = windowNow;
      m.rl.count = 0;
    }
    if (m.rl.count >= this.rpmLimit()) {
      await this.putMachine(m);
      return { ok: false, code: 'RATE_LIMITED' };
    }

    const day = utcDay(now);
    if (m.counters.day !== day) {
      m.counters.day = day;
      m.counters.count = 0;
    }
    if (m.daily_quota !== null && m.counters.count >= m.daily_quota) {
      await this.putMachine(m);
      return { ok: false, code: 'QUOTA_EXCEEDED' };
    }

    m.rl.count += 1;
    m.counters.count += 1;
    m.counters.total += 1;
    m.last_seen = now;
    if (m.prev_token_hash && (m.prev_expires ?? 0) <= now) {
      delete m.prev_token_hash;
      delete m.prev_expires;
      delete (m as MachineRecord & { prev_salt?: string }).prev_salt;
    }
    await this.putMachine(m);
    return { ok: true, machine: { id: m.id, label: m.label } };
  }

  // --- admin UI login: one-time code handed from the CLI to the browser ---

  async createLoginCode(): Promise<string> {
    const code = randomBase64Url(16);
    await this.ctx.storage.put<CodeRecord>(`code:${code}`, { expires: Date.now() + LOGIN_CODE_TTL_MS });
    return code;
  }

  async redeemLoginCode(code: string): Promise<{ session: string; expires: number } | null> {
    if (!code || code.length > 64) return null;
    const key = `code:${code}`;
    const record = await this.ctx.storage.get<CodeRecord>(key);
    if (!record) return null;
    await this.ctx.storage.delete(key); // single use, even when expired
    if (record.expires < Date.now()) return null;
    const session = randomBase64Url(32);
    const expires = Date.now() + SESSION_TTL_MS;
    await this.ctx.storage.put<SessionRecord>(`session:${session}`, { expires });
    return { session, expires };
  }

  async verifySession(token: string): Promise<boolean> {
    if (!token || token.length > 64) return false;
    const record = await this.ctx.storage.get<SessionRecord>(`session:${token}`);
    if (!record) return false;
    if (record.expires < Date.now()) {
      await this.ctx.storage.delete(`session:${token}`);
      return false;
    }
    return true;
  }

  // --- backup/restore: hashes + metadata only, never plaintext tokens ---

  async exportMachines(): Promise<MachineRecord[]> {
    const map = await this.ctx.storage.list<MachineRecord>({ prefix: 'machine:' });
    return [...map.values()];
  }

  async importMachines(records: MachineRecord[]): Promise<{ imported: number; error?: string }> {
    if (!Array.isArray(records)) return { imported: 0, error: 'machines must be an array' };
    const valid: MachineRecord[] = [];
    for (const r of records) {
      if (!r || typeof r !== 'object') return { imported: 0, error: 'invalid machine record' };
      if (!MACHINE_ID_RE.test(String(r.id))) return { imported: 0, error: `invalid machine id '${r.id}'` };
      if (typeof r.token_hash !== 'string' || typeof r.salt !== 'string') {
        return { imported: 0, error: `machine '${r.id}' is missing hash material` };
      }
      valid.push(r);
    }
    for (const r of valid) {
      await this.putMachine(r);
    }
    return { imported: valid.length };
  }
}
