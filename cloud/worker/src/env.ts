// env.ts
// Worker environment surface. Provider keys arrive as worker secrets named
// SK_<SECRET_NAME_UPPER> (see config.secretBindingName); they are looked up
// dynamically, hence the index signature.

import type { AclDO } from './acl';

export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  SHUSH_KV: KVNamespace;
  ACL: DurableObjectNamespace<AclDO>;
  // SHA-256 hash of the admin token (v1:<salt>:<hash>), set via
  // `wrangler secret put ADMIN_TOKEN_HASH`. The worker fails closed (503)
  // until it exists.
  ADMIN_TOKEN_HASH?: string;
  // Optional per-machine requests-per-minute override (plain var).
  MACHINE_RPM?: string;
  // Optional pre-auth Rate Limiting binding keyed on client IP.
  IP_LIMITER?: RateLimiter;
  [binding: string]: unknown;
}

export function getAcl(env: Env) {
  return env.ACL.get(env.ACL.idFromName('acl'));
}
