// admin_api.ts
// Control plane under /api/*. v1 is single-admin: every management call is
// authorized either by the admin token (CLI, Authorization: Bearer) or by a
// browser session minted from a one-time login code the CLI requested.
//
// Plaintext machine tokens appear ONLY in create/rotate responses; backups
// carry hashes and metadata exclusively.

import { verifyAdminToken } from './auth';
import { loadProviders, putProviders, secretBindingName } from './config';
import { getAcl, type Env } from './env';
import { errorResponse, logAdmin } from './log';

const SESSION_HEADER = 'x-shush-session';

async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get('authorization');
  if (auth) {
    const m = /^Bearer\s+(.+)$/i.exec(auth);
    if (m && (await verifyAdminToken(env.ADMIN_TOKEN_HASH!, m[1].trim()))) return true;
  }
  const session = request.headers.get(SESSION_HEADER);
  if (session) {
    return await getAcl(env).verifySession(session.trim());
  }
  return false;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
}

async function readJsonBody(request: Request): Promise<unknown | undefined> {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

export async function handleAdminApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (!env.ADMIN_TOKEN_HASH) {
    logAdmin(503, method, path, 'NOT_CONFIGURED');
    return errorResponse(503, 'NOT_CONFIGURED', 'Worker is not configured yet: run `shush cloud deploy` to set the admin token');
  }

  // Session mint from a one-time code: the only unauthenticated /api route.
  if (path === '/api/session' && method === 'POST') {
    const body = (await readJsonBody(request)) as { code?: string } | undefined;
    const code = typeof body?.code === 'string' ? body.code : '';
    const session = await getAcl(env).redeemLoginCode(code);
    if (!session) {
      logAdmin(401, method, path, 'BAD_CODE');
      return errorResponse(401, 'UNAUTHORIZED', 'Login code is invalid, expired, or already used. Run `shush cloud open` again.');
    }
    logAdmin(200, method, path);
    return json(session);
  }

  if (!(await isAuthorized(request, env))) {
    logAdmin(401, method, path, 'UNAUTHORIZED');
    return errorResponse(401, 'UNAUTHORIZED', 'Admin token or session required');
  }

  const acl = getAcl(env);

  if (path === '/api/login-code' && method === 'POST') {
    const code = await acl.createLoginCode();
    logAdmin(200, method, path);
    return json({ code });
  }

  if (path === '/api/status' && method === 'GET') {
    const machines = await acl.listMachines();
    const cfg = await loadProviders(env.SHUSH_KV);
    const providers = Object.entries(cfg.providers).map(([name, p]) => {
      const binding = secretBindingName(p.secret);
      return {
        name,
        secret: p.secret,
        auth: p.auth,
        base_url: p.base_url,
        allow_methods: p.allow_methods,
        secret_available: !!binding && typeof env[binding] === 'string' && (env[binding] as string).length > 0,
      };
    });
    logAdmin(200, method, path);
    return json({ machines, providers, config_version: cfg.version, config_source: cfg.source });
  }

  if (path === '/api/machines' && method === 'GET') {
    logAdmin(200, method, path);
    return json({ machines: await acl.listMachines() });
  }

  if (path === '/api/machines' && method === 'POST') {
    const body = (await readJsonBody(request)) as { label?: string; grants?: string[] } | undefined;
    const label = typeof body?.label === 'string' ? body.label.trim() : '';
    if (!label) {
      return errorResponse(400, 'INVALID_PARAMS', 'label is required');
    }
    const grants = Array.isArray(body?.grants) ? body!.grants!.map(String) : [];
    const created = await acl.createMachine(label, grants);
    logAdmin(201, method, path, `machine=${created.machine.id}`);
    return json(created, 201);
  }

  const machineRoute = /^\/api\/machines\/([a-z0-9]{4,32})(?:\/([a-z]+))?$/.exec(path);
  if (machineRoute) {
    const [, id, action] = machineRoute;
    if (!action && method === 'DELETE') {
      const removed = await acl.revokeMachine(id);
      logAdmin(removed ? 200 : 404, method, path);
      return removed ? json({ revoked: id }) : errorResponse(404, 'NOT_FOUND', 'No such machine');
    }
    if (action === 'rotate' && method === 'POST') {
      const rotated = await acl.rotateMachine(id);
      logAdmin(rotated ? 200 : 404, method, path);
      return rotated ? json(rotated) : errorResponse(404, 'NOT_FOUND', 'No such machine');
    }
    if ((action === 'disable' || action === 'enable') && method === 'POST') {
      const updated = await acl.setDisabled(id, action === 'disable');
      logAdmin(updated ? 200 : 404, method, path);
      return updated ? json({ machine: updated }) : errorResponse(404, 'NOT_FOUND', 'No such machine');
    }
    if (action === 'grants' && method === 'PUT') {
      const body = (await readJsonBody(request)) as { grants?: string[] } | undefined;
      if (!Array.isArray(body?.grants)) {
        return errorResponse(400, 'INVALID_PARAMS', 'grants must be an array of provider names');
      }
      const updated = await acl.setGrants(id, body!.grants!.map(String));
      logAdmin(updated ? 200 : 404, method, path);
      return updated ? json({ machine: updated }) : errorResponse(404, 'NOT_FOUND', 'No such machine');
    }
    if (action === 'quota' && method === 'PUT') {
      const body = (await readJsonBody(request)) as { daily_quota?: number | null } | undefined;
      const quota = body?.daily_quota ?? null;
      if (quota !== null && (!Number.isInteger(quota) || quota < 0)) {
        return errorResponse(400, 'INVALID_PARAMS', 'daily_quota must be null or a non-negative integer');
      }
      const updated = await acl.setQuota(id, quota);
      logAdmin(updated ? 200 : 404, method, path);
      return updated ? json({ machine: updated }) : errorResponse(404, 'NOT_FOUND', 'No such machine');
    }
    return errorResponse(405, 'METHOD_NOT_ALLOWED', 'Unsupported method for this machine route');
  }

  if (path === '/api/providers' && method === 'GET') {
    const cfg = await loadProviders(env.SHUSH_KV);
    logAdmin(200, method, path);
    return json({ version: cfg.version, source: cfg.source, providers: cfg.providers });
  }

  if (path === '/api/providers' && method === 'PUT') {
    const body = await readJsonBody(request);
    const result = await putProviders(env.SHUSH_KV, body);
    logAdmin(result.status, method, path, result.ok ? undefined : 'REJECTED');
    if (!result.ok) {
      const code = result.status === 409 ? 'VERSION_CONFLICT' : 'INVALID_CONFIG';
      return errorResponse(result.status, code, result.error!);
    }
    return json({ version: result.version });
  }

  if (path === '/api/backup' && method === 'GET') {
    const machines = await acl.exportMachines();
    const cfg = await loadProviders(env.SHUSH_KV);
    logAdmin(200, method, path);
    return json({
      format: 'shush-cloud-backup-v1',
      exported: Date.now(),
      machines, // token hashes + salts + metadata; no plaintext tokens exist server-side
      providers: { version: cfg.version, providers: cfg.providers },
    });
  }

  if (path === '/api/restore' && method === 'POST') {
    const body = (await readJsonBody(request)) as
      | { format?: string; machines?: unknown; providers?: { providers?: unknown } }
      | undefined;
    if (body?.format !== 'shush-cloud-backup-v1') {
      return errorResponse(400, 'INVALID_PARAMS', 'Not a shush-cloud-backup-v1 document');
    }
    const result = await acl.importMachines((body.machines ?? []) as never);
    if (result.error) {
      return errorResponse(400, 'INVALID_PARAMS', result.error);
    }
    let configRestored = false;
    if (body.providers?.providers) {
      const cfg = await loadProviders(env.SHUSH_KV);
      const put = await putProviders(env.SHUSH_KV, { version: cfg.version, providers: body.providers.providers });
      configRestored = put.ok;
    }
    logAdmin(200, method, path, `imported=${result.imported}`);
    return json({ imported: result.imported, config_restored: configRestored });
  }

  logAdmin(404, method, path, 'NOT_FOUND');
  return errorResponse(404, 'NOT_FOUND', 'Unknown admin API route');
}
