// config.ts
// Provider table: built-ins (same table as modules/proxy_server.psm1
// get_default_providers) + a KV overlay at cfg:providers, with a last-good
// fallback at cfg:providers_prev so a corrupted overlay never takes the
// worker down.

export const VALID_AUTH_MODES = ['bearer', 'raw', 'x-api-key', 'x-goog-api-key'] as const;
export type AuthMode = (typeof VALID_AUTH_MODES)[number];

export const ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
export const DEFAULT_ALLOW_METHODS = ['GET', 'POST'];
export const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

// Cloud provider names use the SECRET name grammar (no hyphens, unlike the
// local proxy) so that `SK_<NAME_UPPER>` round-trips bijectively: the local
// grammar `^[a-z][a-z0-9_]*$` maps 1:1 onto `^SK_[A-Z][A-Z0-9_]*$` and back.
export const SECRET_NAME_RE = /^[a-z][a-z0-9_]*$/;
export const PROVIDER_NAME_RE = /^[a-z][a-z0-9_]*$/;

export interface ProviderConfig {
  secret: string;
  auth: AuthMode;
  base_url: string;
  allow_methods: string[];
  max_body_bytes: number;
}

export type ProviderMap = Record<string, ProviderConfig>;

export function getDefaultProviders(): ProviderMap {
  return {
    openai: {
      secret: 'openai_api_key',
      auth: 'bearer',
      base_url: 'https://api.openai.com',
      allow_methods: ['GET', 'POST'],
      max_body_bytes: DEFAULT_MAX_BODY_BYTES,
    },
    anthropic: {
      secret: 'anthropic_api_key',
      auth: 'x-api-key',
      base_url: 'https://api.anthropic.com',
      allow_methods: ['GET', 'POST'],
      max_body_bytes: DEFAULT_MAX_BODY_BYTES,
    },
    gemini: {
      secret: 'gemini_api_key',
      auth: 'x-goog-api-key',
      base_url: 'https://generativelanguage.googleapis.com',
      allow_methods: ['GET', 'POST'],
      max_body_bytes: DEFAULT_MAX_BODY_BYTES,
    },
  };
}

export function secretBindingName(secretName: string): string | null {
  if (!SECRET_NAME_RE.test(secretName)) return null;
  return 'SK_' + secretName.toUpperCase();
}

// Inverse of secretBindingName; used by tests to pin the round-trip.
export function secretNameFromBinding(binding: string): string | null {
  if (!/^SK_[A-Z][A-Z0-9_]*$/.test(binding)) return null;
  const name = binding.slice(3).toLowerCase();
  return SECRET_NAME_RE.test(name) ? name : null;
}

export function isValidBaseUrl(baseUrl: string): boolean {
  if (!baseUrl) return false;
  if (/^https:\/\/[a-zA-Z0-9.-]+(:\d+)?$/.test(baseUrl)) return true;
  // Plain http only for loopback (dev/e2e echo upstreams).
  if (/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(baseUrl)) return true;
  return false;
}

export interface ValidationResult {
  ok: boolean;
  providers?: ProviderMap;
  error?: string;
}

// Validates a user-supplied provider overlay (the KV document's `providers`
// field). Mirrors parse_proxy_config in modules/proxy_server.psm1, minus
// auth_passthrough_paths, which cloud v1 rejects outright: the client's
// Authorization header IS the machine token here, so passing it upstream
// would leak a live credential.
export function validateProviders(input: unknown): ValidationResult {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: "Config must contain a 'providers' object" };
  }
  const out: ProviderMap = {};
  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length === 0) {
    return { ok: false, error: 'Config defines no providers' };
  }
  for (const [name, raw] of entries) {
    if (!PROVIDER_NAME_RE.test(name)) {
      return {
        ok: false,
        error: `Invalid provider name '${name}'. Use lowercase letters, digits, underscores; start with a lowercase letter.`,
      };
    }
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      return { ok: false, error: `Provider '${name}' must be an object` };
    }
    const entry = raw as Record<string, unknown>;
    if ('auth_passthrough_paths' in entry) {
      return {
        ok: false,
        error: `Provider '${name}': auth_passthrough_paths is not supported in the cloud tier (the client Authorization header is the machine token)`,
      };
    }
    for (const required of ['secret', 'auth', 'base_url']) {
      if (typeof entry[required] !== 'string' || !entry[required]) {
        return { ok: false, error: `Provider '${name}' is missing required field '${required}'` };
      }
    }
    const secret = entry.secret as string;
    if (!SECRET_NAME_RE.test(secret)) {
      return { ok: false, error: `Provider '${name}' has invalid secret name '${secret}'` };
    }
    const auth = entry.auth as string;
    if (!(VALID_AUTH_MODES as readonly string[]).includes(auth)) {
      return {
        ok: false,
        error: `Provider '${name}' has invalid auth mode '${auth}'. Valid: ${VALID_AUTH_MODES.join(', ')}`,
      };
    }
    const baseUrl = (entry.base_url as string).replace(/\/+$/, '');
    if (!isValidBaseUrl(baseUrl)) {
      return {
        ok: false,
        error: `Provider '${name}' has invalid base_url '${entry.base_url}'. Must be https://host (http:// allowed for 127.0.0.1/localhost only), no path.`,
      };
    }
    let allowMethods = DEFAULT_ALLOW_METHODS;
    if (entry.allow_methods !== undefined) {
      if (!Array.isArray(entry.allow_methods) || entry.allow_methods.length === 0) {
        return { ok: false, error: `Provider '${name}' has invalid allow_methods` };
      }
      allowMethods = entry.allow_methods.map((m) => String(m).toUpperCase());
      for (const m of allowMethods) {
        if (!ALL_METHODS.includes(m)) {
          return { ok: false, error: `Provider '${name}' has invalid method '${m}' in allow_methods` };
        }
      }
    }
    let maxBody = DEFAULT_MAX_BODY_BYTES;
    if (entry.max_body_bytes !== undefined) {
      maxBody = Number(entry.max_body_bytes);
      if (!Number.isFinite(maxBody) || maxBody < 1) {
        return { ok: false, error: `Provider '${name}' has invalid max_body_bytes` };
      }
    }
    out[name] = { secret, auth: auth as AuthMode, base_url: baseUrl, allow_methods: allowMethods, max_body_bytes: maxBody };
  }
  return { ok: true, providers: out };
}

export interface StoredConfig {
  version: number;
  providers: ProviderMap;
}

const KV_KEY = 'cfg:providers';
const KV_KEY_PREV = 'cfg:providers_prev';

function parseStored(json: string | null): StoredConfig | null {
  if (!json) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch {
    return null;
  }
  if (doc === null || typeof doc !== 'object') return null;
  const d = doc as Record<string, unknown>;
  const version = Number(d.version);
  if (!Number.isInteger(version) || version < 1) return null;
  const validated = validateProviders(d.providers);
  if (!validated.ok) return null;
  return { version, providers: validated.providers! };
}

export interface LoadedConfig {
  providers: ProviderMap;
  version: number; // 0 = built-ins only
  source: 'builtin' | 'kv' | 'kv_prev';
}

// Effective provider table: built-ins with the KV overlay merged on top
// (same name overrides, new names add). A corrupt overlay falls back to
// the last-good copy; if both are bad, the built-ins still serve.
export async function loadProviders(kv: KVNamespace): Promise<LoadedConfig> {
  const defaults = getDefaultProviders();
  let stored = parseStored(await kv.get(KV_KEY));
  let source: LoadedConfig['source'] = 'kv';
  if (!stored) {
    stored = parseStored(await kv.get(KV_KEY_PREV));
    source = stored ? 'kv_prev' : 'builtin';
  }
  if (!stored) {
    return { providers: defaults, version: 0, source: 'builtin' };
  }
  return { providers: { ...defaults, ...stored.providers }, version: stored.version, source };
}

export interface PutResult {
  ok: boolean;
  status: number;
  version?: number;
  error?: string;
}

// PUT with optimistic concurrency: the caller sends the version it based its
// edit on; a mismatch is a 409. The previous good document is preserved at
// cfg:providers_prev before the new one lands.
export async function putProviders(kv: KVNamespace, body: unknown): Promise<PutResult> {
  if (body === null || typeof body !== 'object') {
    return { ok: false, status: 400, error: 'Body must be a JSON object with version and providers' };
  }
  const b = body as Record<string, unknown>;
  const sentVersion = Number(b.version);
  if (!Number.isInteger(sentVersion) || sentVersion < 0) {
    return { ok: false, status: 400, error: 'version must be a non-negative integer' };
  }
  const validated = validateProviders(b.providers);
  if (!validated.ok) {
    return { ok: false, status: 400, error: validated.error };
  }
  const current = parseStored(await kv.get(KV_KEY));
  const currentVersion = current ? current.version : 0;
  if (sentVersion !== currentVersion) {
    return { ok: false, status: 409, error: `Version mismatch: config is at version ${currentVersion}, you sent ${sentVersion}` };
  }
  if (current) {
    await kv.put(KV_KEY_PREV, JSON.stringify(current));
  }
  const next: StoredConfig = { version: currentVersion + 1, providers: validated.providers! };
  await kv.put(KV_KEY, JSON.stringify(next));
  return { ok: true, status: 200, version: next.version };
}
