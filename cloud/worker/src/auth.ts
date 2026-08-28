// auth.ts
// Machine-token and admin-token parsing, hashing, and timing-safe verification.
//
// Machine token wire format: shm.<machine_id>.<base64url 32B secret>
// The delimiter is '.' on purpose: '_' and '-' are both in the base64url
// alphabet, so either would make the format ambiguous.
//
// At rest only SHA-256(salt || secret) is stored, so a leaked DO snapshot or
// backup file cannot be replayed as a credential.

export const MACHINE_TOKEN_PREFIX = 'shm';
export const MACHINE_ID_RE = /^[a-z0-9]{4,32}$/;

export interface ParsedMachineToken {
  id: string;
  secret: string;
}

export function parseMachineToken(raw: string): ParsedMachineToken | null {
  if (!raw) return null;
  const parts = raw.split('.');
  if (parts.length !== 3) return null;
  const [prefix, id, secret] = parts;
  if (prefix !== MACHINE_TOKEN_PREFIX) return null;
  if (!MACHINE_ID_RE.test(id)) return null;
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(secret)) return null;
  return { id, secret };
}

// The token extraction list MUST equal the credential strip list in proxy.ts
// (plus the ?key= query param): a header we accept a token from but forget to
// strip leaks the machine token upstream; a header we strip but do not accept
// breaks every client that authenticates through it (e.g. Gemini clients use
// x-goog-api-key or ?key=).
export const CREDENTIAL_HEADERS = ['authorization', 'x-api-key', 'x-goog-api-key', 'api-key'] as const;
export const CREDENTIAL_QUERY_PARAM = 'key';

export function extractClientToken(request: Request, url: URL): string | null {
  const auth = request.headers.get('authorization');
  if (auth) {
    const m = /^Bearer\s+(.+)$/i.exec(auth);
    return (m ? m[1] : auth).trim();
  }
  for (const header of ['x-api-key', 'x-goog-api-key', 'api-key']) {
    const value = request.headers.get(header);
    if (value) return value.trim();
  }
  const queryKey = url.searchParams.get(CREDENTIAL_QUERY_PARAM);
  if (queryKey) return queryKey.trim();
  return null;
}

const encoder = new TextEncoder();

export function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array | null {
  try {
    const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

// SHA-256(salt_bytes || secret_utf8) -> base64url.
export async function hashSecret(secret: string, saltB64Url: string): Promise<string | null> {
  const salt = fromBase64Url(saltB64Url);
  if (!salt) return null;
  const secretBytes = encoder.encode(secret);
  const input = new Uint8Array(salt.length + secretBytes.length);
  input.set(salt, 0);
  input.set(secretBytes, salt.length);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return toBase64Url(new Uint8Array(digest));
}

// Constant-time string comparison. Both sides here are already fixed-length
// hashes, so length is not secret; still, mismatched lengths return false
// after a full-width scan.
export function timingSafeEqualStrings(a: string, b: string): boolean {
  const ab = encoder.encode(a);
  const bb = encoder.encode(b);
  const len = Math.max(ab.length, bb.length);
  let diff = ab.length === bb.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    diff |= (ab[i % ab.length] ?? 0) ^ (bb[i % bb.length] ?? 0);
  }
  return diff === 0;
}

// Admin token hash worker secret format: v1:<salt_b64url>:<sha256(salt||token) b64url>
export function formatAdminTokenHash(saltB64Url: string, hashB64Url: string): string {
  return `v1:${saltB64Url}:${hashB64Url}`;
}

export async function verifyAdminToken(storedHash: string, providedToken: string): Promise<boolean> {
  if (!storedHash || !providedToken) return false;
  const parts = storedHash.split(':');
  if (parts.length !== 3 || parts[0] !== 'v1') return false;
  const computed = await hashSecret(providedToken, parts[1]);
  if (!computed) return false;
  return timingSafeEqualStrings(computed, parts[2]);
}
