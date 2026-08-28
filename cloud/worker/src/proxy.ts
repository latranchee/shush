// proxy.ts
// The credential-injecting proxy path: /<provider>/<upstream-path>.
//
// The client authenticates with its machine token placed wherever its SDK
// normally puts a credential (Authorization, x-api-key, x-goog-api-key,
// api-key, or ?key=). The proxy extracts it, verifies it against AclDO,
// strips every client credential, injects the provider's worker secret, and
// streams the response back.

import { CREDENTIAL_HEADERS, CREDENTIAL_QUERY_PARAM, extractClientToken, parseMachineToken } from './auth';
import { loadProviders, secretBindingName, type ProviderConfig } from './config';
import { getAcl, type Env } from './env';
import { errorResponse, logProxy } from './log';

// Strip list == extraction list (CREDENTIAL_HEADERS + ?key=) plus cookie,
// which is never a provider credential we want travelling upstream.
const STRIP_HEADERS = [...CREDENTIAL_HEADERS, 'cookie', 'host'];

function authHeaderPlan(auth: ProviderConfig['auth']): { header: string; prefix: string } {
  switch (auth) {
    case 'bearer':
      return { header: 'authorization', prefix: 'Bearer ' };
    case 'raw':
      return { header: 'authorization', prefix: '' };
    case 'x-api-key':
      return { header: 'x-api-key', prefix: '' };
    case 'x-goog-api-key':
      return { header: 'x-goog-api-key', prefix: '' };
  }
}

const VERIFY_FAILURES: Record<string, { status: number; message: string }> = {
  UNAUTHORIZED: { status: 401, message: 'Machine token is missing, malformed, or revoked' },
  MACHINE_DISABLED: { status: 403, message: 'This machine is disabled' },
  PROVIDER_NOT_GRANTED: { status: 403, message: 'This machine has no grant for the requested provider' },
  RATE_LIMITED: { status: 429, message: 'Per-machine rate limit exceeded; retry shortly' },
  QUOTA_EXCEEDED: { status: 429, message: 'Per-machine daily quota exhausted' },
};

export async function handleProxy(request: Request, env: Env): Promise<Response> {
  const started = Date.now();
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // Fail closed until the deploy flow has set the admin hash: a worker
  // reachable before its ACL exists must serve nothing.
  if (!env.ADMIN_TOKEN_HASH) {
    logProxy(503, method, '-', path, '', started, 'NOT_CONFIGURED');
    return errorResponse(503, 'NOT_CONFIGURED', 'Worker is not configured yet: run `shush cloud deploy` to set the admin token');
  }

  // WebSocket relay (e.g. OpenAI Realtime) is documented-unsupported in v1.
  if (request.headers.get('upgrade')) {
    logProxy(501, method, '-', path, '', started, 'UPGRADE_UNSUPPORTED');
    return errorResponse(501, 'UPGRADE_UNSUPPORTED', 'WebSocket/upgrade requests are not supported by the shush cloud tier (v1). Use plain HTTP/SSE endpoints.');
  }

  // Pre-auth abuse control: cheap IP rate limit before any token work, so a
  // 401 flood cannot burn DO requests. Per-colo best-effort by design.
  if (env.IP_LIMITER) {
    const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
    try {
      const { success } = await env.IP_LIMITER.limit({ key: ip });
      if (!success) {
        logProxy(429, method, '-', path, '', started, 'RATE_LIMITED_IP');
        return errorResponse(429, 'RATE_LIMITED', 'Too many requests from this address; retry shortly');
      }
    } catch {
      // A broken limiter binding must not take the proxy down.
    }
  }

  const rawToken = extractClientToken(request, url);
  if (!rawToken) {
    logProxy(401, method, '-', path, '', started, 'UNAUTHORIZED');
    return errorResponse(401, 'UNAUTHORIZED', 'Missing machine token. Send it as the API key (Authorization, x-api-key, x-goog-api-key, api-key, or ?key=).');
  }
  const parsed = parseMachineToken(rawToken);
  if (!parsed) {
    logProxy(401, method, '-', path, '', started, 'UNAUTHORIZED');
    return errorResponse(401, 'UNAUTHORIZED', 'Malformed machine token (expected shm.<id>.<secret>)');
  }

  const segments = path.replace(/^\/+|\/+$/g, '').split('/');
  const providerName = (segments[0] ?? '').toLowerCase();
  if (!providerName) {
    logProxy(404, method, '-', path, parsed.id, started, 'INVALID_PATH');
    return errorResponse(404, 'INVALID_PATH', 'Request path must be /<provider>/<upstream-path>');
  }

  const { providers } = await loadProviders(env.SHUSH_KV);
  const provider = providers[providerName];
  if (!provider) {
    logProxy(404, method, providerName, path, parsed.id, started, 'PROVIDER_NOT_FOUND');
    return errorResponse(404, 'PROVIDER_NOT_FOUND', `Unknown provider '${providerName}'. Configured: ${Object.keys(providers).sort().join(', ')}`);
  }

  if (!provider.allow_methods.includes(method)) {
    logProxy(405, method, providerName, path, parsed.id, started, 'METHOD_NOT_ALLOWED');
    return errorResponse(405, 'METHOD_NOT_ALLOWED', `Method ${method} not allowed for provider '${providerName}'. Allowed: ${provider.allow_methods.join(', ')}`);
  }

  const verdict = await getAcl(env).verify(parsed.id, parsed.secret, providerName);
  if (!verdict.ok) {
    const failure = VERIFY_FAILURES[verdict.code] ?? { status: 401, message: 'Rejected' };
    logProxy(failure.status, method, providerName, path, parsed.id, started, verdict.code);
    return errorResponse(failure.status, verdict.code, failure.message);
  }

  const binding = secretBindingName(provider.secret);
  const secretValue = binding ? env[binding] : undefined;
  if (typeof secretValue !== 'string' || secretValue.length === 0) {
    logProxy(502, method, providerName, path, parsed.id, started, 'SECRET_UNAVAILABLE');
    return errorResponse(502, 'SECRET_UNAVAILABLE', `Secret '${provider.secret}' for provider '${providerName}' is not available. Set it with: shush cloud secret set ${provider.secret}`);
  }

  // Body cap. Content-Length first; a length-less streaming body gets a
  // counting TransformStream that aborts the upstream call at the cap.
  const declaredLength = request.headers.get('content-length');
  if (declaredLength !== null && Number(declaredLength) > provider.max_body_bytes) {
    logProxy(413, method, providerName, path, parsed.id, started, 'BODY_TOO_LARGE');
    return errorResponse(413, 'BODY_TOO_LARGE', `Request body exceeds limit of ${provider.max_body_bytes} bytes`);
  }

  const upstreamPath = segments.length > 1 ? '/' + segments.slice(1).join('/') : '/';
  const upstreamUrl = new URL(provider.base_url + upstreamPath);
  for (const [k, v] of url.searchParams) {
    // Scrub the credential query param; everything else passes through.
    if (k === CREDENTIAL_QUERY_PARAM) continue;
    upstreamUrl.searchParams.append(k, v);
  }

  const headers = new Headers(request.headers);
  for (const h of STRIP_HEADERS) headers.delete(h);
  const plan = authHeaderPlan(provider.auth);
  headers.set(plan.header, plan.prefix + secretValue);

  const hasBody = method !== 'GET' && method !== 'HEAD' && request.body !== null;
  const abort = new AbortController();
  let exceeded = false;
  let body: BodyInit | null = null;
  if (hasBody) {
    const cap = provider.max_body_bytes;
    let total = 0;
    body = request.body!.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          total += chunk.byteLength;
          if (total > cap) {
            exceeded = true;
            controller.error(new Error('BODY_TOO_LARGE'));
            abort.abort();
            return;
          }
          controller.enqueue(chunk);
        },
      }),
    );
  }

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method,
      headers,
      body,
      signal: abort.signal,
      redirect: 'manual',
    });
  } catch (err) {
    if (exceeded) {
      logProxy(413, method, providerName, path, parsed.id, started, 'BODY_TOO_LARGE');
      return errorResponse(413, 'BODY_TOO_LARGE', `Request body exceeds limit of ${provider.max_body_bytes} bytes`);
    }
    logProxy(502, method, providerName, path, parsed.id, started, 'UPSTREAM_FAILED');
    return errorResponse(502, 'UPSTREAM_FAILED', `Upstream request failed: ${err instanceof Error ? err.message : 'fetch error'}`);
  }

  logProxy(upstreamResponse.status, method, providerName, path, parsed.id, started);
  // Stream the body through untouched (SSE included); re-wrap so the
  // response headers are mutable for the runtime.
  return new Response(upstreamResponse.body, upstreamResponse);
}
