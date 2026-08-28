// log.ts
// Redacted logging + the error-response contract shared with the local proxy.
//
// Redaction contract (identical to modules/proxy_server.psm1): a log line may
// contain time, status, method, provider, path, machine id, and elapsed ms —
// never query strings (some providers put keys there), header values, bodies,
// tokens, or secret values.

export interface ProxyError {
  code: string;
  message: string;
}

export function errorResponse(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export function logProxy(
  status: number,
  method: string,
  provider: string,
  path: string,
  machineId: string,
  startedMs: number,
  detail?: string,
): void {
  const elapsed = Date.now() - startedMs;
  const suffix = detail ? ` (${detail})` : '';
  // Path only — the query string is deliberately dropped.
  console.log(`${status} ${method} ${provider} ${path} machine=${machineId || '-'}${suffix} ${elapsed}ms`);
}

export function logAdmin(status: number, method: string, path: string, detail?: string): void {
  const suffix = detail ? ` (${detail})` : '';
  console.log(`${status} ${method} admin ${path}${suffix}`);
}
