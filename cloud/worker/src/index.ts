// index.ts
// shush cloud worker: router.
//
//   /admin       -> static admin UI (machines x providers grant matrix)
//   /api/*       -> admin control plane (admin token or browser session)
//   /<provider>/* -> credential-injecting proxy (machine token)

import adminHtml from '../public/admin.html';
import adminJs from '../public/admin.js.txt';
import { handleAdminApi } from './admin_api';
import { handleProxy } from './proxy';
import type { Env } from './env';

export { AclDO } from './acl';

// Strict CSP: no external origins, scripts only from this worker, no inline
// script. Inline styles are allowed (the page ships its own <style> block).
const ADMIN_CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/' || path === '') {
      return new Response(JSON.stringify({ service: 'shush-cloud', admin: '/admin', routes: '/<provider>/<upstream-path>' }), {
        headers: { 'content-type': 'application/json' },
      });
    }

    if (path === '/admin' || path === '/admin/') {
      return new Response(adminHtml, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy': ADMIN_CSP,
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
          'cache-control': 'no-store',
        },
      });
    }

    if (path === '/admin.js') {
      return new Response(adminJs, {
        headers: {
          'content-type': 'text/javascript; charset=utf-8',
          'x-content-type-options': 'nosniff',
          'cache-control': 'no-store',
        },
      });
    }

    if (path === '/api' || path.startsWith('/api/')) {
      return handleAdminApi(request, env);
    }

    return handleProxy(request, env);
  },
} satisfies ExportedHandler<Env>;
