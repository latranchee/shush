import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { createHash } from 'node:crypto';

// Fixed admin token for the test suite; the worker only ever sees the hash,
// in the same v1:<salt>:<hash> format `shush cloud deploy` produces.
export const TEST_ADMIN_TOKEN = 'test-admin-token-0123456789';

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const salt = Buffer.from('unit-test-salt-16');
const digest = createHash('sha256')
  .update(Buffer.concat([salt, Buffer.from(TEST_ADMIN_TOKEN, 'utf8')]))
  .digest();
const adminTokenHash = `v1:${b64url(salt)}:${b64url(digest)}`;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          ADMIN_TOKEN_HASH: adminTokenHash,
          // Provider worker secrets (SK_<SECRET_NAME_UPPER>).
          SK_OPENAI_API_KEY: 'sk-test-openai-secret',
          SK_ECHO_KEY: 'echo-secret-value',
          SK_GECHO_KEY: 'gecho-secret-value',
        },
      },
    }),
  ],
  test: {
    globalSetup: ['./test/global_setup.ts'],
    testTimeout: 20000,
  },
});
