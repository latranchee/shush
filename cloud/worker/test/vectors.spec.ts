// vectors.spec.ts
// Shared vectors consumed by BOTH this suite and tests/cloud_client.Tests.ps1
// so the TypeScript and PowerShell halves cannot drift: SK_ binding
// round-trip, machine token grammar, provider name grammar, and the
// extraction==strip header list.

import { describe, expect, it } from 'vitest';
import vectors from '../../../tests/fixtures/cloud_vectors.json';
import { parseMachineToken, CREDENTIAL_HEADERS, CREDENTIAL_QUERY_PARAM } from '../src/auth';
import { PROVIDER_NAME_RE, secretBindingName, secretNameFromBinding } from '../src/config';

describe('SK_ binding round-trip', () => {
  for (const v of vectors.secret_name_to_binding) {
    it(`'${v.name}' -> ${v.binding ?? 'rejected'}`, () => {
      const binding = secretBindingName(v.name);
      expect(binding).toBe(v.binding);
      if (v.valid && binding) {
        expect(secretNameFromBinding(binding)).toBe(v.name);
      }
    });
  }
});

describe('machine token grammar', () => {
  for (const v of vectors.machine_tokens) {
    it(`'${v.token.slice(0, 24)}...' valid=${v.valid}`, () => {
      const parsed = parseMachineToken(v.token);
      if (v.valid) {
        expect(parsed).not.toBeNull();
        expect(parsed!.id).toBe(v.id);
      } else {
        expect(parsed).toBeNull();
      }
    });
  }
});

describe('provider name grammar', () => {
  for (const v of vectors.provider_names) {
    it(`'${v.name}' valid=${v.valid}`, () => {
      expect(PROVIDER_NAME_RE.test(v.name)).toBe(v.valid);
    });
  }
});

describe('extraction == strip contract', () => {
  it('the credential header list matches the shared vectors exactly', () => {
    expect([...CREDENTIAL_HEADERS]).toEqual(vectors.credential_headers);
    expect(CREDENTIAL_QUERY_PARAM).toBe(vectors.credential_query_param);
  });
});
