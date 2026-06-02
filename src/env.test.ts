import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateEnvExports, getShellHookLine, SHELL_HOOK_MARKER, isValidShellIdentifier } from './env';
import type { WritableSecretBackend } from './backends/types';

function createMockBackend(secrets: Record<string, string>): WritableSecretBackend {
  return {
    name: 'mock',
    async store() {},
    async resolve(prefix: string) {
      const result: Record<string, string> = {};
      for (const [key, value] of Object.entries(secrets)) {
        if (key.startsWith(prefix)) {
          result[key] = value;
        }
      }
      return result;
    },
    async delete() { return true; },
    async healthCheck() { return { healthy: true, latencyMs: 0, message: 'ok' }; },
  };
}

describe('generateEnvExports', () => {
  it('generates export statements for stored secrets', async () => {
    const backend = createMockBackend({
      'secret/NPM_TOKEN': 'npm_abc123',
      'secret/GITHUB_TOKEN': 'ghp_xyz789',
    });

    const output = await generateEnvExports({ backend });
    expect(output).toContain("export GITHUB_TOKEN='ghp_xyz789'");
    expect(output).toContain("export NPM_TOKEN='npm_abc123'");
  });

  it('returns empty string when no secrets exist', async () => {
    const backend = createMockBackend({});
    const output = await generateEnvExports({ backend });
    expect(output).toBe('');
  });

  it('escapes single quotes in values', async () => {
    const backend = createMockBackend({
      'secret/TRICKY': "it's a test",
    });

    const output = await generateEnvExports({ backend });
    expect(output).toContain("export TRICKY='it'\\''s a test'");
  });

  it('filters by --only when specified', async () => {
    const backend = createMockBackend({
      'secret/NPM_TOKEN': 'npm_abc',
      'secret/GITHUB_TOKEN': 'ghp_xyz',
      'secret/STRIPE_KEY': 'sk_live_123',
    });

    const output = await generateEnvExports({ backend, only: ['NPM_TOKEN'] });
    expect(output).toContain("export NPM_TOKEN='npm_abc'");
    expect(output).not.toContain('GITHUB_TOKEN');
    expect(output).not.toContain('STRIPE_KEY');
  });

  // Stored secret names allow `-` (SAFE_NAME in secret-store), but a shell
  // variable name cannot. Emitting `export vault-name=...` makes the shell
  // reject the entire `eval "$(secretless-ai env)"`, which broke every command
  // in profiles using the eval hook. A non-identifier name must be skipped, not
  // emitted, and must not take valid secrets down with it.
  it('skips secret names that are not valid shell identifiers instead of emitting an invalid export', async () => {
    const backend = createMockBackend({
      'secret/vault-name': 'oops',
      'secret/GOOD_TOKEN': 'ghp_ok',
    });

    const output = await generateEnvExports({ backend });
    // The bad name never becomes an `export` line.
    expect(output).not.toContain('export vault-name');
    // The valid secret still exports — one bad name does not break the rest.
    expect(output).toContain("export GOOD_TOKEN='ghp_ok'");
    // The skip is surfaced as a shell comment (no-op inside eval, visible direct).
    expect(output).toMatch(/^# secretless: skipped 1 secret .*vault-name/m);
    // Every non-comment line is a valid `export` of a valid identifier.
    for (const line of output.split('\n').filter(l => l && !l.startsWith('#'))) {
      expect(line).toMatch(/^export [A-Za-z_][A-Za-z0-9_]*=/);
    }
  });

  it('the whole eval output parses as a shell no-op when only bad names exist', async () => {
    const backend = createMockBackend({ 'secret/bad-name': 'x', 'secret/9starts': 'y' });
    const output = await generateEnvExports({ backend });
    expect(output).not.toMatch(/^export /m); // no export lines at all
    expect(output.split('\n').every(l => l === '' || l.startsWith('#'))).toBe(true);
  });
});

describe('isValidShellIdentifier', () => {
  it('accepts POSIX shell identifiers', () => {
    for (const n of ['FOO', '_foo', 'foo_bar', 'A1', 'supabase_registry_db']) {
      expect(isValidShellIdentifier(n)).toBe(true);
    }
  });
  it('rejects names with dashes, leading digits, dots, or spaces', () => {
    for (const n of ['vault-name', '9lives', 'a.b', 'a b', '', '-x']) {
      expect(isValidShellIdentifier(n)).toBe(false);
    }
  });
});

describe('getShellHookLine', () => {
  it('returns eval statement for secretless-ai env', () => {
    const line = getShellHookLine();
    expect(line).toBe('eval "$(secretless-ai env 2>/dev/null)"');
  });
});

describe('SHELL_HOOK_MARKER', () => {
  it('is a comment line', () => {
    expect(SHELL_HOOK_MARKER).toMatch(/^#/);
    expect(SHELL_HOOK_MARKER).toContain('secretless-ai');
  });
});
