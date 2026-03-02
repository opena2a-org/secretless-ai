import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateEnvExports, getShellHookLine, SHELL_HOOK_MARKER } from './env';
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
