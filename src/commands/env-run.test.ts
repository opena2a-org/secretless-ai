import { describe, it, expect, vi, afterEach } from 'vitest';
import { runEnv } from './env-run';

// Security regression (release-test 2026-07-16): `secretless-ai env` dumps every
// stored secret as plaintext. Inside an AI-agent runtime it must refuse, and the
// refusal must be driven by the runtime — NOT by parsing the command string —
// because an agent can spell the invocation any number of ways that defeat the
// deny-glob and guard-hook layers. This asserts the tool-level gate: whatever
// args `runEnv` gets, if an agent marker is set, it emits nothing and exits 1.
describe('runEnv agent-runtime refusal', () => {
  const savedClaude = process.env.CLAUDECODE;

  afterEach(() => {
    vi.restoreAllMocks();
    if (savedClaude === undefined) delete process.env.CLAUDECODE;
    else process.env.CLAUDECODE = savedClaude;
  });

  function captureIO() {
    const out: string[] = [];
    const err: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out.push(String(c)); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation((c: any) => { err.push(String(c)); return true; });
    return { out, err };
  }

  // Every one of these argv shapes maps to a real full-store dump at runtime;
  // none can be distinguished from a legitimate call by inspecting the string.
  // The gate ignores them all and refuses because the runtime marker is set.
  const argShapes: [string, string[]][] = [
    ['no args', []],
    ['--only subset', ['--only', 'STRIPE_SECRET_KEY']],
    ['stray positional', ['env']],
  ];

  for (const [label, args] of argShapes) {
    it(`refuses (${label}) when CLAUDECODE is set: exit 1, empty stdout, guidance on stderr`, async () => {
      process.env.CLAUDECODE = '1';
      const { out, err } = captureIO();

      const code = await runEnv(args);

      expect(code).toBe(1);
      expect(out.join('')).toBe(''); // no secret ever reaches stdout
      const stderr = err.join('');
      expect(stderr).toContain('Refused');
      expect(stderr).toContain('CLAUDECODE');
      expect(stderr).toContain('run --only'); // points at the safe path, not a dead end
    });
  }

  it('still serves --help under an agent runtime (help is harmless, no values)', async () => {
    process.env.CLAUDECODE = '1';
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const code = await runEnv(['--help']);
    expect(code).toBe(0);
    expect(logSpy.mock.calls.flat().join('\n')).toContain('eval');
  });
});
