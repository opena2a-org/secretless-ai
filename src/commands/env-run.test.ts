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

// Issue #110: the unmatched-`--only` error carries a Verify/Fix block. Printing
// only its first line indented breaks the block apart, which is the same defect
// that had to be fixed in the #108 backend error. `runWithSecrets` is mocked so
// this never constructs a real backend (an OS-keychain construction inside a
// test run pops a blocking modal on the operator's machine).
vi.mock('../run', () => ({ runWithSecrets: vi.fn() }));

describe('runRun surfaces a multi-line precondition error intact', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('returns 1 and indents EVERY line of the message', async () => {
    const { runRun } = await import('./env-run');
    const { runWithSecrets } = await import('../run');

    vi.mocked(runWithSecrets).mockRejectedValue(new Error(
      'Requested secret not found in the store: ABSENT_NAME\n' +
      '\n' +
      '  Nothing was injected and the command was not run.\n' +
      '\n' +
      '  Verify:  secretless-ai secret list\n' +
      '  Fix:     secretless-ai secret set ABSENT_NAME',
    ));

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await runRun(['--only', 'ABSENT_NAME', '--', 'echo', 'hi']);
    const printed = errSpy.mock.calls.flat().join('\n');

    expect(code).toBe(1);
    expect(printed).toContain('ABSENT_NAME');
    expect(printed).toContain('Verify:');
    expect(printed).toContain('Fix:');
    // Every non-empty line indented — no line flush to column 0 after the first.
    const body = printed.split('\n').filter(l => l.trim().length > 0);
    for (const line of body) {
      expect(line.startsWith('  '), `line not indented: ${JSON.stringify(line)}`).toBe(true);
    }
  });
});
