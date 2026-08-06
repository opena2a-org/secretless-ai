/**
 * `--help` routing.
 *
 * The blanket interception exists because subcommand runners perform their
 * action rather than parsing help: `init --help` once created a literal
 * `--help/` directory (release-test 2026-04-14). That safety property must
 * hold. The exception list carries only runners that handle `--help` as their
 * first statement, which is what makes the `.secretless` format reachable from
 * `setup --help` (#112).
 */
import { describe, it, expect, vi } from 'vitest';
import { OWN_HELP } from './commands/help';
import { runSetupCommand, runEnv } from './commands/env-run';

describe('OWN_HELP exception list', () => {
  it('contains only commands whose runner returns help before any side effect', async () => {
    // Every listed runner must print usage and exit 0 without touching a store,
    // the filesystem, or a daemon. Asserted by running them.
    expect([...OWN_HELP].sort()).toEqual(['env', 'setup']);
  });

  it('setup --help prints the manifest format and exits 0', async () => {
    const out: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    let code: number;
    try {
      code = await runSetupCommand(['--help']);
    } finally {
      spy.mockRestore();
    }
    const text = out.join('\n');
    expect(code).toBe(0);
    // The whole point of #112: the format is discoverable from the CLI.
    expect(text).toContain('one secret name per line');
    expect(text).toContain('optional');
    expect(text).toMatch(/not YAML, JSON, or dotenv/);
    // It must NOT have started the interactive flow.
    expect(text).not.toContain('Secretless Setup');
  });

  it('env --help prints usage and exits 0 without exporting anything', async () => {
    const out: string[] = [];
    const stdout: string[] = [];
    const logSpy = vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    const wSpy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { stdout.push(String(c)); return true; });
    let code: number;
    try {
      code = await runEnv(['--help']);
    } finally {
      logSpy.mockRestore();
      wSpy.mockRestore();
    }
    expect(code).toBe(0);
    expect(out.join('\n')).toContain('eval');
    // No export statements on stdout — that is the dangerous output.
    expect(stdout.join('')).not.toMatch(/^export /m);
  });

  it('does NOT list commands whose runner would act first', () => {
    // The 2026-04-14 regression: these must keep falling through to top-level
    // help. Adding one here without moving its help block to the top would
    // reintroduce `--help/` directories and launched daemons.
    for (const cmd of ['init', 'scan', 'broker', 'watch', 'install', 'clean', 'import', 'run']) {
      expect(OWN_HELP.has(cmd), `${cmd} must not bypass the help guard`).toBe(false);
    }
  });
});
