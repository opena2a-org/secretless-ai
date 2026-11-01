/**
 * One decision on a plaintext secret in an MCP server's env, read the same way
 * by `scan`, `scan-staged`, the pre-commit hook, `status`, `verify` and
 * `mcp-status` (src/mcp/env-secrets.ts). A literal under a secret's name in a
 * project MCP config is reported by each of them; an empty value, a
 * whole-value expansion and a placeholder by each of none; a value a
 * credential pattern matches once, under that pattern's name. No preview
 * carries a character run of an env secret, and a per-user config is left to
 * `mcp-status`. Spawns the built entry point (`dist/cli.js`) in a sandbox with
 * nothing inherited (src/mcp-env-secret.test-support.ts).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import { scoreFinding } from './confidence';
import { CREDENTIAL_PATTERNS } from './patterns';
import {
  type Sandbox,
  git,
  githubToken,
  holdsNoPlaceholder,
  leaksRun,
  literalValue,
  makeSandbox,
  removeSandbox,
  runCli,
  seeded,
  server,
  write,
} from './mcp-env-secret.test-support';

let sb: Sandbox;
beforeEach(() => {
  sb = makeSandbox();
});
afterEach(() => {
  removeSandbox(sb);
});

interface JsonFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: string;
  preview: string;
  fix: string;
  confidence: number;
}

function jsonFindings(args: string[] = ['scan', '.', '--json']): { code: number | null; findings: JsonFinding[]; out: string } {
  const run = runCli(sb, args);
  return { code: run.code, findings: (JSON.parse(run.stdout) as { findings: JsonFinding[] }).findings, out: run.out };
}

/** A git repository in the project, with the hook `hook install` writes. */
function repoWithHook(): void {
  expect(git(sb, ['init', '-q']).code).toBe(0);
  expect(runCli(sb, ['hook', 'install']).code).toBe(0);
}

/** `${...}` built from parts, so no line of this file reads as an expansion of its own. */
const expansion = (inner: string): string => ['$', '{', inner, '}'].join('');

describe('one literal secret in a project MCP config, read by all six commands', () => {
  const cases: Array<[string, string]> = [
    ['a server that runs its own command', 'npx'],
    ['a server that runs through the wrapper', 'secretless-mcp'],
  ];
  for (const [label, command] of cases) {
    it(`${label}: scan exits 1, scan-staged and the hook refuse, status counts 1, verify fails and mcp-status lists it as exposed`, () => {
      const value = literalValue(101);
      write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: value }, command) } }, null, 2));

      const scanned = runCli(sb, ['scan', '.']);
      expect(scanned.code).toBe(1);
      expect(scanned.out).toContain('MCP Server Env Secret');
      expect(scanned.out).toContain('.mcp.json:');

      const status = runCli(sb, ['status', '--json']);
      expect((JSON.parse(status.stdout) as { secretsFound: number }).secretsFound).toBe(1);

      const verified = runCli(sb, ['verify']);
      expect(verified.out).toContain('FAIL');
      expect(verified.out).toContain('MCP Server Env Secret');
      expect(verified.out).not.toContain('AI context: clean');

      const mcpStatus = runCli(sb, ['mcp-status']);
      expect(mcpStatus.out).toContain('svc: EXPOSED (1 plaintext secret(s))');

      repoWithHook();
      expect(git(sb, ['add', '.mcp.json']).code).toBe(0);
      const staged = runCli(sb, ['scan-staged']);
      expect(staged.code).toBe(1);
      expect(staged.out).toContain('MCP Server Env Secret in .mcp.json:');
      const commit = git(sb, ['commit', '-q', '-m', 'add config']);
      expect(commit.code).not.toBe(0);
      expect(commit.out).toContain('Blocked commit');

      for (const run of [scanned, status, verified, mcpStatus, staged, commit]) {
        expect(leaksRun(run.out, [value])).toBe(false);
      }
    });
  }
});

describe('values the decision does not count read clean in all six commands', () => {
  it('an empty value, a whole-value expansion and a placeholder: scan exits 0, the commit goes through, status counts 0, verify reads clean, mcp-status lists each server clean', () => {
    const placeholder = ['your', '_service', '_key'].join('');
    const servers = {
      empty: server({ MY_SERVICE_API_KEY: '' }),
      braces: server({ MY_SERVICE_API_KEY: expansion('MY_SERVICE_API_KEY') }),
      fallback: server({ MY_SERVICE_API_KEY: expansion('MY_SERVICE_API_KEY:-') }),
      envform: server({ MY_SERVICE_API_KEY: expansion('env:MY_SERVICE_API_KEY') }),
      input: server({ MY_SERVICE_API_KEY: expansion('input:service-key') }),
      placeholder: server({ MY_SERVICE_API_KEY: placeholder }),
    };
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: servers }, null, 2));

    const scanned = runCli(sb, ['scan', '.']);
    expect(scanned.code).toBe(0);
    expect(scanned.out).toContain('No hardcoded credentials found.');
    expect((JSON.parse(runCli(sb, ['status', '--json']).stdout) as { secretsFound: number }).secretsFound).toBe(0);
    expect(runCli(sb, ['verify']).out).toContain('AI context: clean');

    const mcpStatus = runCli(sb, ['mcp-status']).out;
    expect(mcpStatus).not.toContain('EXPOSED');
    for (const name of Object.keys(servers)) {
      expect(mcpStatus).toContain(`    * ${name}: clean (no secrets in env)\n`);
    }

    repoWithHook();
    expect(git(sb, ['add', '.mcp.json']).code).toBe(0);
    expect(runCli(sb, ['scan-staged']).code).toBe(0);
    expect(git(sb, ['commit', '-q', '-m', 'add config']).code).toBe(0);
  });

  it('a GITHUB_TOKEN env value holding a GitHub token is reported once, under its pattern name, by each command', () => {
    const token = githubToken(201);
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { gh: server({ GITHUB_TOKEN: token }) } }, null, 2));

    const { code, findings, out } = jsonFindings();
    expect(code).toBe(1);
    expect(findings.map((f) => f.patternName)).toEqual(['GitHub Token']);
    expect((JSON.parse(runCli(sb, ['status', '--json']).stdout) as { secretsFound: number }).secretsFound).toBe(1);
    const verified = runCli(sb, ['verify']).out;
    expect(verified.match(/GitHub Token/g)).toHaveLength(1);
    expect(verified).not.toContain('MCP Server Env Secret');
    const mcpStatus = runCli(sb, ['mcp-status']).out;
    expect(mcpStatus).toContain('gh: EXPOSED (1 plaintext secret(s))');

    repoWithHook();
    expect(git(sb, ['add', '.mcp.json']).code).toBe(0);
    const staged = runCli(sb, ['scan-staged']).out;
    expect(staged.match(/ in \.mcp\.json:/g)).toHaveLength(1);
    expect(staged).toContain('GitHub Token in .mcp.json:');
    for (const text of [out, verified, mcpStatus, staged]) expect(leaksRun(text, [token])).toBe(false);
  });
});

describe('a preview never carries an env secret', () => {
  /** Every output form `scan` writes: text, --json and --format sarif. */
  function allForms(): string[] {
    return [runCli(sb, ['scan', '.']).out, runCli(sb, ['scan', '.', '--json']).out, runCli(sb, ['scan', '.', '--format', 'sarif']).out];
  }

  it('a one-line .mcp.json whose env key is written with a \\u escape: one finding, its preview built from the key', () => {
    const value = literalValue(301);
    const visible = literalValue(302, 10);
    write(
      sb.project,
      '.mcp.json',
      `{"mcpServers":{"svc":{"command":"npx","args":["-y","svc-mcp"],"env":{"LOG_FORMAT":"${visible}","\\u004dY_SERVICE_API_KEY":"${value}"}}}}\n`,
    );

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      file: '.mcp.json',
      line: 1,
      patternId: 'mcp-env-secret',
      patternName: 'MCP Server Env Secret',
      severity: 'critical',
      preview: '"MY_SERVICE_API_KEY": "[MCP Server Env Secret REDACTED]"',
    });
    for (const output of allForms()) expect(leaksRun(output, [value])).toBe(false);
  });

  it('a duplicate key, one value written with \\/, two entries on one line: each line one finding, no run of any value', () => {
    const first = literalValue(311);
    const [left, right] = [literalValue(312, 20), literalValue(313, 19)];
    const last = literalValue(314);
    const visible = literalValue(315, 10);
    write(
      sb.project,
      '.mcp.json',
      [
        '{',
        '  "mcpServers": {',
        `    "one": { "command": "npx", "env": { "SVC_API_KEY": "${first}" } },`,
        `    "two": { "command": "npx", "env": { "LOG_FORMAT": "${visible}", "SVC_API_KEY": "${left}\\/${right}", "SVC_API_KEY": "${last}" } }`,
        '  }',
        '}',
        '',
      ].join('\n'),
    );

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    expect(findings.map((f) => [f.line, f.patternId, f.preview]).sort()).toEqual([
      [3, 'mcp-env-secret', '"SVC_API_KEY": "[MCP Server Env Secret REDACTED]"'],
      [4, 'mcp-env-secret', '"SVC_API_KEY": "[MCP Server Env Secret REDACTED]"'],
    ]);
    const planted = [first, `${left}/${right}`, `${left}\\/${right}`, last];
    for (const output of [...allForms(), runCli(sb, ['mcp-status']).out]) expect(leaksRun(output, planted)).toBe(false);
    expect(runCli(sb, ['mcp-status']).out).toContain('two: EXPOSED (2 plaintext secret(s))');
  });

  it('the preview of another finding on the line masks the env secret as written, escapes included, and prints the value it does not mask', () => {
    const [left, right] = [literalValue(321, 20), literalValue(322, 19)];
    const visible = literalValue(323, 8);
    const token = githubToken(324);
    write(
      sb.project,
      '.mcp.json',
      `{"mcpServers":{"svc":{"env":{"LOG_FORMAT":"${visible}","SVC_API_KEY":"${left}\\/${right}","GITHUB_TOKEN":"${token}"}}}}\n`,
    );

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    const byName = new Map(findings.map((f) => [f.patternName, f]));
    expect([...byName.keys()].sort()).toEqual(['GitHub Token', 'MCP Server Env Secret']);
    // The preview is cut at 80 characters, inside the marker.
    expect(byName.get('GitHub Token')!.preview).toContain(visible);
    expect(byName.get('GitHub Token')!.preview).toContain('"SVC_API_KEY":"[MCP Server');
    const forms = allForms();
    expect(forms[0]).toContain(visible);
    for (const output of forms) expect(leaksRun(output, [`${left}/${right}`, `${left}\\/${right}`, token])).toBe(false);
  });
});

describe('the env rule reads project MCP configs only', () => {
  it('a GitHub token in the args of .windsurf/mcp.json leaves verify reading clean', () => {
    const token = githubToken(401);
    write(sb.project, '.windsurf/mcp.json', JSON.stringify({ mcpServers: { svc: { command: 'npx', args: ['-y', 'svc-mcp', '--token', token], env: {} } } }, null, 2));

    const verified = runCli(sb, ['verify']).out;
    expect(verified).toContain('AI context: clean');
    expect(verified).not.toContain('FAIL');
    expect(leaksRun(verified, [token])).toBe(false);
  });

  it('a literal in the env of a per-user config leaves scan, status and verify as they were; mcp-status lists it', () => {
    const userValue = literalValue(411);
    const localValue = literalValue(412);
    const desktopValue = literalValue(413);
    const cursorValue = literalValue(414);
    const claudeJson = write(
      sb.home,
      '.claude.json',
      JSON.stringify(
        {
          mcpServers: { user: server({ MY_SERVICE_API_KEY: userValue }) },
          projects: { [sb.project]: { mcpServers: { local: server({ MY_SERVICE_API_KEY: localValue }) } } },
        },
        null,
        2,
      ),
    );
    const desktop = write(
      sb.home,
      path.join('Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      JSON.stringify({ mcpServers: { desk: server({ MY_SERVICE_API_KEY: desktopValue }) } }, null, 2),
    );
    const cursor = write(sb.home, path.join('.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { cur: server({ MY_SERVICE_API_KEY: cursorValue }) } }, null, 2));

    expect(runCli(sb, ['scan', '.']).code).toBe(0);
    for (const file of [claudeJson, desktop, cursor]) expect(runCli(sb, ['scan', file]).code).toBe(0);
    // The home directory scanned as a project: its .cursor/mcp.json is the per-user config.
    expect(runCli(sb, ['scan', '.'], sb.home).code).toBe(0);
    expect((JSON.parse(runCli(sb, ['status', '--json']).stdout) as { secretsFound: number }).secretsFound).toBe(0);
    expect(runCli(sb, ['verify']).out).toContain('AI context: clean');

    const mcpStatus = runCli(sb, ['mcp-status']).out;
    for (const name of ['user', 'local', 'desk', 'cur']) expect(mcpStatus).toContain(`${name}: EXPOSED (1 plaintext secret(s))`);
  });

  it('scan --show-placeholders reports an env placeholder with exit 1, as it reports a placeholder a pattern matches; scan without it hides the value and says so', () => {
    const placeholder = ['your', '_service', '_key'].join('');
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: placeholder }) } }, null, 2));

    const shown = runCli(sb, ['scan', '.', '--show-placeholders']);
    expect(shown.code).toBe(1);
    expect(shown.out).toContain('MCP Server Env Secret');
    const hidden = runCli(sb, ['scan', '.']);
    expect(hidden.code).toBe(0);
    expect(hidden.out).toContain('1 value looked like a placeholder and was hidden.');
  });
});

describe('every occurrence, the confidence floor, the next step and a value led by $', () => {
  it('a duplicate key whose last value is empty still reports the earlier literal: every occurrence is read', () => {
    const value = literalValue(501);
    write(
      sb.project,
      '.mcp.json',
      [
        '{',
        '  "mcpServers": {',
        '    "svc": {',
        '      "command": "npx",',
        '      "env": {',
        `        "MY_SERVICE_API_KEY": "${value}",`,
        '        "MY_SERVICE_API_KEY": ""',
        '      }',
        '    }',
        '  }',
        '}',
        '',
      ].join('\n'),
    );

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    expect(findings.map((f) => [f.line, f.patternId])).toEqual([[6, 'mcp-env-secret']]);
    expect(runCli(sb, ['mcp-status']).out).toContain('svc: EXPOSED (1 plaintext secret(s))');
  });

  it('scan with no --min-confidence reports the env finding at the confidence its value and path give', () => {
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(511) }) } }, null, 2));

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBeGreaterThan(0.5);
    expect(findings[0].confidence).toBeLessThan(0.6);
    // A floor above that score hides it, as it hides a pattern finding.
    const floored = runCli(sb, ['scan', '.', '--min-confidence', '0.6']);
    expect(floored.code).toBe(0);
  });

  it('a line holding both a below-floor pattern match and an env literal still reports the env finding', () => {
    // A telegram-shaped value with few distinct characters scores low; a literal of 40
    // distinct characters scores higher. The floor goes between the two.
    const telegram = ['111111111', ':', '1'.repeat(30), 'abcde'].join('');
    const telegramPattern = CREDENTIAL_PATTERNS.find((p) => p.id === 'telegram-bot')!;
    expect(CREDENTIAL_PATTERNS.find((p) => p.regex.test(telegram))?.id).toBe('telegram-bot');
    let literal = '';
    for (let s = 521; ; s++) {
      literal = [...seeded(s, 400)].filter((ch, i, all) => all.indexOf(ch) === i).join('').slice(0, 40);
      if (literal.length === 40 && holdsNoPlaceholder(literal) && !CREDENTIAL_PATTERNS.some((p) => p.regex.test(literal))) break;
    }
    const low = scoreFinding({ pattern: telegramPattern, value: telegram.match(telegramPattern.regex)![0], filePath: '.mcp.json' }).score;
    const high = scoreFinding({ pattern: { id: 'mcp-env-secret', regex: /(?:)/ }, value: literal, filePath: '.mcp.json' }).score;
    expect(low).toBeLessThan(high);
    const floor = (Math.ceil(((low + high) / 2) * 1000) / 1000).toFixed(3);
    expect(Number(floor)).toBeGreaterThan(low);
    expect(Number(floor)).toBeLessThanOrEqual(high);
    write(sb.project, '.mcp.json', `{"mcpServers":{"svc":{"command":"npx","args":["--chat","${telegram}"],"env":{"MY_SERVICE_API_KEY":"${literal}"}}}}\n`);

    const { code, findings } = jsonFindings(['scan', '.', '--json', '--min-confidence', floor]);
    expect(code).toBe(1);
    expect(findings.map((f) => [f.line, f.patternId])).toEqual([[1, 'mcp-env-secret']]);
  });

  it('after an env finding the next step names protect-mcp for a .mcp.json and the move-and-rotate step otherwise, not init', () => {
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(531) }) } }, null, 2));
    const atRoot = runCli(sb, ['scan', '.']).out;
    expect(atRoot).toContain('MCP env secrets:    Run npx secretless-ai protect-mcp to encrypt exposed secrets.');
    expect(atRoot).toContain('Fix: Run npx secretless-ai protect-mcp to encrypt exposed secrets.');
    expect(atRoot).not.toContain('npx secretless-ai init');
    const explained = runCli(sb, ['scan', '.', '--explain']).out;
    expect(explained).toContain('MCP env secrets: Run npx secretless-ai protect-mcp to encrypt exposed secrets.');
    expect(explained).not.toContain('npx secretless-ai init');

    removeSandbox(sb);
    sb = makeSandbox();
    write(sb.project, 'mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(532) }) } }, null, 2));
    const bare = runCli(sb, ['scan', '.']).out;
    expect(bare).toContain('MCP env secrets:    Move each value out of its file and rotate it, then run npx secretless-ai mcp-status again.');
    expect(bare).not.toContain('npx secretless-ai init');

    removeSandbox(sb);
    sb = makeSandbox();
    write(sb.project, path.join('sub', '.mcp.json'), JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: literalValue(533) }) } }, null, 2));
    // A finding of another kind still has init as its step.
    write(sb.project, 'config.json', JSON.stringify({ token: githubToken(534) }, null, 2));
    const nested = runCli(sb, ['scan', '.']).out;
    expect(nested).toContain('MCP env secrets:    Run npx secretless-ai protect-mcp in sub to encrypt exposed secrets.');
    expect(nested).toContain('Protect now:        npx secretless-ai init');
  });

  it('a value of $ followed by 39 random letters and digits is a literal, not an expansion', () => {
    const value = `$${literalValue(541, 39)}`;
    write(sb.project, '.mcp.json', JSON.stringify({ mcpServers: { svc: server({ MY_SERVICE_API_KEY: value }) } }, null, 2));

    const { code, findings } = jsonFindings();
    expect(code).toBe(1);
    expect(findings.map((f) => f.patternId)).toEqual(['mcp-env-secret']);
    expect(runCli(sb, ['mcp-status']).out).toContain('svc: EXPOSED (1 plaintext secret(s))');
  });
});
