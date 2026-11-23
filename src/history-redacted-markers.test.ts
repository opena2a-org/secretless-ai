import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'fs/promises';
import * as os from 'os';
import { scanHistory, cleanHistory } from './history';

/**
 * `scan --history` passes over a value `clean-history` already replaced with
 * `[REDACTED:<pattern id>]` (#471). The marker is 20 characters or more, so
 * `export NAME="[REDACTED:github-pat]"` was the `export NAME=<20 characters>`
 * the command patterns report, and the scan after one `clean-history` still
 * reported lines; a second `clean-history` rewrote them again.
 *
 * Every credential below is built at run time from pieces, so no line of this
 * file reads as one.
 */

vi.mock('fs/promises');
vi.mock('os');

const HOME = '/home/testuser';
const files = new Map<string, string>();

beforeEach(() => {
  files.clear();
  vi.mocked(os.homedir).mockReturnValue(HOME);
  vi.mocked(fs.readFile).mockReset().mockImplementation((async (p: unknown) => {
    const content = files.get(String(p));
    if (content === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    return content;
  }) as typeof fs.readFile);
  vi.mocked(fs.writeFile).mockReset().mockImplementation((async (p: unknown, data: unknown) => {
    files.set(String(p), String(data));
  }) as typeof fs.writeFile);
});

const mixed = (n: number): string => 'aB3dE6gH9k'.repeat(Math.ceil(n / 10)).slice(0, n);
const gh = (): string => ['gh', 'p_'].join('') + mixed(36);
const ant = (): string => ['sk', 'ant', 'api03', ''].join('-') + mixed(24);
const long = (): string => mixed(32);

function history(lines: string[]): void {
  files.set(`${HOME}/.bash_history`, `${lines.join('\n')}\n`);
}

const LINES = (): string[] => [
  `export GITHUB_TOKEN="${gh()}"`,
  `export GITHUB_TOKEN='${gh()}'`,
  `export GITHUB_TOKEN=${gh()}`,
  `export MY_SERVICE_TOKEN=${long()}`,
  `export MY_SERVICE_TOKEN="${long()}"`,
  `curl -H "Authorization: Bearer ${long()}" https://api.example.com`,
  `curl -H "Authorization: Bearer ${ant()}" https://api.example.com`,
  `tool --api-key ${long()} run`,
  `tool --api-key=${gh()} run`,
  'npx secretless-ai secret set STRIPE_KEY=not-a-real-value',
  `npx secretless-ai secret set GH="${gh()}"`,
  `npx secretless-ai secret set --meta app=web GH='${long()}'`,
  `echo ${ant()} && echo ${gh()}`,
  `psql postgres://admin:${mixed(12)}@db.internal:5432/app`,
  `: 1700000000:0;export API_KEY="${gh()}"`,
];

describe('scan --history after clean-history (#471)', () => {
  it('one clean-history leaves nothing for scan --history to report', async () => {
    history(['ls -la', ...LINES(), 'git status']);

    const before = await scanHistory();
    expect(before.findingCount).toBe(LINES().length);

    const cleaned = await cleanHistory();
    expect(cleaned.linesRedacted).toBe(LINES().length);
    expect(files.get(`${HOME}/.bash_history`)).toContain('[REDACTED:github-pat]');

    const after = await scanHistory();
    expect(after.findings).toEqual([]);
  });

  it('a second clean-history finds nothing to redact and writes nothing', async () => {
    history(LINES());
    await cleanHistory();
    const once = files.get(`${HOME}/.bash_history`);
    vi.mocked(fs.writeFile).mockClear();

    const again = await cleanHistory();
    expect(again.linesRedacted).toBe(0);
    expect(again.filesModified).toBe(0);
    expect(fs.writeFile).not.toHaveBeenCalled();
    expect(files.get(`${HOME}/.bash_history`)).toBe(once);
  });

  it('a credential on a line that also holds a marker is still reported', async () => {
    history([`export A="[REDACTED:github-pat]" B=${gh()}`]);
    const result = await scanHistory();
    expect(result.findings.map((f) => f.patternId)).toEqual(['github-pat']);
  });

  it('a marker with credential characters run on after it is not a redacted value', async () => {
    history([
      `export MY_SERVICE_TOKEN=[REDACTED:cmd-export]${long()}`,
      'npx secretless-ai secret set NAME=[REDACTED:cmd-secret-set]x',
    ]);
    const result = await scanHistory();
    expect(result.findings.map((f) => f.patternId)).toEqual(['cmd-export', 'cmd-secret-set']);
  });

  it('a value written as the marker, as a user may type it, is not reported', async () => {
    history([
      'export GITHUB_TOKEN="[REDACTED:github-pat]"',
      'npx secretless-ai secret set NAME=[REDACTED:cmd-secret-set]',
      'tool --api-key [REDACTED:cmd-api-key]',
      'npx secretless-ai secret set A="[REDACTED:github-pat]"',
      "npx secretless-ai secret set B='[REDACTED:github-pat]'",
    ]);
    const result = await scanHistory();
    expect(result.findings).toEqual([]);
  });
});
