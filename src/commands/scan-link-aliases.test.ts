/**
 * A finding the scan reached through a symbolic link and by its own path is
 * reported under its own path, and the link paths are listed (#398): in full
 * under `aliases` in `--json`, and on an `Also linked as:` line under the path
 * in the text report and the `--explain` view.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from './core';

// A line the gcp-service-account pattern matches. It holds no credential
// value, so the fixture is not credential-shaped.
const LINE = 'export const account = { "type": "service_account" };\n';

/** `src/app.ts` holding LINE, and a link to `src` under each name in `links`. */
function treeWithLinks(links: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-aliases-'));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src/app.ts'), LINE);
  for (const name of links) fs.symlinkSync('src', path.join(dir, name), 'dir');
  return dir;
}

function captureLog(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.map(String).join(' ')); });
  return lines;
}

/** The printed lines without colour, which these tests do not assert. */
function plain(lines: string[]): string[] {
  // eslint-disable-next-line no-control-regex
  return lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '').split('\n');
}

type JsonFinding = { file: string; aliases?: string[] };

describe('scan output for a file also reached through a link (#398)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('--json reports the path with no link in it and lists the link path under aliases', async () => {
    const dir = treeWithLinks(['.alias']);
    const lines = captureLog();
    const code = await runScan(dir, { json: true });
    const doc = JSON.parse(lines.join('\n')) as { findings: JsonFinding[]; summary: { total: number } };
    expect(code).toBe(1);
    expect(doc.summary.total).toBe(1);
    expect(doc.findings.map(f => ({ file: f.file, aliases: f.aliases }))).toEqual([
      { file: 'src/app.ts', aliases: ['.alias/app.ts'] },
    ]);
  });

  it('the text report gives the link path on the line under the path', async () => {
    const dir = treeWithLinks(['.alias']);
    const lines = captureLog();
    await runScan(dir, {});
    const out = plain(lines);
    const at = out.findIndex(l => l.endsWith(' src/app.ts:1'));
    expect(at).toBeGreaterThanOrEqual(0);
    expect(out[at + 1]).toMatch(/^ {2}\S Also linked as: \.alias\/app\.ts$/);
    expect(out.join('\n')).not.toContain('.alias/app.ts:1');
  });

  it('--explain gives the link path on the line under the path', async () => {
    const dir = treeWithLinks(['.alias']);
    const lines = captureLog();
    await runScan(dir, { explain: true });
    const out = plain(lines);
    const at = out.indexOf('         src/app.ts:1');
    expect(at).toBeGreaterThanOrEqual(0);
    expect(out[at + 1]).toBe('         Also linked as: .alias/app.ts');
  });

  it('the text report and --explain name three link paths and count the rest, which --json lists', async () => {
    const links = ['.a1', '.a2', '.a3', '.a4', '.a5'];
    const dir = treeWithLinks(links);

    const text = captureLog();
    await runScan(dir, {});
    expect(plain(text)).toContainEqual(expect.stringMatching(
      /^ {2}\S Also linked as: \.a1\/app\.ts, \.a2\/app\.ts, \.a3\/app\.ts and 2 more$/,
    ));
    vi.restoreAllMocks();

    const explain = captureLog();
    await runScan(dir, { explain: true });
    expect(plain(explain)).toContain('         Also linked as: .a1/app.ts, .a2/app.ts, .a3/app.ts and 2 more');
    vi.restoreAllMocks();

    const json = captureLog();
    await runScan(dir, { json: true });
    const doc = JSON.parse(json.join('\n')) as { findings: JsonFinding[] };
    expect(doc.findings.map(f => ({ file: f.file, aliases: f.aliases }))).toEqual([
      { file: 'src/app.ts', aliases: links.map(l => `${l}/app.ts`) },
    ]);
  });

  it('CONTROL: a file reached by one path has no Also linked as line and no aliases', async () => {
    const dir = treeWithLinks([]);
    const text = captureLog();
    await runScan(dir, {});
    expect(plain(text).join('\n')).toContain('src/app.ts:1');
    expect(plain(text).join('\n')).not.toContain('Also linked as');
    vi.restoreAllMocks();

    const json = captureLog();
    await runScan(dir, { json: true });
    const doc = JSON.parse(json.join('\n')) as { findings: JsonFinding[] };
    expect(doc.findings).toHaveLength(1);
    expect(doc.findings[0]).not.toHaveProperty('aliases');
  });
});
