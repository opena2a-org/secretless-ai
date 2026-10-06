import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as ts from 'typescript';

/**
 * `scan()` appends to a coverage collector only when the caller supplies it, so
 * a caller that builds its own stats object and leaves one out reads that gap
 * as clean. `status` did exactly that: its object had no `oversize` array, so a
 * tree holding one file over the size cap read `scanIncomplete: false` in
 * `status --json`, while `scan --json` over the same tree reported
 * `oversize: 1` and exited 1. `vault scan` built the same partial object and
 * printed "No hardcoded credentials found." over that tree.
 *
 * The transcript and watch modules are mocked so `status` reads nothing from
 * the operator's home directory.
 */

vi.mock('./transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));
vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { status } from './status';
import { vaultScan } from './vault-core';
import { SOURCE_FILE_CAP_BYTES } from './scan';

const ROOT = path.resolve(__dirname, '..');

/** A tree holding one source file of exactly `bytes` bytes, with no credential in it. */
function treeWithSourceFile(bytes: number): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-callers-'));
  const head = '// x\n';
  fs.writeFileSync(path.join(dir, 'big.js'), head + 'a'.repeat(bytes - head.length));
  return dir;
}

describe('status over a file skipped for size', () => {
  let dir: string;
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('reads scanIncomplete true: the file was never opened', async () => {
    dir = treeWithSourceFile(SOURCE_FILE_CAP_BYTES + 1024);
    const s = await status(dir);
    expect(s.secretsFound).toBe(0);
    expect(s.scanIncomplete).toBe(true);
  });

  it('CONTROL: the same file under the cap reads scanIncomplete false', async () => {
    dir = treeWithSourceFile(1024);
    const s = await status(dir);
    expect(s.secretsFound).toBe(0);
    expect(s.scanIncomplete).toBe(false);
  });
});

describe('vault scan over a file skipped for size', () => {
  let dir: string;
  let lines: string[];
  beforeEach(() => {
    lines = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { lines.push(args.join(' ')); });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('does not print the unqualified clean line, and names the skip', async () => {
    dir = treeWithSourceFile(SOURCE_FILE_CAP_BYTES + 1024);
    await vaultScan(dir);
    const out = lines.join('\n');
    expect(out).not.toContain('No hardcoded credentials found.');
    expect(out).toContain('1 file(s) skipped for size');
  });

  it('CONTROL: the same file under the cap prints the clean line', async () => {
    dir = treeWithSourceFile(1024);
    await vaultScan(dir);
    expect(lines.join('\n')).toContain('No hardcoded credentials found.');
  });
});

/**
 * The class, not the two instances above. Every call to `scan()` in the files
 * the build compiles is found through the type checker, so an aliased import,
 * a destructured dynamic import and a namespace call are all reached; a regex
 * over the source would miss them or match prose in comments. Each call must
 * pass a third argument whose type carries every `ScanStats` member as
 * non-optional. The member list is read from the interface itself, so a
 * collector added to `ScanStats` later reds this test at every caller that
 * does not pass it.
 */
describe('every non-test caller of scan() passes every coverage collector', () => {
  it('finds the callers and reports none that drops a collector', () => {
    const configPath = path.join(ROOT, 'tsconfig.json');
    const { config } = ts.readConfigFile(configPath, ts.sys.readFile);
    // The build's own input set: tsconfig excludes the test files.
    const parsed = ts.parseJsonConfigFileContent(config, ts.sys, ROOT);
    const program = ts.createProgram(parsed.fileNames, parsed.options);
    const checker = program.getTypeChecker();

    const scanSource = program.getSourceFile(path.join(ROOT, 'src', 'scan.ts'))!;
    const exported = checker.getExportsOfModule(checker.getSymbolAtLocation(scanSource)!);
    const scanDecl = exported.find(s => s.name === 'scan')!.valueDeclaration;
    const statsType = checker.getDeclaredTypeOfSymbol(exported.find(s => s.name === 'ScanStats')!);
    const collectors = checker.getPropertiesOfType(statsType).map(p => p.name);
    expect(scanDecl).toBeDefined();
    expect(collectors).toEqual(expect.arrayContaining(['truncated', 'unreadable', 'oversize', 'skips']));

    const callers: string[] = [];
    const gaps: string[] = [];
    for (const sf of program.getSourceFiles()) {
      if (sf.isDeclarationFile || !sf.fileName.startsWith(path.join(ROOT, 'src'))) continue;
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node) && checker.getResolvedSignature(node)?.declaration === scanDecl) {
          const rel = path.relative(ROOT, sf.fileName).replace(/\\/g, '/');
          const where = `${rel}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`;
          callers.push(rel);
          const statsArg = node.arguments[2];
          if (!statsArg) {
            gaps.push(`${where} passes no stats object`);
          } else {
            const argType = checker.getTypeAtLocation(statsArg);
            for (const name of collectors) {
              const prop = checker.getPropertyOfType(argType, name);
              if (!prop || (prop.flags & ts.SymbolFlags.Optional)) gaps.push(`${where} does not pass ${name}`);
            }
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(sf);
    }

    // CONTROL: the walk reaches a named import, a destructured dynamic import
    // and the CLI, so an empty gap list is a measurement, not an empty search.
    expect(callers).toEqual(expect.arrayContaining(['src/status.ts', 'src/vault-core.ts', 'src/commands/core.ts']));
    expect(gaps).toEqual([]);
  }, 60_000);
});
