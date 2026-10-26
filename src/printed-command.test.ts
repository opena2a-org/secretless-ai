import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { printedCommand } from './printed-command';
import { VERSION } from './commands/utils';

/**
 * The renderer every command the wrapper, protect-mcp and mcp-status print
 * goes through: the node binary and this package's CLI as two quoted paths
 * when the script is this package's CLI, else this build's exact version for
 * npx, else the unversioned form. The surface files write no npx command
 * themselves, and hook-prefix.ts takes its checks from here.
 */

const ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(ROOT, 'dist', 'cli.js');
const source = (file: string) => fs.readFileSync(path.join(ROOT, 'src', file), 'utf-8');

let scratch: string;
let foreign: string;

beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-renderer-'));
  // A script with no package.json above it.
  foreign = path.join(scratch, 'dist', 'cli.js');
  fs.mkdirSync(path.dirname(foreign), { recursive: true });
  fs.writeFileSync(foreign, '');
});

afterAll(() => fs.rmSync(scratch, { recursive: true, force: true }));

describe('the renderer names this build in the first form that applies', () => {
  it("tier (a): this package's CLI script and a node binary give the two quoted paths, whatever the version", () => {
    for (const version of [VERSION, 'unknown']) {
      expect(printedCommand('mcp-status', version, { execPath: process.execPath, pathEnv: '', script: CLI_PATH })).toBe(
        `'${process.execPath}' '${CLI_PATH}' mcp-status`,
      );
    }
  });

  it('tier (a) writes a quote in a path the way a shell reads it back', () => {
    const quoted = path.join(scratch, "it's", 'dist', 'cli.js');
    fs.mkdirSync(path.dirname(quoted), { recursive: true });
    fs.writeFileSync(quoted, '');
    fs.writeFileSync(path.join(scratch, "it's", 'package.json'), JSON.stringify({ name: 'secretless-ai' }));

    expect(printedCommand('protect-mcp', VERSION, { execPath: process.execPath, pathEnv: '', script: quoted })).toBe(
      `'${process.execPath}' '${quoted.replace(/'/g, "'\\''")}' protect-mcp`,
    );
  });

  it('tier (b): a script with no package.json above it gives the pinned npx form', () => {
    expect(printedCommand('protect-mcp', VERSION, { execPath: process.execPath, pathEnv: '', script: foreign })).toBe(
      `npx secretless-ai@${VERSION} protect-mcp`,
    );
  });

  it('tier (b): a node binary whose path carries a control character gives the pinned npx form', () => {
    const node = path.join(scratch, 'no\x07de');
    expect(printedCommand('protect-mcp', VERSION, { execPath: node, pathEnv: '', script: CLI_PATH })).toBe(
      `npx secretless-ai@${VERSION} protect-mcp`,
    );
  });

  it('tier (b): a relative script path gives the pinned npx form', () => {
    expect(printedCommand('mcp-status', VERSION, { execPath: process.execPath, pathEnv: '', script: path.join('dist', 'cli.js') })).toBe(
      `npx secretless-ai@${VERSION} mcp-status`,
    );
  });

  it("tier (c): with a version that is not an exact one, such as 'unknown', the unversioned npx form", () => {
    for (const version of ['unknown', 'latest', '^0.24.0', '0.24', '']) {
      expect(printedCommand('mcp-status', version, { execPath: process.execPath, pathEnv: '', script: foreign })).toBe(
        'npx secretless-ai mcp-status',
      );
    }
  });
});

describe('one renderer: the surface files name no npx command, and hook-prefix.ts shares its checks', () => {
  it('the wrapper, mcp.ts and protect.ts hold no npx command of either form; the renderer holds the two', () => {
    for (const file of ['mcp-wrapper.ts', path.join('commands', 'mcp.ts'), path.join('mcp', 'protect.ts')]) {
      expect(source(file).split('\n').filter((line) => line.includes('npx secretless-ai')), file).toEqual([]);
    }
    expect(source('printed-command.ts').split('\n').filter((line) => /npx secretless-ai(@|\b)/.test(line))).toHaveLength(2);
  });

  it('hook-prefix.ts imports the path, CLI and version checks from the renderer instead of defining them', () => {
    const hook = source('hook-prefix.ts');
    expect(hook).toMatch(/import \{[^}]*\bisExactVersion\b[^}]*\bisOwnCli\b[^}]*\bwritablePath\b[^}]*\} from '\.\/printed-command';/);
    for (const name of ['writablePath', 'isFile', 'isOwnCli', 'isExactVersion']) {
      expect(hook, name).not.toMatch(new RegExp(`function ${name}\\(`));
    }
    expect(hook).not.toContain('\\d+\\.\\d+\\.\\d+');
  });
});
