import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/**
 * tsconfig.json leaves test files out of the build, and vitest removes types
 * without checking them, so no step compiled a test file. An extensionless
 * relative `import()` that the build's node16 resolution rejects, a fixture
 * missing a required field, or an argument of the wrong type went unnoticed.
 * The last kind hid a test that could not fail: confidence.test.ts passed
 * numbers to `lengthTier(value: string)`, so every tier read 0.15 and its
 * ordering check held for any implementation.
 *
 * tsconfig.test.json compiles every file under src/ with the build's compiler
 * options and emits nothing; `npm run typecheck` runs it. These tests run it
 * too, so `npm test` fails on a type error in a test file.
 */

const ROOT = path.resolve(__dirname, '..');
const TSC = path.join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');

function testFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...testFilesUnder(full));
    else if (entry.name.endsWith('.test.ts')) out.push(fs.realpathSync(full));
  }
  return out;
}

describe('test files are type-checked', () => {
  it('tsconfig.test.json uses the build options and only turns off emit', () => {
    const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'tsconfig.test.json'), 'utf8'));
    expect(config.extends).toBe('./tsconfig.json');
    // A different module or moduleResolution here would accept imports the
    // build rejects, which is the gap this config closes.
    expect(Object.keys(config.compilerOptions ?? {})).toEqual(['noEmit']);
    expect(config.compilerOptions.noEmit).toBe(true);
  });

  it('every test file under src/ compiles without a type error', () => {
    const r = spawnSync(
      process.execPath,
      [TSC, '-p', 'tsconfig.test.json', '--listFiles', '--pretty', 'false'],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    );
    const lines = r.stdout.split('\n');

    const errors = lines.filter((line) => /\berror TS\d+:/.test(line));
    expect(errors, 'type errors under src/ (reproduce: npm run typecheck)').toEqual([]);
    expect(r.status, r.stderr).toBe(0);

    // The compile is only a check of the test files if it includes them.
    const compiled = new Set(
      lines
        .map((line) => line.trim())
        .filter((line) => line.endsWith('.test.ts') && fs.existsSync(line))
        .map((line) => fs.realpathSync(line)),
    );
    const left = testFilesUnder(path.join(ROOT, 'src'))
      .filter((file) => !compiled.has(file))
      .map((file) => path.relative(ROOT, file));
    expect(left, 'test files tsconfig.test.json does not compile').toEqual([]);
    expect(compiled.size).toBeGreaterThan(0);
  }, 120_000);
});
