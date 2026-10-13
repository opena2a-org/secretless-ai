import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * What `scan` tells the user to do next.
 *
 * A key found in a `.env` file got the fix "Move to env var STRIPE_SECRET_KEY",
 * where it already is, and the tool's own `import` command, which moves the
 * value into the secret store, was never named. The Next Steps block printed
 * `Protect now: npx secretless-ai init` in a project `status` reports
 * protected.
 *
 * The transcript and watcher modules are mocked and HOME is a scratch
 * directory, so `status` and the Next Steps check read only the project.
 */

vi.mock('../transcript', () => ({
  discoverTranscripts: () => [],
  scanTranscriptFile: () => ({ findings: [], redacted: '' }),
}));

vi.mock('../watch', () => ({ isWatchRunning: () => false }));

import { runScan } from './core';
import { scan, fixFor } from '../scan';
import { status } from '../status';
import { init } from '../init';
import { shellQuote } from '../display-safe';
import { CREDENTIAL_PATTERNS } from '../patterns';

// Assembled from parts so no line of this file reads as a credential.
const STRIPE_KEY = ['sk', '_live_', '51Q7bY2nR9vX4mL6pT8w', 'Z3cF5hJ1dG0sA7eU2iO4'].join('');
const OPENAI_KEY = ['sk-', 'proj-', 'A1B2C3D4E5F6G7H8I9J0', 'K1L2M3N4O5P6Q7R8S9T0'].join('');

const STRIPE_ROTATE = 'Rotate at dashboard.stripe.com > Developers > API Keys.';
const INIT_LINE = 'Protect now:        npx secretless-ai init';

let root: string;
let home: string;
let project: string;
let savedHome: string | undefined;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-remedies-'));
  home = path.join(root, 'home');
  project = path.join(root, 'project');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  savedHome = process.env.HOME;
  process.env.HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  vi.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

function write(rel: string, content: string): string {
  const full = path.join(project, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

function capture(): string[] {
  const lines: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
    lines.push(a.map(String).join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
  });
  return lines;
}

/** The lines of one finding block, from its `file:line` row to the next blank line. */
function block(lines: string[], location: string): string[] {
  const start = lines.findIndex(l => l.includes(`│ ${location}`));
  expect(start, `no finding at ${location}`).toBeGreaterThan(-1);
  const end = lines.findIndex((l, i) => i > start && l.trim() === '');
  return lines.slice(start, end === -1 ? undefined : end);
}

function envFix(operand: string, rotate: string): string {
  return `Store it with npx secretless-ai import ${operand}, delete the line, `
    + `and start the app with npx secretless-ai run -- <command>. ${rotate}`;
}

describe('a key in a real .env file', () => {
  it('names import for the .env file and keeps the rotation text; a source file keeps "Move to env var"', async () => {
    write('.env', `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`);
    write('app.js', `const k = "${OPENAI_KEY}";\n`);

    const lines = capture();
    expect(await runScan(project)).toBe(1);

    const env = block(lines, '.env:1');
    expect(env.filter(l => l.includes('Move to env var'))).toEqual([]);
    // The project lies outside the shell's cwd, so the operand is its full path.
    expect(env).toContain(`  │ Fix: ${envFix(shellQuote(path.join(project, '.env')), STRIPE_ROTATE)}`);

    const app = block(lines, 'app.js:1');
    expect(app).toContain('  │ Fix: Move to env var OPENAI_API_KEY. Rotate at platform.openai.com > API Keys.');
  });

  it('applies to every real env file name, and the --json fix carries the same text', () => {
    write('services/api/.env.production', `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`);

    const findings = scan(project, { scanGlobal: false });
    const f = findings.find(x => x.file === 'services/api/.env.production');
    expect(f?.fix).toBe(envFix(shellQuote(path.join(project, 'services/api/.env.production')), STRIPE_ROTATE));
  });

  it('names the file itself when the scan target is the .env file', () => {
    const file = write('.env', `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`);

    const findings = scan(file, { scanGlobal: false });
    expect(findings).toHaveLength(1);
    expect(findings[0].fix).toBe(envFix(shellQuote(file), STRIPE_ROTATE));
  });

  it('quotes a directory name the shell would split or end a quote on', () => {
    write("svc it's/.env", `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`);

    const f = scan(project, { scanGlobal: false }).find(x => x.file === "svc it's/.env");
    const full = path.join(project, "svc it's/.env");
    expect(f?.fix).toContain(`import '${full.split("'").join("'\\''")}', delete the line`);
  });

  it('does not put a terminal control character from a directory name into the fix', () => {
    write('svc\x1b[31m/.env', `STRIPE_SECRET_KEY=${STRIPE_KEY}\n`);

    const f = scan(project, { scanGlobal: false }).find(x => x.file.endsWith('/.env'));
    expect(f?.fix).toBe(envFix('<file>', STRIPE_ROTATE));
  });

  it('keeps a fix that does not say "Move to env var" as written', () => {
    for (const id of ['aws-sts', 'pem-private-key']) {
      const p = CREDENTIAL_PATTERNS.find(x => x.id === id) ?? { id, name: id, envPrefix: 'X' };
      expect(fixFor(p, { envFile: '.env' }), id).toBe(fixFor(p));
    }
  });

  it('keeps the derived revoke-and-reissue text for a pattern with no verified entry', () => {
    const p = { id: 'no-verified-entry', name: 'Example Token', envPrefix: 'EXAMPLE_TOKEN' };
    expect(fixFor(p)).toBe("Move to env var EXAMPLE_TOKEN. Revoke and reissue this Example Token in the provider's dashboard.");
    expect(fixFor(p, { envFile: '.env' })).toBe(
      envFix('.env', "Revoke and reissue this Example Token in the provider's dashboard."),
    );
  });
});

describe('Next Steps names init only where it is a next step', () => {
  it('names init in a project with no protection', async () => {
    write('app.js', `const k = "${OPENAI_KEY}";\n`);
    expect((await status(project)).isProtected).toBe(false);

    const lines = capture();
    await runScan(project);
    expect(lines).toContain(`  ${INIT_LINE}`);
    expect(lines).toContain('  Full security scan: npx hackmyagent secure');
  });

  it('does not name init in a project status reports protected', async () => {
    write('app.js', `const k = "${OPENAI_KEY}";\n`);
    fs.mkdirSync(path.join(project, '.claude'));
    init(project);
    const s = await status(project);
    expect(s.isProtected).toBe(true);
    expect(s.enforcement).toBe('hook');

    const lines = capture();
    await runScan(project);
    expect(lines.filter(l => l.includes('Protect now:'))).toEqual([]);
    expect(lines).toContain('  Full security scan: npx hackmyagent secure');
  });

  it('reads a file target as the project holding it', async () => {
    const file = write('app.js', `const k = "${OPENAI_KEY}";\n`);
    fs.mkdirSync(path.join(project, '.claude'));
    init(project);

    const lines = capture();
    await runScan(file);
    expect(lines.filter(l => l.includes('Protect now:'))).toEqual([]);
  });

  it('does not name init where init has set up a tool it configures only through instruction files', async () => {
    write('app.js', `const k = "${OPENAI_KEY}";\n`);
    fs.mkdirSync(path.join(project, '.cursor'));
    init(project);
    const s = await status(project);
    expect(s.enforcement).toBe('advisory');
    expect(s.detectedTools).toEqual(['cursor']);

    const lines = capture();
    await runScan(project);
    expect(lines.filter(l => l.includes('Protect now:'))).toEqual([]);
  });

  it('still names init where CLAUDE.md carries the instruction block and no hook is installed', async () => {
    write('app.js', `const k = "${OPENAI_KEY}";\n`);
    write('CLAUDE.md', '<!-- secretless:managed -->\n## Secretless AI\n');
    const s = await status(project);
    expect(s.enforcement).toBe('advisory');
    expect(s.detectedTools).toContain('claude-code');

    const lines = capture();
    await runScan(project);
    expect(lines).toContain(`  ${INIT_LINE}`);
  });

  it('still names init where the guard script is on disk and nothing runs it', async () => {
    write('app.js', `const k = "${OPENAI_KEY}";\n`);
    write('.claude/hooks/secretless-guard.sh', '#!/bin/sh\nexit 0\n');
    const s = await status(project);
    expect(s.isProtected).toBe(true);
    expect(s.enforcement).toBe('none');

    const lines = capture();
    await runScan(project);
    expect(lines).toContain(`  ${INIT_LINE}`);
  });
});
