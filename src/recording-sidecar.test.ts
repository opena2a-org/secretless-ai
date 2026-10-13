import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT, typedCommands } from './tape.test-support';

/**
 * A recording is a rendered file: nobody reads a diff of a GIF, and nothing in
 * the picture says which build drew it. The render script writes a sidecar
 * beside the recording that names the build, the fixture, the commands and the
 * files, and these tests hold that sidecar to the repository. An edit to the
 * tape, the fixture or the package version that is not followed by a render
 * fails here, which is what keeps the recording from showing a build that is
 * no longer the one a reader installs.
 *
 *   docs/vhs/record-init.sh     renders the tape and writes the sidecar
 */

const SIDECAR = 'docs/vhs/init.json';
const TAPE = 'docs/vhs/init.tape';
const CAPTURE = 'docs/vhs/init-capture.txt';
const RECORDING = 'docs/vhs/init.gif';
const FIXTURE_SCRIPT = 'docs/vhs/setup-fixture.sh';
const VHS_PATCH = 'docs/vhs/docker/vhs-0.12.0-render-context.patch';
const README = 'README.md';

const read = (file: string) => fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
const bytes = (file: string) => fs.statSync(path.join(REPO_ROOT, file)).size;
const sha256 = (file: string) => createHash('sha256').update(fs.readFileSync(path.join(REPO_ROOT, file))).digest('hex');
const sidecar = () => JSON.parse(read(SIDECAR));

/** The one README line that links the recording. */
function readmeLine(): string {
  const lines = read(README).split('\n').filter(line => line.includes(`(${RECORDING})`));
  expect(lines, `${README} links ${RECORDING} on one line`).toHaveLength(1);
  return lines[0];
}

/**
 * What a recording never shows: a path under a home directory, which names the
 * machine and often the person it was rendered on, or a numbered phase. Each
 * path pattern is put together from parts so this file does not hold the text
 * it looks for.
 */
const under = (directory: string) => `${directory}/`;
const MACHINE_WORDS = new RegExp([under('/Users'), under('/home'), under('~'), 'phase [0-9]'].join('|'));
const VERSION_OR_DATE = /[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}/;

/**
 * The one line of the tool's own output that writes the home directory in its
 * shell shorthand: `verify` states its scope above every result, on every
 * machine, in the same words. It is read from the source that prints it, so
 * the capture may carry that line as printed and no other, and the allowance
 * ends when the line does.
 */
function verifyScopeLine(): string {
  const printed = read('src/commands/core.ts').match(/c\.dim\('(Scope: [^']+)'\)/);
  expect(printed, 'runVerify prints its scope').not.toBeNull();
  return printed![1];
}

describe('the recorded walkthrough and its sidecar', () => {
  it('names the version in package.json', () => {
    // The sidecar's version is what the installed build reported inside the
    // render container. A release that bumps package.json and does not render
    // again would leave the README linking a recording of the previous build.
    expect(sidecar().version, `${SIDECAR} was rendered from another version: run docs/vhs/record-init.sh`)
      .toBe(JSON.parse(read('package.json')).version);
  });

  it('lists the commands the tape types on screen, in order', () => {
    const typed = typedCommands(read(TAPE));
    expect(typed.length).toBeGreaterThan(0);
    expect(sidecar().commands).toEqual(typed);
  });

  it('pairs each typed command with its output in the text capture', () => {
    const capture = read(CAPTURE).split('\n');
    expect(capture.filter(line => line.startsWith('$ ')).map(line => line.slice(2))).toEqual(sidecar().commands);
    expect(capture.filter(line => /^\[exit \d+\]$/.test(line)).map(line => Number(line.slice(6, -1)))).toEqual(sidecar().exitCodes);
  });

  it('can tell a home-directory path and a numbered phase from ordinary output', () => {
    // Pinned in both directions before the real files are read.
    for (const line of [`cd ${under('/Users')}name/project`, `${under('/home')}name`, `ls ${under('~')}project`, 'phase 2']) {
      expect(MACHINE_WORDS.test(line), line).toBe(true);
    }
    for (const line of ['    + .claude/settings.json (99 deny patterns)', 'export HOME=/work/new-home', '$ npx secretless-ai init']) {
      expect(MACHINE_WORDS.test(line), line).toBe(false);
    }
    expect(MACHINE_WORDS.test(verifyScopeLine())).toBe(true);
  });

  it('shows no home-directory path and no numbered phase in the tape, the text capture or the README line', () => {
    const offenders: string[] = [];
    const check = (file: string, lines: string[], printedByTheTool: string[] = []): void => {
      lines.forEach((line, i) => {
        if (MACHINE_WORDS.test(line) && !printedByTheTool.includes(line.trim())) offenders.push(`${file}:${i + 1}: ${line.trim()}`);
      });
    };
    check(TAPE, read(TAPE).split('\n'));
    check(CAPTURE, read(CAPTURE).split('\n'), [verifyScopeLine()]);
    check(README, [readmeLine()]);
    expect(offenders).toEqual([]);
  });

  it('is linked from the README by what it shows, with no version or date, and not embedded', () => {
    // The recording shows the version banner the tool prints, so the README
    // links it and does not embed it: an embedded picture would put a release
    // number on the page that the text of the page leaves out.
    const line = readmeLine();
    expect(line).toContain(`[secretless-ai init: sets up a project, then verifies the setup](${RECORDING})`);
    expect(line).not.toMatch(VERSION_OR_DATE);
    expect(line).not.toMatch(/!\[[^\]]*\]\(docs\/vhs\/init\.gif\)/);
  });

  it('was rendered from the tape, the fixture and the patch the repository carries', () => {
    const s = sidecar();
    expect(s.tape).toBe(TAPE);
    expect(s.tapeSha256, `${TAPE} changed after the render: run docs/vhs/record-init.sh`).toBe(sha256(TAPE));
    expect(s.scriptSha256).toBe(s.tapeSha256);
    expect(s.fixtureScript).toBe(FIXTURE_SCRIPT);
    expect(s.fixtureSha, `${FIXTURE_SCRIPT} changed after the render: run docs/vhs/record-init.sh`).toBe(sha256(FIXTURE_SCRIPT));
    expect(s.fixtureUncommittedChanges).toBe(0);
    expect(s.vhsPatchSha256).toBe(sha256(VHS_PATCH));
    expect(s.environment.vhs.patchSha256).toBe(s.vhsPatchSha256);
    expect(s.outputs.gif).toEqual({ path: RECORDING, bytes: bytes(RECORDING) });
    expect(s.outputs.capture).toBe(CAPTURE);
  });

  it('names one build: the published package by its integrity, or the commit it was packed from', () => {
    const s = sidecar();
    expect(s.tool).toBe('secretless-ai');
    expect([s.npmIntegrity, s.packedFromCommit].filter(Boolean)).toHaveLength(1);
    if (s.npmIntegrity) expect(s.npmIntegrity).toMatch(/^sha512-/);
    else expect(s.packedFromCommit).toMatch(/^[0-9a-f]{40}$/);
  });

  it('records the terminal the tape sets, on a host named laptop with no keychain', () => {
    const s = sidecar();
    const set = (name: string) => Number(read(TAPE).match(new RegExp(`^Set ${name} (\\d+)$`, 'm'))![1]);
    expect([s.columns, s.rows, s.framerate]).toEqual([set('Columns'), set('Rows'), set('Framerate')]);
    expect([s.columns, s.rows, s.framerate]).toEqual([120, 40, 10]);
    expect(s.hostname).toBe('laptop');
    expect(s.keychain).toBe('none');
    expect(s.fixturePath).not.toMatch(MACHINE_WORDS);
    expect(s.fixtureHome).not.toMatch(MACHINE_WORDS);
  });

  it('stays inside the budgets: a minute of wall clock, 3.0 MB of GIF, 1.5 MB of MP4, no metered spend', () => {
    const s = sidecar();
    expect(s.wallClockSeconds).toBeGreaterThan(0);
    expect(s.wallClockSeconds).toBeLessThanOrEqual(60);
    expect(s.durationSeconds).toBeGreaterThan(0);
    expect(s.durationSeconds).toBeLessThanOrEqual(s.wallClockSeconds);
    expect(s.outputs.gif.bytes).toBeLessThanOrEqual(3_000_000);
    expect(s.outputs.mp4.bytes).toBeGreaterThan(0);
    expect(s.outputs.mp4.bytes).toBeLessThanOrEqual(1_500_000);
    expect(s.meteredCostUsd).toBe(0);
    expect(s.gifsicle).toContain('-O3 --lossy=40');
  });

  it('keeps the MP4 out of the repository and says which file it was', () => {
    const s = sidecar();
    expect(s.outputs.mp4.path.startsWith('docs/vhs/out/')).toBe(true);
    expect(s.outputs.mp4.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(read('.gitignore').split('\n')).toContain('docs/vhs/out/');
  });

  it('says how the recording differs from a plain run, in the words agreed for that and no others', () => {
    const allowed = ['setup not shown', 'waits shortened', 'hard cuts and labelled skips'];
    const s = sidecar();
    expect(Array.isArray(s.edits)).toBe(true);
    expect(s.edits.filter((edit: string) => !allowed.includes(edit))).toEqual([]);
    // The tape hides its setup, so the sidecar has to say so.
    expect(/^Hide\b/m.test(read(TAPE))).toBe(s.edits.includes('setup not shown'));
  });

  it('carries every field a reader of a sidecar looks for', () => {
    const s = sidecar();
    const fields = [
      'tape', 'tapeSha256', 'scriptSha256', 'commands', 'tool', 'version', 'ranAtUtc',
      'fixture', 'fixtureSha', 'fixtureUncommittedChanges', 'fixturePath', 'hostname',
      'columns', 'rows', 'framerate', 'gifsicle', 'gifFrames', 'gifFullScreenFrames',
      'renderedPixelSize', 'outputs', 'durationSeconds', 'wallClockSeconds',
      'meteredCostUsd', 'vhsPatchSha256', 'edits', 'keychain',
    ];
    expect(fields.filter(field => s[field] === undefined)).toEqual([]);
    expect(s.ranAtUtc).toMatch(/^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(Array.isArray(s.outputs.frames)).toBe(true);
    for (const frame of s.outputs.frames) expect(fs.existsSync(path.join(REPO_ROOT, frame)), frame).toBe(true);
  });
});
