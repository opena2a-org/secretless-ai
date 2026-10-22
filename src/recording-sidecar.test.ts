import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { defaultTranscriptDir } from './transcript';
import {
  REPO_ROOT, typedCommands, tapeSteps, tapeSeconds, typingSpeedMs, DEMO_START, DEMO_END, demoCaption,
} from './tape.test-support';

/**
 * A recording is a rendered file: nobody reads a diff of a GIF, and nothing in
 * the picture says which build drew it. The render script writes a sidecar
 * beside the recording that names the build, the fixture, the commands and the
 * files, and these tests hold that sidecar to the repository. An edit to the
 * tape, the fixture or the package version that is not followed by a render
 * fails here, which is what keeps the recording from showing a build that is
 * no longer the one a reader installs.
 *
 * The recording is also held to a pace a viewer can follow: typing they can
 * read, a pause before each command runs, each screen held for the time its
 * output and its spoken sentence take, and a terminal small enough to stay
 * legible in a README column. The README shows it in its Quick start, with a
 * caption the render script writes from the sidecar.
 *
 *   docs/vhs/record-init.sh     renders the tape and writes the sidecar
 */

const SIDECAR = 'docs/vhs/init.json';
const TAPE = 'docs/vhs/init.tape';
const CAPTURE = 'docs/vhs/init-capture.txt';
const NARRATION = 'docs/vhs/init.narration.json';
const RECORDING = 'docs/vhs/init.gif';
const FIXTURE_SCRIPT = 'docs/vhs/setup-fixture.sh';
const VHS_PATCH = 'docs/vhs/docker/vhs-0.12.0-render-context.patch';
const README = 'README.md';
/** The image line of the README block; docs/vhs/record-init.sh writes the same line. */
const IMAGE_LINE = `![secretless-ai init sets up a project, then verify checks it](${RECORDING})`;

/** The keys every recording's sidecar starts with (schema demo-sidecar/2), in this order; this repository's own keys follow them. */
const SCHEMA_KEYS = [
  'schema', 'surfaceClass', 'tool', 'version', 'prerelease', 'script', 'scriptSha256', 'recorder',
  'commands', 'steps', 'fixture', 'fixtureSha', 'fixtureUncommittedChanges', 'ranAtUtc', 'durationSeconds',
  'outputs', 'capture', 'narration', 'pace', 'exitCodes', 'meteredCostUsd',
];

const read = (file: string) => fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
const bytes = (file: string) => fs.statSync(path.join(REPO_ROOT, file)).size;
const sha256 = (file: string) => createHash('sha256').update(fs.readFileSync(path.join(REPO_ROOT, file))).digest('hex');
const sidecar = () => JSON.parse(read(SIDECAR));
const narration = () => JSON.parse(read(NARRATION)) as { steps: Array<{ id: string; text: string }>; [key: string]: unknown };
const wordCount = (text: string) => text.split(/\s+/).filter(Boolean).length;

/** The README lines from the start marker of the recording's block to its end marker, both included. */
function demoBlock(): string[] {
  const lines = read(README).split('\n');
  expect(lines.filter(line => line === DEMO_START), `${README} holds ${DEMO_START} once`).toHaveLength(1);
  expect(lines.filter(line => line === DEMO_END), `${README} holds ${DEMO_END} once`).toHaveLength(1);
  const start = lines.indexOf(DEMO_START);
  const end = lines.indexOf(DEMO_END);
  expect(end, `${DEMO_END} follows ${DEMO_START}`).toBeGreaterThan(start);
  return lines.slice(start, end + 1);
}

/** What each typed command printed in the text capture, between its `$` line and its `[exit N]` line, in order. */
function captureBlocks(): string[][] {
  const blocks: string[][] = [];
  let block: string[] | null = null;
  for (const line of read(CAPTURE).split('\n')) {
    if (line.startsWith('$ ')) block = [];
    else if (block && /^\[exit \d+\]$/.test(line)) {
      blocks.push(block);
      block = null;
    } else if (block) block.push(line);
  }
  return blocks;
}

/** The `Type@<speed>` overrides a tape shows on screen, in milliseconds; a hidden one is not seen. */
function shownTypingOverridesMs(tape: string): number[] {
  const speeds: number[] = [];
  let hidden = false;
  for (const line of tape.split('\n')) {
    if (/^Hide\b/.test(line)) hidden = true;
    else if (/^Show\b/.test(line)) hidden = false;
    else if (!hidden) {
      const speed = line.match(/^Type@(\S+)\s/);
      if (speed) speeds.push(Math.round(tapeSeconds(speed[1]) * 1000));
    }
  }
  return speeds;
}

/** Whether a tape hides anything after the first command it shows: a cut from one screen to the next. */
function hidesAfterFirstCommand(tape: string): boolean {
  let hidden = false;
  let shown = false;
  for (const line of tape.split('\n')) {
    if (/^Hide\b/.test(line)) {
      if (shown) return true;
      hidden = true;
    } else if (/^Show\b/.test(line)) hidden = false;
    else if (!hidden && /^Type(?:@\S+)?\s/.test(line)) shown = true;
  }
  return false;
}

/**
 * What a recording never shows: a path under a home directory, which names the
 * machine and often the person it was rendered on, or a numbered phase. Each
 * path pattern is put together from parts so this file does not hold the text
 * it looks for.
 */
const under = (directory: string) => `${directory}/`;
const MACHINE_WORDS = new RegExp([under('/Users'), under('/home'), under('~'), 'phase [0-9]'].join('|'));

/**
 * The lines of the tool's own output that write a directory under the home
 * directory in its shell shorthand, in the same words on every machine:
 * `verify` states its scope above every result, and `init` names the
 * directory Claude Code keeps its transcripts in when that directory does not
 * exist yet, as in a new home. Each is read from the source that prints it,
 * so the capture may carry those lines as printed and no other, and the
 * allowance ends when a line does.
 */
function homeShorthandLines(): string[] {
  const scope = read('src/commands/core.ts').match(/c\.dim\('(Scope: [^']+)'\)/);
  expect(scope, 'runVerify prints its scope').not.toBeNull();
  const watcher = read('src/commands/transcript.ts').match(
    /console\.log\(`\s*(Transcript watcher not installed: no transcript directory yet\. Claude Code creates )\$\{displayDir\(dirs\[0\]\)\}( at its first session\.)`\)/,
  );
  expect(watcher, 'init names the transcript directory it did not find').not.toBeNull();
  const transcripts = ['~', ...path.relative(os.homedir(), defaultTranscriptDir({})).split(path.sep)].join('/');
  return [scope![1], `${watcher![1]}${transcripts}${watcher![2]}`];
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
    const printed = homeShorthandLines();
    expect(printed).toHaveLength(2);
    for (const line of printed) expect(MACHINE_WORDS.test(line), line).toBe(true);
  });

  it('shows no home-directory path and no numbered phase in the tape, the text capture, the narration or the README block', () => {
    const offenders: string[] = [];
    const check = (file: string, lines: string[], printedByTheTool: string[] = []): void => {
      lines.forEach((line, i) => {
        if (MACHINE_WORDS.test(line) && !printedByTheTool.includes(line.trim())) offenders.push(`${file}:${i + 1}: ${line.trim()}`);
      });
    };
    check(TAPE, read(TAPE).split('\n'));
    check(CAPTURE, read(CAPTURE).split('\n'), homeShorthandLines());
    check(NARRATION, narration().steps.map(step => step.text));
    check(README, demoBlock());
    expect(offenders).toEqual([]);
  });

  it('is shown in the Quick start of the README between the demo:init markers, captioned from its sidecar, with links to the text version and the sidecar', () => {
    // The caption names the build the recording shows and the day it was
    // rendered. The render script writes it from the sidecar, and the sidecar
    // is held to the version in package.json above, so the caption moves with
    // each release and cannot be left behind by one.
    const block = demoBlock();
    expect(block).toHaveLength(5);
    expect(block[1]).toBe(IMAGE_LINE);
    expect(block[2]).toBe(demoCaption(sidecar()));
    expect(block[3]).toContain(`](${CAPTURE})`);
    expect(block[3]).toContain(`](${SIDECAR})`);

    const lines = read(README).split('\n');
    const quickStart = lines.indexOf('## Quick start');
    const nextSection = lines.findIndex((line, i) => i > quickStart && line.startsWith('## '));
    expect(quickStart).toBeGreaterThan(-1);
    expect(lines.indexOf(DEMO_START)).toBeGreaterThan(quickStart);
    expect(lines.indexOf(DEMO_END)).toBeLessThan(nextSection);
    // Shown there, and linked from nowhere else on the page.
    expect(lines.filter(line => line.includes(`(${RECORDING})`))).toEqual([IMAGE_LINE]);
  });

  it('captions a recording with the tool, the version and the date of its render, and a pre-release build as one', () => {
    // Pinned in both directions, so the README test above cannot pass on a
    // caption that drops the pre-release note or keeps it after a release.
    const render = { tool: 'secretless-ai', version: '1.2.3', ranAtUtc: '2026-01-02T03:04:05Z' };
    expect(demoCaption({ ...render, prerelease: false })).toBe('Recorded with secretless-ai 1.2.3 on 2026-01-02');
    expect(demoCaption({ ...render, prerelease: true })).toBe('Recorded with secretless-ai 1.2.3 on 2026-01-02 (pre-release build)');
  });

  it('keeps the recording that the README published with 0.23.0 embeds', () => {
    // The README published with 0.23.0 embeds this file by a path relative to
    // the repository:
    //   npm view secretless-ai@0.23.0 readme | grep -n secretless-ai-demo.gif
    // It can go once a version whose README does not embed it is published,
    // which is when this prints 0:
    //   npm view secretless-ai readme | grep -c secretless-ai-demo.gif
    expect(fs.existsSync(path.join(REPO_ROOT, 'docs/secretless-ai-demo.gif'))).toBe(true);
  });

  it('was rendered from the tape, the fixture and the patch the repository carries', () => {
    const s = sidecar();
    expect(s.tape).toBe(TAPE);
    expect(s.tapeSha256, `${TAPE} changed after the render: run docs/vhs/record-init.sh`).toBe(sha256(TAPE));
    expect(s.fixtureScript).toBe(FIXTURE_SCRIPT);
    expect(s.fixtureSha, `${FIXTURE_SCRIPT} changed after the render: run docs/vhs/record-init.sh`).toBe(sha256(FIXTURE_SCRIPT));
    expect(s.fixtureUncommittedChanges).toBe(0);
    expect(s.vhsPatchSha256).toBe(sha256(VHS_PATCH));
    expect(s.environment.vhs.patchSha256).toBe(s.vhsPatchSha256);
    // The GIF the README shows, by its digest, at the size the render measured.
    expect(s.outputs.gif).toEqual({
      path: RECORDING,
      bytes: bytes(RECORDING),
      sha256: sha256(RECORDING),
      width: s.renderedPixelSize.width,
      height: s.renderedPixelSize.height,
      frames: s.gifFrames,
    });
    // At most 1200 px wide, so a README column scales it down and never crops it.
    expect(s.outputs.gif.width).toBeLessThanOrEqual(1200);
    expect(s.outputs.capture).toBe(CAPTURE);
  });

  it('starts with the keys of the demo-sidecar/2 schema, in its order', () => {
    const s = sidecar();
    expect(Object.keys(s).slice(0, SCHEMA_KEYS.length)).toEqual(SCHEMA_KEYS);
    expect(s.schema).toBe('demo-sidecar/2');
    expect(s.surfaceClass).toBe('terminal');
    expect(s.script).toBe(TAPE);
    expect(s.scriptSha256, `${TAPE} changed after the render: run docs/vhs/record-init.sh`).toBe(sha256(TAPE));
    expect(s.recorder).toEqual({ name: 'vhs', version: s.environment.vhs.version, container: 'docs/vhs/docker/Dockerfile' });
    expect(s.capture).toBe(CAPTURE);
    expect(s.narration).toBe(NARRATION);
    expect(Object.keys(s.outputs)).toEqual(['gif', 'mp4', 'webm', 'frames', 'capture']);
  });

  it('says whether the build it shows is a release, and never calls the published package a pre-release', () => {
    // The README caption says "pre-release build" from this field.
    const s = sidecar();
    expect(typeof s.prerelease).toBe('boolean');
    if (s.npmIntegrity) expect(s.prerelease).toBe(false);
  });

  it('holds the digest of the tape under scriptSha256 and tapeSha256, the two fields that name the tape, and under no other field', () => {
    // A digest is read as the digest of the file its field names, so the
    // tape's digest under another name says that file is the tape.
    const tapeDigest = sha256(TAPE);
    const holders: string[] = [];
    const walk = (value: unknown, at: string): void => {
      if (value === tapeDigest) holders.push(at);
      else if (value && typeof value === 'object') {
        for (const [key, inner] of Object.entries(value)) walk(inner, at ? `${at}.${key}` : key);
      }
    };
    walk(sidecar(), '');
    expect(holders).toEqual(['scriptSha256', 'tapeSha256']);
    expect([sidecar().script, sidecar().tape]).toEqual([TAPE, TAPE]);
  });

  it('names one build: the published package by its integrity, or the commit it was packed from', () => {
    const s = sidecar();
    expect(s.tool).toBe('secretless-ai');
    expect([s.npmIntegrity, s.packedFromCommit].filter(Boolean)).toHaveLength(1);
    if (s.npmIntegrity) expect(s.npmIntegrity).toMatch(/^sha512-/);
    else expect(s.packedFromCommit).toMatch(/^[0-9a-f]{40}$/);
  });

  it('names the commit the render started from, whichever build it shows, and a packed build was packed from it', () => {
    // A render of the published package names no packed commit, so without
    // this field nothing in the sidecar says which checkout ran the tape.
    const s = sidecar();
    expect(s.commit).toMatch(/^[0-9a-f]{40}$/);
    if (s.packedFromCommit) expect(s.packedFromCommit).toBe(s.commit);
  });

  it('records the terminal the tape sets, 100 to 120 columns by 24 to 30 rows, on a host named laptop with no keychain', () => {
    const s = sidecar();
    const set = (name: string) => Number(read(TAPE).match(new RegExp(`^Set ${name} (\\d+)$`, 'm'))![1]);
    expect([s.columns, s.rows, s.framerate]).toEqual([set('Columns'), set('Rows'), set('Framerate')]);
    // 40 rows at font 14 render 774 px tall, and a README column scales that
    // down until the type is under 10 px; 28 rows keep it legible.
    expect([s.columns, s.rows, s.framerate]).toEqual([110, 28, 10]);
    expect(s.columns).toBeGreaterThanOrEqual(100);
    expect(s.columns).toBeLessThanOrEqual(120);
    expect(s.rows).toBeGreaterThanOrEqual(24);
    expect(s.rows).toBeLessThanOrEqual(30);
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

  it('gives a web page an MP4 that plays before it has all arrived, and a VP9 WebM, neither of them committed', () => {
    // faststart: the MP4's index (moov) comes before its media (mdat), so a
    // <video> element starts playing while the file downloads. The WebM is
    // the element's second source.
    const s = sidecar();
    expect(s.outputs.mp4.faststart).toBe(true);
    expect(s.outputs.webm).toEqual({
      path: 'docs/vhs/out/init.webm',
      bytes: expect.any(Number),
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      committed: false,
    });
    expect(s.outputs.webm.bytes).toBeGreaterThan(0);
  });

  it('says how the recording differs from a plain run, in the words agreed for that and no others', () => {
    const allowed = ['setup not shown', 'waits shortened', 'hard cuts and labelled skips'];
    const s = sidecar();
    expect(Array.isArray(s.edits)).toBe(true);
    expect(s.edits.filter((edit: string) => !allowed.includes(edit))).toEqual([]);
    // The tape hides its setup, so the sidecar has to say so.
    expect(/^Hide\b/m.test(read(TAPE))).toBe(s.edits.includes('setup not shown'));
    // A Hide after the first command shown cuts from one screen to the next
    // without showing how, so the sidecar has to say that too.
    expect(hidesAfterFirstCommand(read(TAPE))).toBe(s.edits.includes('hard cuts and labelled skips'));
  });

  it('can tell a cut after the first command from a hidden setup, and reads a tape duration in its units', () => {
    // Pinned in both directions before the real tape is read.
    const setupOnly = ['Hide', 'Type "cd /work/project && clear"', 'Enter', 'Show', 'Type "npx secretless-ai init"', 'Enter'];
    expect(hidesAfterFirstCommand(setupOnly.join('\n'))).toBe(false);
    expect(hidesAfterFirstCommand([...setupOnly, 'Hide', 'Type "clear"', 'Enter', 'Show'].join('\n'))).toBe(true);
    expect([tapeSeconds('800ms'), tapeSeconds('9.5s'), tapeSeconds('2'), tapeSeconds('1m')]).toEqual([0.8, 9.5, 2, 60]);
  });

  it('reads the steps of a tape: the command each types, its pause before Enter, its anchor frame and its hold', () => {
    const tape = [
      'Set TypingSpeed 120ms',
      'Hide',
      'Type@10ms "cd /work/project && clear"',
      'Enter',
      'Show',
      'Sleep 1s',
      '# step: s1',
      'Type "npx secretless-ai init"',
      'Sleep 800ms',
      'Enter',
      'Wait',
      'Screenshot docs/vhs/init-s1.png',
      'Sleep 9.5s',
      'Hide',
      'Type@10ms "clear"',
      'Enter',
      'Sleep 300ms',
      'Show',
      '# step: s2',
      'Type "npx secretless-ai verify"',
      'Enter',
      'Sleep 2s',
      'Sleep 500ms',
    ].join('\n');
    expect(tapeSteps(tape)).toEqual([
      { id: 's1', command: 'npx secretless-ai init', preEnterMs: 800, anchorFrame: 'docs/vhs/init-s1.png', holdSeconds: 9.5 },
      { id: 's2', command: 'npx secretless-ai verify', preEnterMs: null, anchorFrame: null, holdSeconds: 2.5 },
    ]);
    expect(typingSpeedMs(tape)).toBe(120);
    expect(shownTypingOverridesMs(tape)).toEqual([]);
    expect(shownTypingOverridesMs('Type@40ms "npx secretless-ai init"')).toEqual([40]);
  });

  it('names its steps alike in the tape, the narration and the sidecar, each typing one command and taking an anchor frame the repository carries', () => {
    const tape = read(TAPE);
    const steps = tapeSteps(tape);
    const s = sidecar();
    const ids = steps.map(step => step.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
    // Every command the tape types on screen is a step of its own.
    expect(steps.map(step => step.command)).toEqual(typedCommands(tape));
    expect(narration().steps.map(step => step.id)).toEqual(ids);
    expect(s.steps).toEqual(steps.map(step => ({ id: step.id, title: step.command, anchorFrame: step.anchorFrame })));
    for (const step of s.steps) {
      expect(step.anchorFrame, step.id).toMatch(/^docs\/vhs\/[a-z0-9-]+\.png$/);
      expect(fs.existsSync(path.join(REPO_ROOT, step.anchorFrame)), step.anchorFrame).toBe(true);
    }
    expect(s.outputs.frames).toEqual(s.steps.map((step: { anchorFrame: string }) => step.anchorFrame));
  });

  it('carries a narration for each step, written for the version the recording shows', () => {
    // The narration sizes each hold now, and is the text of the audio later.
    const n = narration();
    expect(n.schema).toBe('demo-narration/1');
    expect(n.tool).toBe('secretless-ai');
    expect(n.version).toBe(sidecar().version);
    expect(n.wordsPerMinute).toBe(150);
    for (const step of n.steps) expect(wordCount(step.text), step.id).toBeGreaterThan(0);
  });

  it('records the pace the tape sets, at a speed a viewer can read and with a pause before each command runs', () => {
    const tape = read(TAPE);
    const steps = tapeSteps(tape);
    const typed = typedCommands(tape);
    const pace = sidecar().pace;
    expect(pace).toEqual({
      typingSpeedMs: typingSpeedMs(tape),
      preEnterHoldMs: Math.min(...steps.map(step => step.preEnterMs ?? 0)),
      minHoldSeconds: Math.min(...steps.map(step => step.holdSeconds)),
      maxLineChars: Math.max(...typed.map(line => line.length)),
    });
    // 100 to 140 ms a character: the viewer reads a command as it appears.
    // A speed set on one typed line is held to the same range; hidden typing
    // is not seen.
    for (const speed of [pace.typingSpeedMs, ...shownTypingOverridesMs(tape)]) {
      expect(speed).toBeGreaterThanOrEqual(100);
      expect(speed).toBeLessThanOrEqual(140);
    }
    // 600 to 1000 ms after the last character, so the whole command is seen
    // before it runs.
    for (const step of steps) {
      expect(step.preEnterMs, `${step.id}: the Sleep before Enter`).not.toBeNull();
      expect(step.preEnterMs!, step.id).toBeGreaterThanOrEqual(600);
      expect(step.preEnterMs!, step.id).toBeLessThanOrEqual(1000);
    }
    // A typed line a viewer can take in at once.
    expect(pace.maxLineChars).toBeLessThanOrEqual(72);
  });

  it('holds each step on screen for the time its output and its spoken sentence take, and for at most 12 s', () => {
    // At least 3 s, 1 s for every 4 lines the step prints, and the step's
    // sentence at the narration's words a minute plus 0.5 s, so the audio can
    // be added later without a new render. Past 12 s a screen is too much to
    // take in, and the step shows less instead.
    const steps = tapeSteps(read(TAPE));
    const blocks = captureBlocks();
    const n = narration();
    expect(blocks).toHaveLength(steps.length);
    const wordsPerSecond = (n.wordsPerMinute as number) / 60;
    const outOfRange = steps.flatMap((step, i) => {
      const needed = Math.max(3, blocks[i].length / 4, wordCount(n.steps[i].text) / wordsPerSecond + 0.5);
      return step.holdSeconds >= needed && step.holdSeconds <= 12
        ? []
        : [`${step.id}: holds ${step.holdSeconds} s; needs ${needed.toFixed(2)} s to 12 s`];
    });
    expect(outOfRange).toEqual([]);
  });

  it('is at most 45 s long, as the first recording a reader meets', () => {
    expect(sidecar().durationSeconds).toBeLessThanOrEqual(45);
  });

  it('carries every field a reader of a sidecar looks for', () => {
    const s = sidecar();
    const fields = [
      'tape', 'tapeSha256', 'commands', 'tool', 'version', 'commit', 'ranAtUtc',
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
