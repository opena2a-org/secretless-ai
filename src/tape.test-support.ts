import * as fs from 'fs';
import * as path from 'path';

/**
 * Reading a recording's tape: which tapes the repository carries, what each
 * one types where a viewer can see it, its steps and its pace, and the caption
 * the README shows under the recording. Shared by the test that checks those
 * commands against the CLI, the test that checks them against the sidecar and
 * the README budget, so they cannot come to read a tape differently.
 */

export const REPO_ROOT = path.resolve(__dirname, '..');

/** Every tape under docs/, as paths relative to the repository root. */
export function tapeFiles(): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(path.join(REPO_ROOT, dir), { withFileTypes: true })) {
      const relative = path.posix.join(dir, entry.name);
      if (entry.isDirectory()) walk(relative);
      else if (entry.name.endsWith('.tape')) files.push(relative);
    }
  };
  walk('docs');
  return files.sort();
}

/**
 * The lines a tape types on screen, in order: the text of each `Type` line
 * outside a `Hide`..`Show` block. A hidden block is setup the viewer never
 * sees (entering the fixture, clearing the screen), so it is not a command the
 * recording shows anyone.
 */
export function typedCommands(tape: string): string[] {
  const typed: string[] = [];
  let hidden = false;
  for (const line of tape.split('\n')) {
    if (/^Hide\b/.test(line)) hidden = true;
    else if (/^Show\b/.test(line)) hidden = false;
    else if (!hidden) {
      const m = line.match(/^Type(?:@\S+)?\s+(["'`])(.*)\1\s*$/);
      if (m) typed.push(m[2]);
    }
  }
  return typed;
}

/** The programs a tape declares with `Require`, which VHS checks before it records. */
export function requiredPrograms(tape: string): string[] {
  return [...tape.matchAll(/^Require\s+(\S+)\s*$/gm)].map(m => m[1]);
}

/** A duration as a tape writes it (`800ms`, `9.5s`, `1m`, or a bare number of seconds), in seconds. */
export function tapeSeconds(value: string): number {
  const m = value.trim().match(/^([0-9]*\.?[0-9]+)(ms|s|m)?$/);
  if (!m) throw new Error(`not a tape duration: ${value}`);
  const n = Number(m[1]);
  return m[2] === 'ms' ? n / 1000 : m[2] === 'm' ? n * 60 : n;
}

/** One step of a recording, as its tape writes it. */
export interface TapeStep {
  /** The id after `# step:`, which the narration and the sidecar use for the same step. */
  id: string;
  /** The command the step types on screen. */
  command: string | null;
  /** The `Sleep` directly before the step's `Enter`, in milliseconds; null when there is none. */
  preEnterMs: number | null;
  /** The `Screenshot` the step takes after its `Enter`. */
  anchorFrame: string | null;
  /** The `Sleep`s shown after the step's `Enter`, up to the next `Type`, in seconds. */
  holdSeconds: number;
}

/**
 * The steps of a tape, in order. A step starts at a `# step: <id>` comment
 * outside a `Hide`..`Show` block and types one command on screen. After its
 * `Enter` the tape may `Wait` for the prompt, which takes as long as the
 * command does and is not counted, and takes the step's `Screenshot`; the
 * step's hold is the sum of the `Sleep`s shown from there to the next `Type`,
 * hidden or not, or to the end of the tape.
 */
export function tapeSteps(tape: string): TapeStep[] {
  const steps: TapeStep[] = [];
  let hidden = false;
  let step: TapeStep | null = null;
  let entered = false;
  let sleptMs: number | null = null;
  for (const raw of tape.split('\n')) {
    const line = raw.trim();
    if (line === '') continue;
    const id = line.match(/^#\s*step:\s*(\S+)/);
    if (id && !hidden) {
      step = { id: id[1], command: null, preEnterMs: null, anchorFrame: null, holdSeconds: 0 };
      steps.push(step);
      entered = false;
      sleptMs = null;
      continue;
    }
    if (line.startsWith('#')) continue;
    if (/^Hide\b/.test(line)) hidden = true;
    else if (/^Show\b/.test(line)) hidden = false;
    else if (/^Type(?:@\S+)?\s/.test(line)) {
      const typed = line.match(/^Type(?:@\S+)?\s+(["'`])(.*)\1$/);
      if (step && entered) step = null;
      else if (step && !hidden && step.command === null && typed) step.command = typed[2];
    } else if (/^Sleep\s/.test(line)) {
      // Whole milliseconds, so a sum of Sleeps is exact.
      const ms = Math.round(tapeSeconds(line.slice('Sleep'.length)) * 1000);
      if (step && entered && !hidden) step.holdSeconds = (Math.round(step.holdSeconds * 1000) + ms) / 1000;
      sleptMs = ms;
      continue;
    } else if (/^Enter\b/.test(line)) {
      if (step && !hidden && !entered && step.command !== null) {
        step.preEnterMs = sleptMs;
        entered = true;
      }
    } else {
      const shot = line.match(/^Screenshot\s+(\S+)$/);
      if (shot && step && entered && !hidden) step.anchorFrame = shot[1];
    }
    sleptMs = null;
  }
  return steps;
}

/** The milliseconds a tape types each character in: its `Set TypingSpeed`, or VHS's 50 ms when it sets none. */
export function typingSpeedMs(tape: string): number {
  const m = tape.match(/^Set TypingSpeed\s+(\S+)\s*$/m);
  return m ? Math.round(tapeSeconds(m[1]) * 1000) : 50;
}

/**
 * The README shows the recording between these two lines: the image, the
 * caption written from the sidecar, and a line linking the text version and
 * the sidecar. docs/vhs/record-init.sh writes the block after each render.
 */
export const DEMO_START = '<!-- demo:init:start -->';
export const DEMO_END = '<!-- demo:init:end -->';

/** The caption under the recording: the tool, the version and the date of the render, and whether the build was a release. */
export function demoCaption(sidecar: { tool: string; version: string; ranAtUtc: string; prerelease: boolean }): string {
  return `Recorded with ${sidecar.tool} ${sidecar.version} on ${sidecar.ranAtUtc.slice(0, 10)}${sidecar.prerelease ? ' (pre-release build)' : ''}`;
}
