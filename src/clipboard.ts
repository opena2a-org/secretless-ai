/**
 * Read and clear the system clipboard through the platform's own tool, for
 * `secret set NAME --from-clipboard` (#234).
 *
 * A key copied from a web dashboard used to reach the store through one of
 * three leaks: `NAME=VALUE` puts it in argv and shell history, the prompt
 * echoed it into scrollback, and `pbpaste | secret set NAME` left it in the
 * clipboard for the next paste. Here the value only ever travels through a
 * child process's stdout pipe. No command line built in this module carries
 * it, and clearing writes an empty input rather than the value.
 */
import { spawnSync } from 'child_process';

/** Largest clipboard read accepted. A credential is far smaller. */
const MAX_CLIPBOARD_BYTES = 1024 * 1024;

export interface ClipboardTool {
  /** Name of the executable, as printed in messages. */
  name: string;
  readArgs: string[];
  clearArgs: string[];
  /** Feed an empty stdin to the clear command (pbcopy, xclip). */
  clearWithEmptyInput?: boolean;
}

export interface ClipboardRunResult {
  /** Exit status, or null when the process did not run or was killed. */
  status: number | null;
  stdout: string;
  /** Set when the process could not be started (ENOENT) or overflowed. */
  errorCode?: string;
}

/** Runs one tool. `capture` is false for clear commands, whose output is not read. */
export type ClipboardRunner = (command: string, args: string[], capture: boolean) => ClipboardRunResult;

export type ClipboardReadResult =
  | { ok: true; text: string; tool: ClipboardTool }
  | { ok: false; reason: 'no-tool'; tried: string[] }
  | { ok: false; reason: 'failed'; tool: ClipboardTool; detail: string };

export interface ClipboardOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  run?: ClipboardRunner;
}

const POWERSHELL = ['-NoProfile', '-NonInteractive', '-Command'];

/** The tools to try on this platform, in order. */
export function clipboardTools(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): ClipboardTool[] {
  if (platform === 'darwin') {
    return [{ name: 'pbpaste', readArgs: [], clearArgs: [], clearWithEmptyInput: true }];
  }
  if (platform === 'win32') {
    return [{
      name: 'powershell.exe',
      readArgs: [...POWERSHELL, 'Get-Clipboard -Raw'],
      clearArgs: [...POWERSHELL, 'Set-Clipboard -Value $null'],
    }];
  }
  const wayland: ClipboardTool = { name: 'wl-paste', readArgs: ['--no-newline'], clearArgs: ['--clear'] };
  const x11: ClipboardTool[] = [
    { name: 'xclip', readArgs: ['-selection', 'clipboard', '-o'], clearArgs: ['-selection', 'clipboard', '-i'], clearWithEmptyInput: true },
    { name: 'xsel', readArgs: ['--clipboard', '--output'], clearArgs: ['--clipboard', '--clear'] },
  ];
  return env.WAYLAND_DISPLAY ? [wayland, ...x11] : [...x11, wayland];
}

/** The command that clears the clipboard for a tool. wl-paste reads; wl-copy writes. */
function clearCommand(tool: ClipboardTool): string {
  if (tool.name === 'pbpaste') return 'pbcopy';
  if (tool.name === 'wl-paste') return 'wl-copy';
  return tool.name;
}

/** What to install when no tool was found, as a `Fix:` line. */
export function clipboardInstallHint(platform: NodeJS.Platform): string {
  if (platform === 'darwin') return 'pbpaste and pbcopy ship with macOS in /usr/bin; check that /usr/bin is on PATH';
  if (platform === 'win32') return 'Get-Clipboard needs Windows PowerShell 5.1 or later (powershell.exe on PATH)';
  return 'install wl-clipboard (Wayland) or xclip (X11), for example: sudo apt install wl-clipboard xclip';
}

const defaultRunner = (env: NodeJS.ProcessEnv): ClipboardRunner => (command, args, capture) => {
  const res = spawnSync(command, args, {
    env,
    encoding: 'utf-8',
    maxBuffer: MAX_CLIPBOARD_BYTES,
    timeout: 10_000,
    windowsHide: true,
    // xclip forks a child that serves the selection and inherits stdout, so a
    // captured stdout on the clear command would never close.
    stdio: capture ? ['ignore', 'pipe', 'ignore'] : ['pipe', 'ignore', 'ignore'],
    input: capture ? undefined : '',
  });
  const errorCode = (res.error as NodeJS.ErrnoException | undefined)?.code;
  return { status: res.status, stdout: typeof res.stdout === 'string' ? res.stdout : '', errorCode };
};

export class Clipboard {
  readonly platform: NodeJS.Platform;
  private readonly env: NodeJS.ProcessEnv;
  private readonly run: ClipboardRunner;

  constructor(options: ClipboardOptions = {}) {
    this.platform = options.platform ?? process.platform;
    this.env = options.env ?? process.env;
    this.run = options.run ?? defaultRunner(this.env);
  }

  /** The clipboard's text through the first tool that exists. */
  read(): ClipboardReadResult {
    const tools = clipboardTools(this.platform, this.env);
    for (const tool of tools) {
      const res = this.run(tool.name, tool.readArgs, true);
      if (res.errorCode === 'ENOENT') continue;
      if (res.errorCode === 'ENOBUFS') {
        return { ok: false, reason: 'failed', tool, detail: `the clipboard holds more than ${MAX_CLIPBOARD_BYTES / 1024} KB` };
      }
      if (res.errorCode) return { ok: false, reason: 'failed', tool, detail: `${tool.name} could not run (${res.errorCode})` };
      // wl-paste and xclip exit non-zero when the clipboard holds no text.
      if (res.status !== 0) {
        return { ok: false, reason: 'failed', tool, detail: `${tool.name} exited with status ${res.status}; the clipboard is empty, holds no text, or could not be reached` };
      }
      return { ok: true, text: res.stdout, tool };
    }
    return { ok: false, reason: 'no-tool', tried: tools.map((t) => t.name) };
  }

  /** Empty the clipboard. Returns the reason on failure. */
  clear(tool: ClipboardTool): string | null {
    const command = clearCommand(tool);
    const res = this.run(command, tool.clearArgs, false);
    if (res.errorCode) return `${command} could not run (${res.errorCode})`;
    if (res.status !== 0) return `${command} exited with status ${res.status}`;
    return null;
  }
}
