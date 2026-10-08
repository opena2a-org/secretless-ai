/**
 * Read one line from a terminal without echoing it (#234).
 *
 * `secret set NAME` on a terminal used to read a cooked line with echo on, so
 * a pasted key was printed to the screen and stayed in scrollback. Raw mode
 * turns echo off and hands every keystroke to this reader, which also drops
 * the bracketed-paste markers a terminal wraps around a paste: captured with
 * the value they turned a 40-character token into 19 bytes of control
 * characters (#104).
 */

export const PASTE_START = '\u001b[200~';
export const PASTE_END = '\u001b[201~';

/** A terminal input stream. `setRawMode` is what turns echo off. */
export interface TtyInput extends NodeJS.ReadableStream {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
}

export interface PromptOutput {
  write(text: string): unknown;
}

export type HiddenLineResult =
  | { kind: 'line'; value: string }
  | { kind: 'cancelled' };

/** True when this stream can read with echo off. */
export function canReadHidden(input: TtyInput): boolean {
  return input.isTTY === true && typeof input.setRawMode === 'function';
}

/**
 * Print `prompt`, then read keystrokes with echo off until Enter.
 *
 * Enter or Ctrl-D ends the line, Ctrl-C cancels it, Backspace removes the
 * last character and Ctrl-U clears the line. Nothing typed or pasted is
 * written to `output`; only the prompt and the closing newline are.
 */
export function readHiddenLine(input: TtyInput, output: PromptOutput, prompt: string): Promise<HiddenLineResult> {
  return new Promise((resolve) => {
    const wasRaw = input.isRaw === true;
    let pending = '';
    let value = '';
    let settled = false;

    const finish = (result: HiddenLineResult): void => {
      if (settled) return;
      settled = true;
      input.removeListener('data', onData);
      input.removeListener('end', onEnd);
      input.setRawMode!(wasRaw);
      input.pause();
      // Echo is off, so the Enter the user pressed did not move the cursor.
      output.write('\n');
      resolve(result);
    };

    const onData = (chunk: string | Buffer): void => {
      pending += String(chunk);
      while (pending.length > 0 && !settled) {
        if (pending.startsWith(PASTE_START) || pending.startsWith(PASTE_END)) {
          pending = pending.slice(PASTE_START.length);
          continue;
        }
        // A marker split across two reads: wait for the rest of it.
        if (PASTE_START.startsWith(pending) || PASTE_END.startsWith(pending)) return;
        const ch = pending[0];
        pending = pending.slice(1);
        if (ch === '\r' || ch === '\n' || ch === '\u0004') {
          finish({ kind: 'line', value });
        } else if (ch === '\u0003') {
          finish({ kind: 'cancelled' });
        } else if (ch === '\u007f' || ch === '\b') {
          value = Array.from(value).slice(0, -1).join('');
        } else if (ch === '\u0015') {
          value = '';
        } else {
          value += ch;
        }
      }
    };

    const onEnd = (): void => finish({ kind: 'line', value });

    input.setRawMode!(true);
    input.setEncoding('utf-8');
    output.write(prompt);
    input.on('data', onData);
    input.on('end', onEnd);
    input.resume();
  });
}
