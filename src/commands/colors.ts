/**
 * Minimal ANSI color system for secretless-ai CLI output.
 * Aligned with hackmyagent visual design: score meters, section dividers,
 * severity-colored borders. Respects NO_COLOR and non-TTY environments.
 */

const noColor = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;

const raw = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  brightRed: '\x1b[91m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  white: '\x1b[97m',
  reset: '\x1b[0m',
};

function wrap(code: string) {
  return (text: string) => noColor ? text : `${code}${text}${raw.reset}`;
}

export const c = {
  green: wrap(raw.green),
  yellow: wrap(raw.yellow),
  red: wrap(raw.red),
  brightRed: wrap(raw.brightRed),
  cyan: wrap(raw.cyan),
  dim: wrap(raw.dim),
  bold: wrap(raw.bold),
  white: wrap(raw.white),
  boldWhite: wrap(`${raw.bold}${raw.white}`),
  boldGreen: wrap(`${raw.bold}${raw.green}`),
  boldRed: wrap(`${raw.bold}${raw.red}`),
  boldYellow: wrap(`${raw.bold}${raw.yellow}`),
  boldCyan: wrap(`${raw.bold}${raw.cyan}`),
};

/** Section divider matching HMA design */
export function divider(label?: string): string {
  if (label) {
    const pad = Math.max(1, 56 - label.length);
    return `\n  ${c.dim('\u2500\u2500')} ${c.bold(label)} ${c.dim('\u2500'.repeat(pad))}`;
  }
  return `  ${c.dim('\u2500'.repeat(62))}`;
}
