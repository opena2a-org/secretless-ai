import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The team guide opens with "Secretless connects to a shared backend so every
 * team member resolves secrets from the same source", and the table in its
 * Step 1 is the list a team picks that backend from. A backend that keeps its
 * store on one machine does not belong in it: each developer who picked it
 * would hold a separate store nobody else resolves from.
 *
 * The table listed `keychain` as "Small teams, macOS-only" (#344). The OS
 * keychain is per machine, on macOS and on Linux Secret Service alike, and
 * docs/use-cases/bring-your-own-vault.md already said so in its own table
 * ("Shared across machines? No"). These tests hold the two tables together,
 * so a backend the one calls per machine cannot be offered as shared by the
 * other.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const TEAM_DOC = 'docs/use-cases/team-setup.md';
const VAULT_DOC = 'docs/use-cases/bring-your-own-vault.md';

/** The cells of a markdown table row, or null for a line that is not one. */
function tableCells(line: string): string[] | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith('|') || !trimmed.endsWith('|') || trimmed.length < 2) return null;
  return trimmed.slice(1, -1).split('|').map(cell => cell.trim());
}

interface BackendRow {
  backend: string;
  /** The row's cell under the requested column. */
  cell: string;
  /** 1-based line of the row in its file. */
  line: number;
}

/**
 * The rows of the first table in `text` whose header starts with `Backend` and
 * has a `column` column. A row counts when its first cell is a backend name in
 * backticks, which is how both guides write one.
 */
function backendTable(text: string, column: string): BackendRow[] {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const header = tableCells(lines[i]);
    if (!header || header[0] !== 'Backend' || !header.includes(column)) continue;
    const at = header.indexOf(column);
    const rows: BackendRow[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      const cells = tableCells(lines[j]);
      if (!cells) break;
      const name = cells[0].match(/^`([a-z0-9-]+)`$/);
      if (name) rows.push({ backend: name[1], cell: cells[at] ?? '', line: j + 1 });
    }
    return rows;
  }
  return [];
}

function read(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');
}

describe('the team guide offers shared backends only', () => {
  it('reads a backend table by its header and its backticked first cell', () => {
    // Pin the extractor in both directions before trusting a green run over
    // the real guides.
    const table = [
      'Intro line.',
      '',
      '| Situation | Exit |',
      '|---|---|',
      '| `init` re-run | 0 |',
      '',
      '| Backend | Shared across machines? | Requires |',
      '|---------|-------------------------|----------|',
      '| `local` | No (single machine) | Nothing |',
      '| `gcp-sm` | Yes | Credentials |',
      '',
      '| `vault` | Yes | A second table is not read |',
    ].join('\n');
    expect(backendTable(table, 'Shared across machines?')).toEqual([
      { backend: 'local', cell: 'No (single machine)', line: 9 },
      { backend: 'gcp-sm', cell: 'Yes', line: 10 },
    ]);
    expect(backendTable(table, 'Best For')).toEqual([]);
    expect(tableCells('Not a | table row')).toBeNull();
  });

  it('finds the vault guide\'s answer for every backend, with both answers present', () => {
    // Guard against the extraction matching nothing, or the column being
    // reworded into something this test no longer reads as yes or no; either
    // would leave the check below with nothing to compare against.
    const rows = backendTable(read(VAULT_DOC), 'Shared across machines?');
    expect(rows.length).toBeGreaterThan(0);
    const unread = rows.filter(r => !/^(Yes|No)\b/.test(r.cell));
    expect(unread.map(r => `${VAULT_DOC}:${r.line}: \`${r.backend}\` — ${r.cell}`)).toEqual([]);
    expect(rows.some(r => r.cell.startsWith('Yes'))).toBe(true);
    expect(rows.some(r => r.cell.startsWith('No'))).toBe(true);
  });

  it('lists no backend the vault guide says is not shared across machines', () => {
    const shared = new Map(
      backendTable(read(VAULT_DOC), 'Shared across machines?').map(r => [r.backend, r.cell]),
    );
    const offered = backendTable(read(TEAM_DOC), 'Best For');
    // The table a team chooses from has to be there to be checked.
    expect(offered.length).toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const row of offered) {
      const answer = shared.get(row.backend);
      if (answer === undefined) {
        offenders.push(`${TEAM_DOC}:${row.line}: \`${row.backend}\` has no row in the ${VAULT_DOC} table`);
      } else if (!answer.startsWith('Yes')) {
        offenders.push(`${TEAM_DOC}:${row.line}: \`${row.backend}\` — ${VAULT_DOC} says "Shared across machines? ${answer}"`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
