import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * `status` reads only the most recent few transcripts so it can answer
 * immediately, but it was reporting the DISCOVERY count as the scanned count:
 *
 *     ✓ Transcripts clean (8850 files scanned)
 *
 * while having read three of them. Measured on a real machine during the 0.21.3
 * release test: that line printed alongside `clean --dry-run` finding 882
 * credentials in 168 of those same 8850 files. Same defect class as the rest of
 * this release — a confident zero over content that was never read — and it was
 * sitting on the headline verdict surface.
 *
 * The transcript module is mocked so the assertion is about the sampling
 * contract rather than about whatever happens to be in the operator's
 * ~/.claude directory.
 */

const DISCOVERED = 8850;
const FAKE_TRANSCRIPTS = Array.from({ length: DISCOVERED }, (_, i) => `/fake/transcript-${i}.jsonl`);
const filesActuallyRead: string[] = [];

vi.mock('./transcript', () => ({
  discoverTranscripts: () => FAKE_TRANSCRIPTS,
  scanTranscriptFile: (file: string) => {
    filesActuallyRead.push(file);
    return { findings: [], redacted: '' };
  },
}));

vi.mock('./watch', () => ({ isWatchRunning: () => false }));

import { status, TRANSCRIPT_SAMPLE_SIZE } from './status';
import { runStatus } from './commands/core';

describe('status transcript scope', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-tscope-'));
    filesActuallyRead.length = 0;
  });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('separates how many transcripts exist from how many were read', () => {
    const result = status(dir);
    const tp = result.transcriptProtection;

    expect(tp.transcriptFiles).toBe(DISCOVERED);
    expect(tp.transcriptFilesScanned).toBe(TRANSCRIPT_SAMPLE_SIZE);
    // The count must describe real work, not the constant: prove only that many
    // files were opened.
    expect(filesActuallyRead.length).toBe(TRANSCRIPT_SAMPLE_SIZE);
    expect(tp.transcriptFilesScanned).toBeLessThan(tp.transcriptFiles);
  });

  it('reads the most recent transcripts, which is what the output claims', () => {
    status(dir);
    // discoverTranscripts sorts by mtime descending, so "most recent" is the
    // head of the list. If that ever changes, the wording in the status row
    // becomes false and this fails.
    expect(filesActuallyRead).toEqual(FAKE_TRANSCRIPTS.slice(0, TRANSCRIPT_SAMPLE_SIZE));
  });

  it('never reports the discovery count as the number of files scanned', () => {
    const logs: string[] = [];
    const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '));
    });
    try {
      runStatus(dir);
    } finally {
      spy.mockRestore();
    }
    const out = logs.join('\n');

    // Guard against a green run over output that never contained the row at all.
    expect(out).toMatch(/transcript/i);
    // The exact false claim that shipped.
    expect(out).not.toMatch(new RegExp(`${DISCOVERED} files? scanned`));
    // What it must say instead: the scope it actually covered, and the fact that
    // the remainder was not read.
    expect(out).toContain(`${TRANSCRIPT_SAMPLE_SIZE} most recent transcripts`);
    expect(out).toContain('the rest were not read');
  });
});
