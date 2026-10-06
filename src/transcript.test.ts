import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { deepScan, scanTranscriptFile, atomicWrite, discoverTranscripts, cleanTranscripts, MAX_LINE_SIZE, type TranscriptFinding } from './transcript';

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-transcript-test-'));
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('deepScan', () => {
  it('redacts Anthropic key in nested message.content[0].text', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      message: {
        content: [{ type: 'text', text: 'Use this key: sk-ant-api03-abc123def456abc123def456abc123' }],
      },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(1);
    expect(findings[0].patternName).toBe('Anthropic API Key');
    expect(findings[0].jsonPath).toBe('.message.content[0].text');
    expect(result.message.content[0].text).toContain('[REDACTED:anthropic]');
    expect(result.message.content[0].text).not.toContain('sk-ant-api03');
  });

  it('redacts GitHub PAT in message.content[0].input.command', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      message: {
        content: [{
          type: 'tool_use',
          input: { command: 'curl -H "Authorization: token ghp_abcdefghijklmnopqrstuvwxyz0123456789"' },
        }],
      },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 5 }) as any;

    expect(findings).toHaveLength(1);
    expect(findings[0].patternId).toBe('github-pat');
    expect(result.message.content[0].input.command).toContain('[REDACTED:github-pat]');
  });

  it('skips metadata fields (uuid, sessionId, timestamp)', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      uuid: 'sk-ant-api03-abc123def456abc123def456abc123',
      sessionId: 'sk-ant-api03-abc123def456abc123def456abc123',
      timestamp: '2026-01-15T10:30:00Z',
      parentUuid: 'sk-ant-api03-abc123def456abc123def456abc123',
      message: { content: 'clean text' },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(0);
    // Metadata fields preserved unchanged
    expect(result.uuid).toBe(input.uuid);
    expect(result.sessionId).toBe(input.sessionId);
    expect(result.parentUuid).toBe(input.parentUuid);
  });

  it('handles mixed content arrays (text + tool_use + thinking)', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      message: {
        content: [
          { type: 'thinking', thinking: 'planning next step' },
          { type: 'text', text: 'Here is the result' },
          { type: 'tool_use', input: { command: 'echo sk-ant-api03-abc123def456abc123def456abc123' } },
          { type: 'text', text: 'Also ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
        ],
      },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(2);
    expect(result.message.content[0].thinking).toBe('planning next step');
    expect(result.message.content[1].text).toBe('Here is the result');
    expect(result.message.content[2].input.command).toContain('[REDACTED:anthropic]');
    expect(result.message.content[3].text).toContain('[REDACTED:github-pat]');
  });

  it('is idempotent — already-redacted values do not re-trigger', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      message: { content: 'Key was [REDACTED:anthropic] and token was [REDACTED:github-pat]' },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(0);
    expect(result.message.content).toBe(input.message.content);
  });

  it('redacts ALL occurrences of the same credential in a single string', () => {
    const findings: TranscriptFinding[] = [];
    const key = 'sk-ant-api03-abc123def456abc123def456abc123';
    const input = {
      toolUseResult: {
        originalFile: `line1\napi_key = "${key}"\nline3\nbackup_key = "${key}"\nline5`,
      },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(1);
    expect(result.toolUseResult.originalFile).not.toContain('sk-ant-api03');
    // Both occurrences should be redacted
    const redactedCount = (result.toolUseResult.originalFile.match(/\[REDACTED:anthropic\]/g) || []).length;
    expect(redactedCount).toBe(2);
  });

  it('catches credential hidden after fake redaction marker', () => {
    const findings: TranscriptFinding[] = [];
    const input = {
      message: { content: '[REDACTED:anthropic]sk-ant-api03-abc123def456abc123def456abc123' },
    };

    const result = deepScan(input, '', findings, { file: 'test.jsonl', line: 1 }) as any;

    expect(findings).toHaveLength(1);
    expect(result.message.content).toContain('[REDACTED:anthropic]');
    expect(result.message.content).not.toContain('sk-ant-api03');
  });
});

describe('scanTranscriptFile', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('dry-run reports findings without modifying file', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const line = JSON.stringify({
      message: { content: 'key: sk-ant-api03-abc123def456abc123def456abc123' },
    });
    fs.writeFileSync(filePath, line + '\n');

    const { findings, redactedLines } = scanTranscriptFile(filePath, true);

    expect(findings).toHaveLength(1);
    expect(redactedLines).toBeNull();
    // File unchanged
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('sk-ant-api03');
  });

  it('redact mode modifies file atomically', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const lines = [
      JSON.stringify({ message: { content: 'key: sk-ant-api03-abc123def456abc123def456abc123' } }),
      JSON.stringify({ message: { content: 'clean line' } }),
    ];
    fs.writeFileSync(filePath, lines.join('\n') + '\n');

    const { findings, redactedLines } = scanTranscriptFile(filePath, false);

    expect(findings).toHaveLength(1);
    expect(redactedLines).not.toBeNull();
    expect(redactedLines!.length).toBe(3); // 2 data lines + 1 trailing empty

    // Verify redacted content is valid JSONL
    const redactedParsed = JSON.parse(redactedLines![0]);
    expect(redactedParsed.message.content).toContain('[REDACTED:anthropic]');
  });

  it('handles malformed JSON lines gracefully', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const lines = [
      'not valid json at all',
      JSON.stringify({ message: { content: 'sk-ant-api03-abc123def456abc123def456abc123' } }),
      '{broken: json',
    ];
    fs.writeFileSync(filePath, lines.join('\n'));

    const { findings, redactedLines } = scanTranscriptFile(filePath, false);

    expect(findings).toHaveLength(1);
    expect(redactedLines).not.toBeNull();
    // Malformed lines preserved as-is
    expect(redactedLines![0]).toBe('not valid json at all');
    expect(redactedLines![2]).toBe('{broken: json');
  });

  it('handles empty files', () => {
    const filePath = path.join(dir, 'empty.jsonl');
    fs.writeFileSync(filePath, '');

    const { findings, redactedLines } = scanTranscriptFile(filePath, false);

    expect(findings).toHaveLength(0);
    expect(redactedLines).toBeNull();
  });

  it('returns the number of a line over the length cap, which it leaves unread', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const pat = ['gh', 'p_', 'FAKER1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6'].join('');
    const long = JSON.stringify({ message: { content: 'x'.repeat(MAX_LINE_SIZE) + ' token ' + pat } });
    fs.writeFileSync(filePath, [JSON.stringify({ message: { content: 'hello' } }), long].join('\n') + '\n');

    const { findings, linesNotRead } = scanTranscriptFile(filePath, true);

    expect(findings).toHaveLength(0);
    expect(linesNotRead).toEqual([2]);
  });

  it('CONTROL: a line at the length cap is read, not reported as unread', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const pat = ['gh', 'p_', 'FAKER1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6'].join('');
    const head = JSON.stringify({ message: { content: ' token ' + pat } });
    const content = 'x'.repeat(MAX_LINE_SIZE - head.length);
    const atCap = JSON.stringify({ message: { content: content + ' token ' + pat } });
    expect(atCap.length).toBe(MAX_LINE_SIZE);
    fs.writeFileSync(filePath, atCap + '\n');

    const { findings, linesNotRead } = scanTranscriptFile(filePath, true);

    expect(findings).toHaveLength(1);
    expect(linesNotRead).toEqual([]);
  });
});

describe('atomicWrite', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('leaves no temp files on success', () => {
    const filePath = path.join(dir, 'test.jsonl');
    fs.writeFileSync(filePath, 'original');

    atomicWrite(filePath, ['line1', 'line2']);

    // Verify content was written
    expect(fs.readFileSync(filePath, 'utf-8')).toBe('line1\nline2');
    // No temp files remain
    const files = fs.readdirSync(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe('test.jsonl');
  });

  it('cleans up temp file on write error', () => {
    const filePath = path.join(dir, 'nonexistent', 'deep', 'test.jsonl');

    expect(() => atomicWrite(filePath, ['line1'])).toThrow();

    // Verify no temp files left behind
    const rootFiles = fs.readdirSync(dir);
    expect(rootFiles).toHaveLength(0);
  });
});

describe('discoverTranscripts', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('finds nested .jsonl files', () => {
    const projectDir = path.join(dir, 'project1');
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, 'session1.jsonl'), '{}');
    fs.writeFileSync(path.join(projectDir, 'session2.jsonl'), '{}');

    const found = discoverTranscripts(dir);

    expect(found).toHaveLength(2);
    expect(found.every(f => f.endsWith('.jsonl'))).toBe(true);
  });

  it('skips tool-results directories', () => {
    const projectDir = path.join(dir, 'project1');
    const toolResultsDir = path.join(projectDir, 'tool-results');
    fs.mkdirSync(toolResultsDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, 'session.jsonl'), '{}');
    fs.writeFileSync(path.join(toolResultsDir, 'result.jsonl'), '{}');

    const found = discoverTranscripts(dir);

    expect(found).toHaveLength(1);
    expect(found[0]).toContain('session.jsonl');
  });

  it('finds session-memory summary.md files', () => {
    const memDir = path.join(dir, 'project1', 'session-memory');
    fs.mkdirSync(memDir, { recursive: true });
    fs.writeFileSync(path.join(memDir, 'summary.md'), '# Summary');
    fs.writeFileSync(path.join(dir, 'project1', 'session.jsonl'), '{}');

    const found = discoverTranscripts(dir);

    expect(found).toHaveLength(2);
    expect(found.some(f => f.endsWith('summary.md'))).toBe(true);
  });

  it('returns single file when given a file path', () => {
    const filePath = path.join(dir, 'test.jsonl');
    fs.writeFileSync(filePath, '{}');

    const found = discoverTranscripts(filePath);

    expect(found).toEqual([filePath]);
  });
});

describe('cleanTranscripts', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  it('--last only processes newest file per project directory', () => {
    const project1 = path.join(dir, 'project1');
    const project2 = path.join(dir, 'project2');
    fs.mkdirSync(project1, { recursive: true });
    fs.mkdirSync(project2, { recursive: true });

    const secretLine = JSON.stringify({ message: { content: 'sk-ant-api03-abc123def456abc123def456abc123' } });
    fs.writeFileSync(path.join(project1, 'old.jsonl'), secretLine);
    fs.writeFileSync(path.join(project1, 'new.jsonl'), secretLine);
    fs.writeFileSync(path.join(project2, 'only.jsonl'), secretLine);

    const result = cleanTranscripts({ dryRun: true, targetPath: dir, lastSession: true });

    // Should process 1 file per project directory = 2 files (project1 + project2)
    // Each project dir gets only its newest .jsonl
    expect(result.filesScanned).toBe(2);
    expect(result.filesWithSecrets).toBe(2);
  });

  it('full clean redacts and writes back', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const lines = [
      JSON.stringify({ message: { content: 'key: sk-ant-api03-abc123def456abc123def456abc123' } }),
      JSON.stringify({ message: { content: 'token: ghp_abcdefghijklmnopqrstuvwxyz0123456789' } }),
    ];
    fs.writeFileSync(filePath, lines.join('\n'));

    const result = cleanTranscripts({ targetPath: filePath });

    expect(result.totalFindings).toBe(2);
    expect(result.totalRedacted).toBe(2);

    // Verify file was modified
    const content = fs.readFileSync(filePath, 'utf-8');
    expect(content).toContain('[REDACTED:anthropic]');
    expect(content).toContain('[REDACTED:github-pat]');
    expect(content).not.toContain('sk-ant-api03');
    expect(content).not.toContain('ghp_');

    // Verify each line is still valid JSON
    for (const line of content.split('\n').filter(l => l.trim())) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it('is idempotent — re-scanning redacted file finds zero secrets', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const line = JSON.stringify({ message: { content: 'sk-ant-api03-abc123def456abc123def456abc123' } });
    fs.writeFileSync(filePath, line);

    // First clean
    cleanTranscripts({ targetPath: filePath });

    // Second clean — should find nothing
    const result = cleanTranscripts({ targetPath: filePath, dryRun: true });
    expect(result.totalFindings).toBe(0);
  });

  it('counts the lines over the length cap that it leaves unchanged, per file', () => {
    const filePath = path.join(dir, 'session.jsonl');
    const pat = ['gh', 'p_', 'FAKER1T2Y3U4I5O6P7A8S9D0F1G2H3J4K5L6'].join('');
    const long = JSON.stringify({ message: { content: 'x'.repeat(MAX_LINE_SIZE) + ' token ' + pat } });
    const lines = [
      JSON.stringify({ message: { content: 'key: sk-ant-api03-FAKE23def456abc123def456abc123' } }),
      long,
      long,
    ];
    fs.writeFileSync(filePath, lines.join('\n'));

    const result = cleanTranscripts({ targetPath: filePath });

    expect(result.totalFindings).toBe(1);
    expect(result.totalLinesNotRead).toBe(2);
    expect(result.linesNotRead).toEqual([{ file: filePath.replace(os.homedir(), '~'), path: filePath, lines: [2, 3] }]);
    // Redaction rewrote line 1 and left the unread lines byte-for-byte as they were.
    const after = fs.readFileSync(filePath, 'utf-8').split('\n');
    expect(after[0]).toContain('[REDACTED:anthropic]');
    expect(after[1]).toBe(long);
    expect(after[2]).toBe(long);
  });

  it('CONTROL: a transcript with no long line reports nothing unread', () => {
    const filePath = path.join(dir, 'session.jsonl');
    fs.writeFileSync(filePath, JSON.stringify({ message: { content: 'hello' } }) + '\n');

    const result = cleanTranscripts({ targetPath: filePath, dryRun: true });

    expect(result.totalLinesNotRead).toBe(0);
    expect(result.linesNotRead).toEqual([]);
  });
});

describe('secret-named assignments with no vendor prefix', () => {
  // Process listings and environment dumps print `NAME=value`. The values are
  // generated per run: none of them carries a vendor prefix, so only the
  // variable name can identify them as secrets.
  const hex = (bytes: number) => crypto.randomBytes(bytes).toString('hex');
  const jira = hex(12);
  const gamma = ['sk', 'gamma', hex(21)].join('-');
  const service = hex(16);
  const listing = `npm exec x JIRA_TOKEN=${jira} GAMMA_API_KEY=${gamma} MY_SERVICE_TOKEN=${service}`;
  const pat = 'ghp_' + 'A1b2C3d4E5'.repeat(4).slice(0, 36);

  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { cleanup(dir); });

  function scan(text: string): { findings: TranscriptFinding[]; text: string } {
    const findings: TranscriptFinding[] = [];
    const result = deepScan({ message: { content: text } }, '', findings, { file: 'test.jsonl', line: 1 }) as any;
    return { findings, text: result.message.content };
  }

  it('redacts each value and keeps the variable names', () => {
    const { findings, text } = scan(listing);

    expect(findings).toHaveLength(1);
    expect(findings[0].patternId).toBe('secret-assignment');
    for (const value of [jira, gamma, service]) expect(text).not.toContain(value);
    expect(text).toBe(
      'npm exec x JIRA_TOKEN=[REDACTED:secret-assignment] GAMMA_API_KEY=[REDACTED:secret-assignment] ' +
      'MY_SERVICE_TOKEN=[REDACTED:secret-assignment]',
    );
  });

  it('redacts a quoted value and the common secret-name endings', () => {
    const names = ['DB_PASSWORD', 'PGPASSWORD', 'CLIENT_SECRET', 'SECRET_KEY', 'SIGNING_PRIVATE_KEY', 'S3_ACCESS_KEY', 'SERVICE_CREDENTIAL'];
    for (const name of names) {
      const value = hex(10);
      const { findings, text } = scan(`export ${name}="${value}"`);
      expect(findings.map((f) => f.patternId), name).toEqual(['secret-assignment']);
      expect(text).toBe(`export ${name}="[REDACTED:secret-assignment]"`);
    }
  });

  it('reports a vendor-shaped value once, under its vendor pattern', () => {
    const { findings, text } = scan(`control GITHUB_TOKEN=${pat}`);

    expect(findings.map((f) => f.patternId)).toEqual(['github-pat']);
    expect(text).toBe('control GITHUB_TOKEN=[REDACTED:github-pat]');
  });

  it('leaves names that only contain a secret word, references and env accessors alone', () => {
    const benign = [
      'TOKEN_COUNT=3 MAX_TOKENS=4096',
      'MAX_TOKENS=409600000 TOKEN_LIMIT=100000000',
      'GOOGLE_APPLICATION_CREDENTIALS=/home/me/service-account.json',
      'API_KEY=$API_KEY GITHUB_TOKEN=${GITHUB_TOKEN} NPM_TOKEN=$(cat token-file)',
      'API_KEY=process.env.API_KEY SECRET_KEY=os.environ.get',
      'API_KEY=<your-api-key> PASSWORD=********',
      'myAPI_KEY=abcdefgh1234 api_key=abcdefgh1234',
      'API_KEY = abcdefgh1234',
      'GITHUB_TOKEN=short',
    ];
    for (const line of benign) {
      const { findings, text } = scan(line);
      expect(findings, line).toHaveLength(0);
      expect(text).toBe(line);
    }
  });

  it('clean redacts the transcript lines and a second run finds nothing', () => {
    const projectDir = path.join(dir, 'p1');
    fs.mkdirSync(projectDir);
    const record = (content: string) => JSON.stringify({
      type: 'user',
      message: { role: 'user', content: [{ type: 'tool_result', content }] },
    });
    const t1 = path.join(projectDir, 't1.jsonl');
    const t2 = path.join(projectDir, 't2.jsonl');
    const t3 = path.join(projectDir, 't3.jsonl');
    fs.writeFileSync(t1, record(listing) + '\n');
    fs.writeFileSync(t2, record(`control GITHUB_TOKEN=${pat}`) + '\n');
    fs.writeFileSync(t3, record('TOKEN_COUNT=3 MAX_TOKENS=4096') + '\n');
    const t3Before = fs.readFileSync(t3, 'utf-8');

    const dry = cleanTranscripts({ targetPath: dir, dryRun: true });
    expect(dry.filesScanned).toBe(3);
    expect(dry.filesWithSecrets).toBe(2);

    const result = cleanTranscripts({ targetPath: dir });
    expect(result.totalRedacted).toBe(2);
    const t1After = fs.readFileSync(t1, 'utf-8');
    for (const value of [jira, gamma, service]) expect(t1After).not.toContain(value);
    expect(() => JSON.parse(t1After)).not.toThrow();
    expect(fs.readFileSync(t3, 'utf-8')).toBe(t3Before);

    expect(cleanTranscripts({ targetPath: dir, dryRun: true }).totalFindings).toBe(0);
  });
});
