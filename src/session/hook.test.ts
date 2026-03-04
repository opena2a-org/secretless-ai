import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { hookCheck } from './hook';
import { writeSessionState, clearSessionState } from './session-state';

const SESSION_DIR = path.join(os.homedir(), '.secretless-ai');
const SESSION_FILE = path.join(SESSION_DIR, 'session.json');

describe('hook', () => {
  let originalState: string | null = null;

  beforeEach(() => {
    if (fs.existsSync(SESSION_FILE)) {
      originalState = fs.readFileSync(SESSION_FILE, 'utf-8');
    }
  });

  afterEach(() => {
    if (originalState !== null) {
      fs.writeFileSync(SESSION_FILE, originalState);
    } else if (fs.existsSync(SESSION_FILE)) {
      fs.unlinkSync(SESSION_FILE);
    }
    originalState = null;
  });

  describe('hookCheck', () => {
    it('passes when session is warm', () => {
      writeSessionState(300);
      const result = hookCheck();
      expect(result.passed).toBe(true);
      expect(result.sessionWarm).toBe(true);
      expect(result.message).toBe('');
    });

    it('passes when no session has ever existed (permissive)', () => {
      clearSessionState();
      const result = hookCheck();
      expect(result.passed).toBe(true);
      expect(result.sessionWarm).toBe(false);
      expect(result.message).toBe('');
    });

    it('fails when session existed but expired', () => {
      // Write an expired session
      const state = {
        authenticatedAt: new Date(Date.now() - 600 * 1000).toISOString(),
        ttlSeconds: 300,
        pid: process.pid,
        hostname: os.hostname(),
        version: 1,
      };
      fs.mkdirSync(SESSION_DIR, { recursive: true });
      fs.writeFileSync(SESSION_FILE, JSON.stringify(state));

      const result = hookCheck();
      expect(result.passed).toBe(false);
      expect(result.sessionWarm).toBe(false);
      expect(result.message).toContain('expired');
      expect(result.message).toContain('secretless-ai warm');
    });
  });
});
