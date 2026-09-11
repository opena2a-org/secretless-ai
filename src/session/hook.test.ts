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
      expect(result.tampered).toBe(false);
      expect(result.reason).toBe('');
      expect(result.denyJson).toBe('');
    });

    it('passes when no session has ever existed (permissive)', () => {
      clearSessionState();
      const result = hookCheck();
      expect(result.passed).toBe(true);
      expect(result.sessionWarm).toBe(false);
      expect(result.tampered).toBe(false);
      expect(result.reason).toBe('');
      expect(result.denyJson).toBe('');
    });

    it('fails when session existed but expired', async () => {
      writeSessionState(1);
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const result = hookCheck();
      expect(result.passed).toBe(false);
      expect(result.sessionWarm).toBe(false);
      expect(result.tampered).toBe(false);
      expect(result.reason).toContain('expired');
      expect(result.reason).toContain('secretless-ai warm');
      expect(result.denyJson).toContain('"permissionDecision":"deny"');
      expect(result.denyJson).toContain('"hookEventName":"PreToolUse"');
    });

    it('fails when the session file has a bad HMAC (tampered)', () => {
      writeSessionState(300);
      const persisted = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8'));
      persisted.ttlSeconds = 999; // mutate signed content so the HMAC no longer matches
      fs.writeFileSync(SESSION_FILE, JSON.stringify(persisted, null, 2));

      const result = hookCheck();
      expect(result.passed).toBe(false);
      expect(result.tampered).toBe(true);
      expect(result.reason).toMatch(/tamper/);
      expect(result.denyJson).toContain('"permissionDecision":"deny"');
    });
  });
});
