import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  readSessionState,
  writeSessionState,
  getSessionStatus,
  isSessionWarm,
  clearSessionState,
  getSessionFilePath,
  DEFAULT_SESSION_TTL_SECONDS,
  MAX_SESSION_TTL_SECONDS,
} from './session-state';

const SESSION_DIR = path.join(os.homedir(), '.secretless-ai');
const SESSION_FILE = path.join(SESSION_DIR, 'session.json');

describe('session-state', () => {
  let originalState: string | null = null;

  beforeEach(() => {
    // Backup existing session file
    if (fs.existsSync(SESSION_FILE)) {
      originalState = fs.readFileSync(SESSION_FILE, 'utf-8');
    }
  });

  afterEach(() => {
    // Restore original session file
    if (originalState !== null) {
      fs.writeFileSync(SESSION_FILE, originalState);
    } else if (fs.existsSync(SESSION_FILE)) {
      fs.unlinkSync(SESSION_FILE);
    }
    originalState = null;
  });

  describe('getSessionFilePath', () => {
    it('returns the session file path', () => {
      const filePath = getSessionFilePath();
      expect(filePath).toContain('.secretless-ai');
      expect(filePath).toContain('session.json');
    });
  });

  describe('writeSessionState', () => {
    it('creates a session state file', () => {
      const state = writeSessionState(300);
      expect(state.version).toBe(1);
      expect(state.ttlSeconds).toBe(300);
      expect(state.pid).toBe(process.pid);
      expect(state.hostname).toBe(os.hostname());
      expect(new Date(state.authenticatedAt).getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('uses default TTL when not specified', () => {
      const state = writeSessionState();
      expect(state.ttlSeconds).toBe(DEFAULT_SESSION_TTL_SECONDS);
    });

    it('clamps TTL to maximum', () => {
      const state = writeSessionState(999999);
      expect(state.ttlSeconds).toBe(MAX_SESSION_TTL_SECONDS);
    });

    it('clamps TTL to minimum of 1', () => {
      const state = writeSessionState(0);
      expect(state.ttlSeconds).toBe(1);
    });
  });

  describe('readSessionState', () => {
    it('returns null when no session file exists', () => {
      if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
      expect(readSessionState()).toBeNull();
    });

    it('reads a valid session file', () => {
      writeSessionState(120);
      const state = readSessionState();
      expect(state).not.toBeNull();
      expect(state!.ttlSeconds).toBe(120);
      expect(state!.version).toBe(1);
    });

    it('returns null for corrupted session file', () => {
      fs.mkdirSync(SESSION_DIR, { recursive: true });
      fs.writeFileSync(SESSION_FILE, 'not json');
      expect(readSessionState()).toBeNull();
    });

    it('returns null for wrong version', () => {
      fs.mkdirSync(SESSION_DIR, { recursive: true });
      fs.writeFileSync(SESSION_FILE, JSON.stringify({ version: 99 }));
      expect(readSessionState()).toBeNull();
    });
  });

  describe('getSessionStatus', () => {
    it('reports warm for fresh session', () => {
      writeSessionState(300);
      const status = getSessionStatus();
      expect(status.warm).toBe(true);
      expect(status.remainingSeconds).toBeGreaterThan(0);
      expect(status.remainingSeconds).toBeLessThanOrEqual(300);
      expect(status.expiresAt).not.toBe('');
      expect(status.authenticatedAt).not.toBe('');
    });

    it('reports not warm when no session exists', () => {
      if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
      const status = getSessionStatus();
      expect(status.warm).toBe(false);
      expect(status.remainingSeconds).toBe(0);
      expect(status.expiresAt).toBe('');
    });

    it('reports expired for old session', () => {
      // Write a session that expired 10 seconds ago
      const state = {
        authenticatedAt: new Date(Date.now() - 310 * 1000).toISOString(),
        ttlSeconds: 300,
        pid: process.pid,
        hostname: os.hostname(),
        version: 1,
      };
      fs.mkdirSync(SESSION_DIR, { recursive: true });
      fs.writeFileSync(SESSION_FILE, JSON.stringify(state));

      const status = getSessionStatus();
      expect(status.warm).toBe(false);
      expect(status.remainingSeconds).toBe(0);
    });

    it('respects TTL override', () => {
      writeSessionState(300);
      // Override with 1 second — should expire immediately (or be about to)
      const status = getSessionStatus(1);
      expect(status.ttlSeconds).toBe(1);
    });
  });

  describe('isSessionWarm', () => {
    it('returns true for active session', () => {
      writeSessionState(300);
      expect(isSessionWarm()).toBe(true);
    });

    it('returns false when no session', () => {
      if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
      expect(isSessionWarm()).toBe(false);
    });
  });

  describe('clearSessionState', () => {
    it('removes session file', () => {
      writeSessionState(300);
      expect(fs.existsSync(SESSION_FILE)).toBe(true);
      const cleared = clearSessionState();
      expect(cleared).toBe(true);
      expect(fs.existsSync(SESSION_FILE)).toBe(false);
    });

    it('returns false when no session file', () => {
      if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
      expect(clearSessionState()).toBe(false);
    });
  });
});
