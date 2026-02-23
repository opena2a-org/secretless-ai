import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { installPreCommitHook, uninstallPreCommitHook, isHookInstalled } from './git-hook';

describe('git-hook', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-hook-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('installPreCommitHook', () => {
    it('installs hook in git repo', () => {
      fs.mkdirSync(path.join(tmpDir, '.git'), { recursive: true });

      const result = installPreCommitHook(tmpDir);
      expect(result.installed).toBe(true);

      const hookPath = path.join(tmpDir, '.git', 'hooks', 'pre-commit');
      expect(fs.existsSync(hookPath)).toBe(true);

      const content = fs.readFileSync(hookPath, 'utf-8');
      expect(content).toContain('secretless-ai');
      expect(content).toContain('scan-staged');
    });

    it('fails when not a git repo', () => {
      const result = installPreCommitHook(tmpDir);
      expect(result.installed).toBe(false);
      expect(result.message).toContain('Not a git repository');
    });

    it('does not overwrite foreign hook', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(path.join(hooksDir, 'pre-commit'), '#!/bin/sh\necho "custom hook"');

      const result = installPreCommitHook(tmpDir);
      expect(result.installed).toBe(false);
      expect(result.message).toContain('already exists');
    });

    it('updates existing secretless hook', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        path.join(hooksDir, 'pre-commit'),
        '#!/bin/sh\n# secretless-ai pre-commit hook\nold version',
      );

      const result = installPreCommitHook(tmpDir);
      expect(result.installed).toBe(true);
      expect(result.message).toContain('updated');
    });
  });

  describe('uninstallPreCommitHook', () => {
    it('removes secretless hook', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        path.join(hooksDir, 'pre-commit'),
        '#!/bin/sh\n# secretless-ai pre-commit hook\nnpx secretless-ai scan-staged',
      );

      const result = uninstallPreCommitHook(tmpDir);
      expect(result.removed).toBe(true);
      expect(fs.existsSync(path.join(hooksDir, 'pre-commit'))).toBe(false);
    });

    it('refuses to remove foreign hook', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(path.join(hooksDir, 'pre-commit'), '#!/bin/sh\necho "custom"');

      const result = uninstallPreCommitHook(tmpDir);
      expect(result.removed).toBe(false);
      expect(result.message).toContain('not installed by secretless');
    });

    it('reports when no hook exists', () => {
      fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
      const result = uninstallPreCommitHook(tmpDir);
      expect(result.removed).toBe(false);
      expect(result.message).toContain('No pre-commit hook');
    });
  });

  describe('isHookInstalled', () => {
    it('returns true when secretless hook is installed', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        path.join(hooksDir, 'pre-commit'),
        '#!/bin/sh\n# secretless-ai pre-commit hook\nnpx secretless-ai scan-staged',
      );

      expect(isHookInstalled(tmpDir)).toBe(true);
    });

    it('returns false when no hook exists', () => {
      fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
      expect(isHookInstalled(tmpDir)).toBe(false);
    });

    it('returns false for foreign hook', () => {
      const hooksDir = path.join(tmpDir, '.git', 'hooks');
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(path.join(hooksDir, 'pre-commit'), '#!/bin/sh\necho "custom"');

      expect(isHookInstalled(tmpDir)).toBe(false);
    });
  });
});
