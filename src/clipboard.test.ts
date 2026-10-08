/**
 * Every clipboard clear command gets an empty stdin from the runner, so a
 * tool record carries no per-tool stdin setting that the runner would ignore
 * (#246).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Clipboard, clipboardTools } from './clipboard';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secretless-clipboard-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('clipboard tools', () => {
  it('each tool record holds only the fields the runner reads', () => {
    const sets: Array<[NodeJS.Platform, NodeJS.ProcessEnv]> = [
      ['darwin', {}],
      ['win32', {}],
      ['linux', {}],
      ['linux', { WAYLAND_DISPLAY: 'wayland-0' }],
    ];
    for (const [platform, env] of sets) {
      for (const tool of clipboardTools(platform, env)) {
        expect(Object.keys(tool).sort(), `${platform} ${tool.name}`).toEqual(['clearArgs', 'name', 'readArgs']);
      }
    }
  });

  it.skipIf(process.platform === 'win32')('a clear command gets an empty stdin whichever tool it belongs to', () => {
    // Stand-ins that copy their stdin into the clipboard file. With no stdin
    // given, cat would wait until the runner's timeout.
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const clip = path.join(dir, 'clip');
    for (const name of ['pbcopy', 'xclip', 'xsel']) {
      fs.writeFileSync(path.join(bin, name), `#!/bin/sh\ncat > "${clip}"\n`, { mode: 0o755 });
    }
    const env = { PATH: `${bin}:/usr/bin:/bin` };
    const cases: Array<[NodeJS.Platform, string]> = [['darwin', 'pbpaste'], ['linux', 'xclip'], ['linux', 'xsel']];
    for (const [platform, name] of cases) {
      fs.writeFileSync(clip, 'previous value');
      const clipboard = new Clipboard({ platform, env });
      const tool = clipboardTools(platform, env).find((t) => t.name === name)!;
      expect(clipboard.clear(tool), name).toBeNull();
      expect(fs.readFileSync(clip, 'utf-8'), name).toBe('');
    }
  });
});
