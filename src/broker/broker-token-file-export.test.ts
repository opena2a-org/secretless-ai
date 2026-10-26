/**
 * The broker token file's default path is exported, so a library caller that starts a daemon
 * with no `tokenFile` can find the token: `startDaemon` prints nothing.
 */

import { describe, it, expect, afterAll, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import * as broker from './index';
import * as root from '../index';
import { TOKEN_FILE } from './server';

// server.ts fixes TOKEN_FILE under ~/.secretless-ai when it loads, so HOME is a temporary
// directory set before the modules load (the form of daemon.test.ts).
const testHome = vi.hoisted(() => {
  const fs = require('fs') as typeof import('fs');
  const os = require('os') as typeof import('os');
  const path = require('path') as typeof import('path');
  const original = process.env.HOME;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sl-token-export-'));
  process.env.HOME = dir;
  return { dir, original };
});

afterAll(() => {
  if (testHome.original === undefined) delete process.env.HOME;
  else process.env.HOME = testHome.original;
  fs.rmSync(testHome.dir, { recursive: true, force: true });
});

describe('BROKER_TOKEN_FILE', () => {
  it('is the token file a broker started with no tokenFile writes, from the broker module and the package root', () => {
    expect(broker.BROKER_TOKEN_FILE).toBe(TOKEN_FILE);
    expect(root.BROKER_TOKEN_FILE).toBe(TOKEN_FILE);
    expect(TOKEN_FILE).toBe(path.join(testHome.dir, '.secretless-ai', 'broker.token'));
  });
});
