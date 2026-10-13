import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * A reporter who reads the README and then SECURITY.md must find one response
 * commitment, not two. The README promised a response "within 24 hours" while
 * SECURITY.md said "We acknowledge receipt within 48 hours" (#345). SECURITY.md
 * is the policy, so the README states the same commitment and points to it,
 * along with the private vulnerability reporting it names.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
const read = (name: string) => fs.readFileSync(path.join(REPO_ROOT, name), 'utf-8');
const hoursIn = (text: string) => [...text.matchAll(/within (\d+) hours/g)].map((m) => Number(m[1]));

describe('security report response time', () => {
  it('SECURITY.md states one acknowledgement commitment', () => {
    expect(read('SECURITY.md')).toMatch(/We acknowledge receipt within \d+ hours/);
    expect(new Set(hoursIn(read('SECURITY.md'))).size).toBe(1);
  });

  // CONTRIBUTING.md carries the line the README's Contributing section held.
  it.each(['README.md', 'CONTRIBUTING.md'])('%s states the same commitment as SECURITY.md and points to it', (page) => {
    const policyHours = hoursIn(read('SECURITY.md'))[0];
    const lines = read(page).split('\n');
    const line = lines.find((l) => l.startsWith('Security issues:'));
    expect(line, `${page} must keep its "Security issues:" line`).toBeDefined();
    expect(hoursIn(line!)).toEqual([policyHours]);
    expect(line).toContain('[SECURITY.md](SECURITY.md)');
    expect(line).toContain('https://github.com/opena2a-org/secretless-ai/security/advisories/new');
    expect(read('SECURITY.md')).toContain('https://github.com/opena2a-org/secretless-ai/security/advisories/new');

    const elsewhere = lines.filter((l) => l !== line).join('\n');
    expect(hoursIn(elsewhere), `no other ${page} line may state a response time`).toEqual([]);
  });
});
