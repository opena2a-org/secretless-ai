import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * A version heading in CHANGELOG.md carries the date that version was
 * published. A heading with a placeholder date names a version that was never
 * released, so its entries read as shipped when they are not: they belong
 * under Unreleased until the release is cut.
 */

const CHANGELOG = fs.readFileSync(path.resolve(__dirname, '..', 'CHANGELOG.md'), 'utf8');

describe('CHANGELOG version headings', () => {
  it('every version heading names a version and a calendar date', () => {
    const headings = CHANGELOG.split('\n').filter(l => l.startsWith('## [') && l !== '## [Unreleased]');
    expect(headings.length).toBeGreaterThan(0);
    const undated = headings.filter(l => !/^## \[\d+\.\d+\.\d+\] - \d{4}-\d{2}-\d{2}$/.test(l));
    expect(undated, 'move these entries under ## [Unreleased], or give the heading the date the version was published').toEqual([]);
  });
});
