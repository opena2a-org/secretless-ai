import { describe, it, expect } from 'vitest';
import { formatCommandError } from './utils';

describe('formatCommandError: the one layout for a printed command error (#205)', () => {
  it('labels the first line and keeps the indent a message gives its own Verify and Fix lines', () => {
    const err = new Error([
      'The store refused the read.',
      '',
      '  Nothing was read.',
      '',
      '  Verify:  printenv SOME_SWITCH',
      '  Fix:     unset SOME_SWITCH',
    ].join('\n'));
    expect(formatCommandError(err)).toBe([
      '',
      '  Error: The store refused the read.',
      '',
      '  Nothing was read.',
      '',
      '  Verify:  printenv SOME_SWITCH',
      '  Fix:     unset SOME_SWITCH',
      '',
    ].join('\n'));
  });

  it('indents a continuation line that carries no indent of its own, so nothing lands at column 0', () => {
    const out = formatCommandError(new Error('Not found: NAME\n\nVerify:  secretless-ai secret list'));
    expect(out).toBe('\n  Error: Not found: NAME\n\n  Verify:  secretless-ai secret list\n');
  });

  it('prints a thrown value that is not an Error by its string form', () => {
    expect(formatCommandError('plain text')).toBe('\n  Error: plain text\n');
  });
});
