/**
 * JCS (RFC 8785) over the JSON value space. The vectors are the RFC's own: the section 3.2.2 and
 * 3.2.3 examples and the Appendix B number samples, each input built from its IEEE 754 bits.
 */

import { describe, expect, it } from 'vitest';
import { canonicalizeJson } from './jcs';

/** The double whose IEEE 754 bits are `hex` (16 hex digits, big-endian). */
function fromBits(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

describe('canonicalizeJson: the RFC 8785 vectors', () => {
  it('serializes and sorts the section 3.2.2 sample as section 3.2.3 shows', () => {
    const parsed: unknown = JSON.parse(
      '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],' +
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",' +
        ' "literals": [null, true, false]}',
    );
    expect(canonicalizeJson(parsed)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it('sorts member names by UTF-16 code units, as the section 3.2.3 test data expects', () => {
    const parsed = JSON.parse(
      '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return",' +
        ' "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",' +
        ' "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",' +
        ' "\\u00f6": "Latin Small Letter O With Diaeresis"}',
    ) as Record<string, string>;
    // The RFC's expected order: Carriage Return, One, Control, Latin Small Letter O With
    // Diaeresis, Euro Sign, Emoji: Grinning Face, Hebrew Letter Dalet With Dagesh.
    expect(canonicalizeJson(parsed)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control",' +
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
        '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it.each([
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ])('writes the Appendix B sample %s as %s', (bits, expected) => {
    expect(canonicalizeJson(fromBits(bits))).toBe(expected);
  });

  it.each([
    ['7fffffffffffffff', 'NaN'],
    ['7ff0000000000000', 'Infinity'],
  ])('refuses the Appendix B sample %s (%s), which has no JSON form', (bits) => {
    expect(() => canonicalizeJson(fromBits(bits))).toThrow(/NaN and Infinity/);
  });
});

describe('canonicalizeJson: the JSON value space and nothing else', () => {
  it('sorts nested members, keeps array order, and emits no whitespace', () => {
    expect(
      canonicalizeJson({ b: [3, { z: 1, a: [true, null] }, 'x'], a: { d: '', c: -0 } }),
    ).toBe('{"a":{"c":0,"d":""},"b":[3,{"a":[true,null],"z":1},"x"]}');
  });

  it('writes U+007F, U+2028 and U+2029 as they are, and controls as escapes', () => {
    expect(canonicalizeJson('\u007f  \b\t\n\f\r\u0000\u001f')).toBe(
      '"\u007f  \\b\\t\\n\\f\\r\\u0000\\u001f"',
    );
  });

  it('accepts a well-formed surrogate pair, and refuses a lone surrogate in a value or a name', () => {
    expect(canonicalizeJson('😀')).toBe('"😀"');
    expect(() => canonicalizeJson('\udead')).toThrow(/lone surrogate/);
    expect(() => canonicalizeJson({ ['\ud800']: 1 })).toThrow(/lone surrogate/);
  });

  it('accepts an object with no prototype', () => {
    const bare = Object.create(null) as Record<string, unknown>;
    bare.b = 1;
    bare.a = 2;
    expect(canonicalizeJson(bare)).toBe('{"a":2,"b":1}');
  });

  class Payee {
    name = 'Fictional Payee Ltd';
  }
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;

  it.each([
    ['undefined', undefined],
    ['a member whose value is undefined', { a: undefined }],
    ['a function', () => 1],
    ['a symbol', Symbol('s')],
    ['a bigint', BigInt(1)],
    ['a Date', new Date(0)],
    ['a Map', new Map()],
    ['a class instance', new Payee()],
    ['an object with a toJSON method', { toJSON: () => 'x' }],
    ['an array hole', [1, , 3]],
    ['a cycle', cyclic],
  ])('refuses %s', (_label, value) => {
    expect(() => canonicalizeJson(value)).toThrow(/^JCS: /);
  });

  it('accepts a value that appears twice without a cycle', () => {
    const shared = { a: 1 };
    expect(canonicalizeJson([shared, { shared }])).toBe('[{"a":1},{"shared":{"a":1}}]');
  });

  it('never quotes the refused value in its message', () => {
    const planted = 'Planted Payee Odalys Brennecke';
    let message = '';
    try {
      canonicalizeJson({ payee: planted, when: new Date(0) });
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toMatch(/^JCS: /);
    expect(message.includes('Odalys')).toBe(false);
  });
});
