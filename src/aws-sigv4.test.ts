/**
 * AWS Signature Version 4 (src/aws-sigv4.ts). What these tests hold:
 *
 * - The request time is written as AWS writes it, without milliseconds.
 * - The canonical request is the method, the path, an empty query, the
 *   signed headers in canonical form, their names and the body's hash.
 * - The signature is the HMAC chain AWS documents, over that canonical
 *   request, and the secret is in no header the signer returns.
 */
import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'crypto';
import { amzDate, canonicalRequest, signSigV4, type SigV4Request } from './aws-sigv4';

/** Not a credential: STS knows neither value. */
const KEY = { accessKeyId: 'NOTAREALKEYID000', secretAccessKey: 'not-a-real-secret' };
const AT = new Date(Date.UTC(2026, 0, 2, 3, 4, 5));
const BODY = 'Action=GetCallerIdentity&Version=2011-06-15';
const STS: SigV4Request = {
  method: 'POST', host: 'sts.amazonaws.com', path: '/', body: BODY, region: 'us-east-1', service: 'sts',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
};

const sha256Hex = (text: string): string => createHash('sha256').update(text).digest('hex');
const hmac = (key: string | Buffer, text: string): Buffer => createHmac('sha256', key).update(text).digest();

describe('amzDate', () => {
  it('writes the UTC time as yyyymmddThhmmssZ, without milliseconds', () => {
    expect(amzDate(new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 678)))).toBe('20260102T030405Z');
    expect(amzDate(new Date(Date.UTC(2015, 7, 30, 12, 36, 0)))).toBe('20150830T123600Z');
  });
});

describe('canonicalRequest', () => {
  it('is the method, the path, an empty query, the signed headers, their names and the body hash', () => {
    expect(canonicalRequest(STS, '20260102T030405Z')).toBe([
      'POST',
      '/',
      '',
      'content-type:application/x-www-form-urlencoded; charset=utf-8',
      'host:sts.amazonaws.com',
      'x-amz-date:20260102T030405Z',
      '',
      'content-type;host;x-amz-date',
      sha256Hex(BODY),
    ].join('\n'));
  });

  it('writes header names in lower case and name order, with values trimmed and inner whitespace made one space', () => {
    const request: SigV4Request = { ...STS, method: 'GET', body: '', headers: { 'X-Custom': '  a \t  b  ', Accept: 'text/xml' } };
    const lines = canonicalRequest(request, '20260102T030405Z').split('\n');
    expect(lines.slice(3, 8)).toEqual(['accept:text/xml', 'host:sts.amazonaws.com', 'x-amz-date:20260102T030405Z', 'x-custom:a b', '']);
    expect(lines[8]).toBe('accept;host;x-amz-date;x-custom');
    expect(lines[9]).toBe(sha256Hex(''));
  });
});

describe('signSigV4', () => {
  it('signs with the HMAC chain AWS documents, over the canonical request', () => {
    const date = '20260102T030405Z';
    const scope = '20260102/us-east-1/sts/aws4_request';
    const stringToSign = ['AWS4-HMAC-SHA256', date, scope, sha256Hex(canonicalRequest(STS, date))].join('\n');
    const signingKey = hmac(hmac(hmac(hmac(`AWS4${KEY.secretAccessKey}`, '20260102'), 'us-east-1'), 'sts'), 'aws4_request');
    const signature = hmac(signingKey, stringToSign).toString('hex');
    expect(signSigV4(STS, KEY, AT)).toEqual({
      'X-Amz-Date': date,
      Authorization: `AWS4-HMAC-SHA256 Credential=NOTAREALKEYID000/${scope}, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`,
    });
    // The same signature written out, so a change to the chain above shows too.
    expect(signature).toBe('c75a60d64ece254e964e4f3d05933a1d6cbd50b795044751269af472b538d383');
  });

  it('puts the key ID in the Credential field and the secret in no header', () => {
    const headers = signSigV4(STS, KEY, AT);
    expect(headers.Authorization).toContain('Credential=NOTAREALKEYID000/');
    expect(JSON.stringify(headers)).not.toContain(KEY.secretAccessKey);
  });

  it('gives a different signature for a different secret, time or body', () => {
    const signatureOf = (headers: { Authorization: string }): string => headers.Authorization.slice(headers.Authorization.indexOf('Signature='));
    const base = signatureOf(signSigV4(STS, KEY, AT));
    expect(signatureOf(signSigV4(STS, { ...KEY, secretAccessKey: 'another-not-real-secret' }, AT))).not.toBe(base);
    expect(signatureOf(signSigV4(STS, KEY, new Date(AT.getTime() + 1000)))).not.toBe(base);
    expect(signatureOf(signSigV4({ ...STS, body: `${BODY}&x=1` }, KEY, AT))).not.toBe(base);
  });
});
