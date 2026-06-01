/**
 * HTTPS token-exchange transport — the concrete wire for ExchangeProvider.
 *
 * Generic and vendor-free: POSTs `application/x-www-form-urlencoded` to any RFC 8693
 * token endpoint and parses the JSON response. Used by provider adapters (e.g. the Okta
 * adapter), never referenced from the broker core.
 */

import * as https from 'https';
import * as http from 'http';
import type { TokenExchangeRequest, TokenExchangeResponse, TokenExchangeTransport } from './exchange';

const REQUEST_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_SIZE = 256 * 1024;

export class HttpsTokenExchangeTransport implements TokenExchangeTransport {
  exchange(req: TokenExchangeRequest): Promise<TokenExchangeResponse> {
    return new Promise((resolve, reject) => {
      const url = new URL(req.tokenEndpoint);
      const transport = url.protocol === 'http:' ? http : https;
      const body = new URLSearchParams(req.params).toString();

      const request = transport.request(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'http:' ? 80 : 443),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
            Accept: 'application/json',
          },
          timeout: REQUEST_TIMEOUT_MS,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_SIZE) {
              res.destroy();
              reject(new Error('token endpoint response too large'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const status = res.statusCode ?? 0;
            const text = Buffer.concat(chunks).toString('utf-8');
            if (status < 200 || status >= 300) {
              // Opaque to the caller chain — detail goes to the broker audit log, not the agent.
              reject(new Error(`token exchange failed (status ${status})`));
              return;
            }
            try {
              resolve(JSON.parse(text) as TokenExchangeResponse);
            } catch {
              reject(new Error('token endpoint returned non-JSON response'));
            }
          });
        },
      );

      request.on('error', (err) => reject(err));
      request.on('timeout', () => {
        request.destroy();
        reject(new Error('token exchange timed out'));
      });
      request.write(body);
      request.end();
    });
  }
}
