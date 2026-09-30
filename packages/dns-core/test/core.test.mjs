import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reversePointerName } from '../dist/utils/ip.js';
import { prepareQuery } from '../dist/dns/lookup.js';
import { DohTransport } from '../dist/dns/transport.js';

test('IPv6 reverse pointer expands all 32 nibbles', () => {
  assert.equal(reversePointerName('::1'), '1.' + '0.'.repeat(31) + 'ip6.arpa');
  assert.equal(reversePointerName('192.0.2.1'), '1.2.0.192.in-addr.arpa');
});
test('synthetic DNS types prepare consistent wire queries', () => {
  assert.equal(prepareQuery('example.com', 'DMARC').queryName, '_dmarc.example.com');
  assert.equal(prepareQuery('example.com', 'DKIM', 's1').queryName, 's1._domainkey.example.com');
  assert.equal(prepareQuery('example.com', 'SPF').underlyingType, 'TXT');
});
test('DoH falls back to GET on method rejection with a shared timeout signal', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url: String(url), options });
    return calls.length === 1 ? new Response('', { status: 405 }) : new Response(new Uint8Array([1, 2]));
  });
  assert.deepEqual(await new DohTransport('https://resolver.example/dns-query').query(new Uint8Array([255])), new Uint8Array([1, 2]));
  assert.match(calls[1].url, /dns=_w/);
  assert.equal(calls[0].options.signal, calls[1].options.signal);
});
