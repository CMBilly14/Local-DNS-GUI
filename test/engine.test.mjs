import { test } from 'node:test';
import assert from 'node:assert/strict';
import { walk, fingerprint, validateRequest, digCommand } from '../src/engine.mjs';

const options = validateRequest({ name: 'www.example.com' });
function answer(server, records = [], authority = false, additionals = [], answers = [], rcode = 'NOERROR') {
  return { server, name: 'www.example.com', type: 'A', authoritative: authority,
    packet: { authorities: records, additionals, answers, rcode } };
}
test('trace walks referrals with RD=0, retries failed servers and records the failure', async () => {
  const calls = [];
  const query = async (name, type, server, opts) => {
    calls.push({ server, rd: opts.rd });
    if (server === 'root-bad') throw new Error('timeout');
    if (server === 'root') return answer(server, [{ name: 'com', type: 'NS', data: 'ns.com' }], false, [{ name: 'ns.com', type: 'A', data: '192.0.2.1' }]);
    if (server === '192.0.2.1') return answer(server, [{ name: 'example.com', type: 'NS', data: 'ns.example.com' }], false, [{ name: 'ns.example.com', type: 'A', data: '192.0.2.2' }]);
    return answer(server, [], true, [], [{ name, type, data: '192.0.2.3' }]);
  };
  const report = await walk('www.example.com', 'A', options, { queries: 0, roots: ['root-bad', 'root'], query });
  assert.equal(report.result.server, '192.0.2.2');
  assert.equal(report.steps[0].error, 'timeout');
  assert.equal(report.steps.length, 4);
  assert.ok(calls.every(c => c.rd === false));
});
test('trace stops a looping referral instead of hanging', async () => {
  const report = await walk('www.example.com', 'A', options, { queries: 0, roots: ['root'], query: async () => answer('root', [{ name: 'com', type: 'NS', data: 'ns.com' }], false, [{ name: 'ns.com', type: 'A', data: '192.0.2.1' }]) });
  assert.match(report.error, /advancing referral/);
  assert.equal(report.steps.length, 2);
});
test('out-of-bailiwick additional data is ignored and NS address is resolved from roots', async () => {
  const visited = [];
  const query = async (name, type, server) => {
    visited.push(server);
    if (name === 'ns.provider.net') return answer(server, [], true, [], [{ name, type, data: '192.0.2.20' }]);
    if (server === '192.0.2.20') return answer(server, [], true);
    if (server === 'root') return answer(server, [{ name: 'com', type: 'NS', data: 'ns.com' }], false, [{ name: 'ns.com', type: 'A', data: '192.0.2.1' }]);
    return answer(server, [{ name: 'example.com', type: 'NS', data: 'ns.provider.net' }], false, [{ name: 'ns.provider.net', type: 'A', data: '203.0.113.66' }]);
  };
  const result = await walk('www.example.com', 'A', options, { queries: 0, roots: ['root'], query });
  assert.equal(result.result.server, '192.0.2.20');
  assert.ok(!visited.includes('203.0.113.66'));
  assert.ok(result.steps.some(s => s.purpose));
});
test('root glue for sibling TLD nameservers is usable without recursive bootstrap loops', async () => {
  const result = await walk('www.example.com', 'A', options, { queries: 0, roots: ['root'], query: async (_name, _type, server) => server === 'root'
    ? answer(server, [{ name: 'com', type: 'NS', data: 'a.gtld-servers.net' }], false, [{ name: 'a.gtld-servers.net', type: 'A', data: '192.0.2.1' }])
    : answer(server, [], true) });
  assert.equal(result.result.server, '192.0.2.1');
  assert.equal(result.steps.length, 2);
});
test('negative authoritative answers terminate the trace', async () => {
  const result = await walk('absent.example.com', 'A', options, { queries: 0, roots: ['root'], query: async () => answer('root', [], true, [], [], 'NXDOMAIN') });
  assert.equal(result.result.packet.rcode, 'NXDOMAIN');
});
test('comparison ignores TTL/order/case of DNS names but preserves TXT case and errors', () => {
  const a = answer('a', [], true, [], [{ name: 'www.example.com', type: 'A', data: '192.0.2.1', ttl: 3600 }]);
  const b = structuredClone(a); b.packet.answers[0].ttl = 12;
  assert.equal(fingerprint(a), fingerprint(b));
  b.packet.rcode = 'NXDOMAIN'; assert.notEqual(fingerprint(a), fingerprint(b));
  a.type = b.type = 'TXT'; b.packet.rcode = 'NOERROR';
  a.packet.answers = [{ name: a.name, type: 'TXT', data: [Buffer.from('Hello')] }];
  b.packet.answers = [{ name: b.name, type: 'TXT', data: [Buffer.from('hello')] }];
  assert.notEqual(fingerprint(a), fingerprint(b));
});
test('validation rejects unsafe targets, flags, ports and nameserver hostnames', () => {
  for (const input of [{ name: 'example.com; echo bad' }, { name: 'example.com', mode: 'custom', server: 'example.com' }, { name: 'example.com', port: 0 }, { name: 'example.com', rd: 'false' }, { name: '1.1.1.1', type: 'A' }]) assert.throws(() => validateRequest(input));
  assert.equal(validateRequest({ name: '::1', type: 'PTR' }).type, 'PTR');
});
test('dig export preserves destination and protocol controls', () => {
  assert.match(digCommand({ server: '::1', port: 5353, name: 'example.com', type: 'A', protocol: 'tcp (UDP fallback)', rd: false }, options), /@::1 -p 5353 example.com A \+tcp \+norecurse/);
});
