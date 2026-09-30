import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import packet from 'dns-packet';
import { selectAnswerRecords, fingerprint, runQuery } from '../src/engine.mjs';

const txt = (...parts) => ({ name: 'example.com', type: 'TXT', ttl: 60, data: parts.map(p => Buffer.from(p)) });
const mixed = [txt('google-site-verification=abc'), txt('v=spf1 include:example.net -all'), txt('v=sp', 'f1 +all'), txt('V=SPF1'), txt('v=spf10 -all'), txt('text v=spf1 -all')];
test('SPF selects all matching records, joins TXT chunks, excludes lookalikes; TXT remains unfiltered', () => {
  assert.deepEqual(selectAnswerRecords(mixed, 'SPF'), mixed.slice(1, 4));
  assert.equal(selectAnswerRecords(mixed, 'TXT'), mixed);
  assert.deepEqual(selectAnswerRecords([mixed[0]], 'SPF'), []);
});
test('SPF comparisons ignore unrelated TXT changes but detect SPF differences', () => {
  const result = answers => ({ name: 'example.com', type: 'TXT', packet: { rcode: 'NOERROR', answers } });
  const a = result([mixed[0], mixed[1]]);
  const b = result([txt('another-verification=xyz'), mixed[1]]);
  assert.equal(fingerprint(a, 'SPF'), fingerprint(b, 'SPF'));
  assert.notEqual(fingerprint(a, 'TXT'), fingerprint(b, 'TXT'));
  assert.notEqual(fingerprint(a, 'SPF'), fingerprint(result([mixed[2]]), 'SPF'));
});
test('real SPF lookup filters display/normalized records and preserves the raw TXT packet', async t => {
  const server = dgram.createSocket('udp4');
  await new Promise(resolve => server.bind(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  server.on('message', (wire, remote) => {
    const query = packet.decode(wire);
    assert.equal(query.questions[0].type, 'TXT');
    server.send(packet.encode({ type: 'response', id: query.id, flags: packet.AUTHORITATIVE_ANSWER, questions: query.questions, answers: mixed }), remote.port, remote.address);
  });
  const report = await runQuery({ name: 'example.com', type: 'SPF', mode: 'custom', server: '127.0.0.1', port: server.address().port });
  assert.equal(report.results[0].answerRecords.length, 3);
  assert.equal(report.results[0].answers.length, 3);
  assert.equal(report.results[0].packet.answers.length, mixed.length);
  assert.match(report.results[0].dig, /example.com TXT/);
});
