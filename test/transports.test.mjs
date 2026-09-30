import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import packet from 'dns-packet';
import { UdpTransport, TcpTransport } from '../src/transports.mjs';

const query = packet.encode({ type: 'query', id: 1234, questions: [{ name: 'example.com', type: 'A' }] });
const response = packet.encode({ type: 'response', id: 1234, questions: [{ name: 'example.com', type: 'A' }], answers: [{ name: 'example.com', type: 'A', ttl: 60, data: '192.0.2.1' }] });
test('UDP ignores incorrect transaction IDs and accepts the matching response', async t => {
  const server = dgram.createSocket('udp4');
  await new Promise(resolve => server.bind(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  server.on('message', (_message, remote) => { const wrong = Buffer.from(response); wrong.writeUInt16BE(4321); server.send(wrong, remote.port, remote.address); server.send(response, remote.port, remote.address); });
  const result = await new UdpTransport('127.0.0.1', server.address().port).query(query, { timeoutMs: 1000 });
  assert.deepEqual(Buffer.from(result), response);
});
test('truncated UDP transparently falls back to a fragmented TCP response', async t => {
  const tcp = net.createServer(socket => { socket.once('data', () => { const frame = Buffer.alloc(response.length + 2); frame.writeUInt16BE(response.length); response.copy(frame, 2); socket.write(frame.subarray(0, 3)); setTimeout(() => socket.end(frame.subarray(3)), 5); }); });
  await new Promise(resolve => tcp.listen(0, '127.0.0.1', resolve));
  const port = tcp.address().port;
  const udp = dgram.createSocket('udp4'); await new Promise(resolve => udp.bind(port, '127.0.0.1', resolve));
  t.after(() => { udp.close(); tcp.close(); });
  udp.on('message', (_message, remote) => { const truncated = Buffer.from(response); truncated[2] |= 2; udp.send(truncated, remote.port, remote.address); });
  const transport = new UdpTransport('127.0.0.1', port);
  const result = await transport.query(query, { timeoutMs: 1000 });
  assert.deepEqual(Buffer.from(result), response); assert.equal(transport.usedTcp, true);
});
test('unresponsive UDP query times out and cancellation closes sockets', async t => {
  const server = dgram.createSocket('udp4'); await new Promise(resolve => server.bind(0, '127.0.0.1', resolve)); t.after(() => server.close());
  const transport = new UdpTransport('127.0.0.1', server.address().port);
  await assert.rejects(transport.query(query, { timeoutMs: 50 }), /timeout/);
  const controller = new AbortController(); const pending = transport.query(query, { timeoutMs: 1000, signal: controller.signal }); controller.abort();
  await assert.rejects(pending, /cancelled/);
});
test('TCP rejects incomplete frames without hanging', async t => {
  const server = net.createServer(socket => socket.once('data', () => socket.end(Buffer.from([0, 50, 0]))));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => server.close());
  await assert.rejects(new TcpTransport('127.0.0.1', server.address().port).query(query, { timeoutMs: 1000 }), /incomplete/);
});
test('a socket becoming disconnected before send rejects instead of crashing the process', async t => {
  class DisconnectedSocket extends EventEmitter {
    connect(_port, _server, callback) { queueMicrotask(callback); }
    send() { throw new Error('No route to the selected nameserver'); }
    close() {}
  }
  t.mock.method(dgram, 'createSocket', () => new DisconnectedSocket());
  await assert.rejects(new UdpTransport('2001:db8::1').query(query), /No route/);
});
