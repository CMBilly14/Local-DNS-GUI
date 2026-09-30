import dgram from 'node:dgram';
import net from 'node:net';
import { Buffer } from 'node:buffer';

/** @typedef {import('@dns-search/core/dns/transport').TransportOptions} TransportOptions */
/** @typedef {import('@dns-search/core/dns/transport').DnsTransport} DnsTransport */

function checkResponse(query, response) {
  if (response.length < 12 || response.readUInt16BE(0) !== query.readUInt16BE(0) || !(response[2] & 0x80)) return false;
  return true;
}

/** @implements {DnsTransport} */
export class TcpTransport {
  id = 'tcp';
  label = 'TCP';
  usedTcp = false;
  constructor(server, port = 53) { this.server = server; this.port = port; }
  /** @param {Uint8Array} packet @param {TransportOptions} options */
  query(packet, options = {}) {
    return new Promise((resolve, reject) => {
      const query = Buffer.from(packet);
      const socket = net.createConnection({ host: this.server, port: this.port });
      let received = Buffer.alloc(0);
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', abort);
        socket.destroy();
        if (error) reject(error); else resolve(value);
      };
      const abort = () => finish(new Error('Query cancelled'));
      const timer = setTimeout(() => finish(new Error(`TCP timeout: ${this.server}:${this.port}`)), options.timeoutMs ?? 3000);
      options.signal?.addEventListener('abort', abort, { once: true });
      socket.on('error', error => finish(error));
      socket.on('end', () => finish(new Error('DNS server closed an incomplete TCP response')));
      socket.on('connect', () => {
        const prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(query.length);
        socket.write(Buffer.concat([prefix, query]));
      });
      socket.on('data', chunk => {
        received = Buffer.concat([received, chunk]);
        if (received.length < 2) return;
        const size = received.readUInt16BE(0);
        if (size < 12) { finish(new Error('Invalid DNS TCP frame')); return; }
        if (received.length >= size + 2) {
          const response = received.subarray(2, size + 2);
          if (!checkResponse(query, response)) finish(new Error('Mismatched DNS TCP response'));
          else finish(null, response);
        }
      });
      if (options.signal?.aborted) abort();
    });
  }
}

/** @implements {DnsTransport} */
export class UdpTransport {
  id = 'udp';
  label = 'UDP';
  constructor(server, port = 53) { this.server = server; this.port = port; this.usedTcp = false; }
  /** @param {Uint8Array} packet @param {TransportOptions} options */
  async query(packet, options = {}) {
    const query = Buffer.from(packet);
    const response = await new Promise((resolve, reject) => {
      const socket = dgram.createSocket(net.isIP(this.server) === 6 ? 'udp6' : 'udp4');
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', abort);
        socket.close();
        if (error) reject(error); else resolve(value);
      };
      const abort = () => finish(new Error('Query cancelled'));
      const timer = setTimeout(() => finish(new Error(`UDP timeout: ${this.server}:${this.port}`)), options.timeoutMs ?? 3000);
      socket.on('error', error => finish(error));
      // A connected UDP socket filters packets to the selected peer and port.
      socket.on('message', message => { if (checkResponse(query, message)) finish(null, message); });
      socket.connect(this.port, this.server, () => {
        if (settled) return;
        // Failed IPv6 routes can leave a connecting socket disconnected before this callback.
        try { socket.send(query, error => { if (error) finish(error); }); }
        catch (error) { finish(error); }
      });
      options.signal?.addEventListener('abort', abort, { once: true });
      if (options.signal?.aborted) abort();
    });
    if (response[2] & 0x02) {
      this.usedTcp = true;
      return new TcpTransport(this.server, this.port).query(packet, options);
    }
    return response;
  }
}
