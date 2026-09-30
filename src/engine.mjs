import { randomInt } from 'node:crypto';
import { getServers } from 'node:dns';
import { isIP } from 'node:net';
import { Buffer } from 'node:buffer';
import packet from 'dns-packet';
import { prepareQuery, parseDnsAnswers } from '@dns-search/core/dns/lookup';
import { recordTypeOptions, resolverCatalog } from '@dns-search/core/dns/types';
import { isTargetAllowed } from '@dns-search/core/dns/validators';
import { UdpTransport, TcpTransport } from './transports.mjs';

export const ROOTS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13'];
export const PUBLIC = Object.values(resolverCatalog).filter(r => r.id !== 'auto');
const canonical = name => String(name).toLowerCase().replace(/\.$/, '');
const beneath = (name, zone) => !zone || name === zone || name.endsWith('.' + zone);

export function validateRequest(input) {
  if (!input || typeof input !== 'object') throw new Error('Invalid query');
  const name = String(input.name ?? '').trim();
  if (!isTargetAllowed(name) && name !== '.') throw new Error('Enter a DNS name or an IP address for PTR');
  const recordOption = recordTypeOptions.find(r => r.value === String(input.type ?? 'A'));
  if (!recordOption) throw new Error('Unsupported record type');
  const type = recordOption.value;
  if (isIP(name) && type !== 'PTR') throw new Error('Use PTR for an IP address, or enter a DNS name');
  const mode = String(input.mode ?? 'system');
  if (!['system', 'public', 'custom', 'authoritative', 'trace', 'compare'].includes(mode)) throw new Error('Invalid mode');
  const protocol = String(input.protocol ?? 'udp');
  if (!['udp', 'tcp'].includes(protocol)) throw new Error('Invalid transport');
  const number = (key, fallback, min, max) => {
    const n = Number(input[key] ?? fallback);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${key} must be ${min}–${max}`);
    return n;
  };
  const server = String(input.server ?? '1.1.1.1');
  if (mode === 'custom' && !isIP(server)) throw new Error('Custom nameserver must be an IPv4 or IPv6 address');
  const resolver = String(input.resolver ?? 'cloudflare');
  if (!PUBLIC.some(r => r.id === resolver)) throw new Error('Invalid public resolver');
  const selector = String(input.selector ?? '').trim();
  if (selector && !/^[a-zA-Z0-9_-]{1,63}$/.test(selector)) throw new Error('Invalid DKIM selector');
  if (type === 'DKIM' && !selector && !name.includes('._domainkey.')) throw new Error('Supply a DKIM selector or a full selector._domainkey name');
  const bool = (key, fallback) => {
    if (input[key] !== undefined && typeof input[key] !== 'boolean') throw new Error(`Invalid ${key} flag`);
    return input[key] ?? fallback;
  };
  return { name, type, mode, protocol, server, resolver, selector,
    port: number('port', 53, 1, 65535), timeoutMs: number('timeoutMs', 2500, 100, 10000),
    retries: number('retries', 1, 0, 3), edns: number('edns', 1232, 512, 4096),
    rd: bool('rd', true), cd: bool('cd', false), do: bool('do', false) };
}

export async function queryServer(name, type, server, options, signal) {
  let error;
  for (let attempt = 0; attempt <= options.retries; attempt++) {
    if (signal?.aborted) throw new Error('Query cancelled or overall time limit reached');
    try {
      const transport = options.protocol === 'tcp' ? new TcpTransport(server, options.port) : new UdpTransport(server, options.port);
      const query = packet.encode({ type: 'query', id: randomInt(65536),
        flags: (options.rd ? packet.RECURSION_DESIRED : 0) | (options.cd ? packet.CHECKING_DISABLED : 0),
        questions: [{ name, type, class: 'IN' }],
        additionals: [{ type: 'OPT', name: '.', udpPayloadSize: options.edns, flags: options.do ? 0x8000 : 0, options: [] }] });
      const started = performance.now();
      const wire = await transport.query(query, { timeoutMs: options.timeoutMs, signal });
      const decoded = packet.decode(Buffer.from(wire));
      const question = decoded.questions?.[0];
      if (decoded.questions?.length !== 1 || canonical(question.name) !== canonical(name) || question.type !== type || question.class !== 'IN') throw new Error('DNS response question does not match the query');
      return { server, port: options.port, name, type, protocol: transport.usedTcp ? 'tcp (UDP fallback)' : transport.id,
        rd: options.rd, elapsedMs: Math.round(performance.now() - started), attempt: attempt + 1,
        authoritative: Boolean(decoded.flag_aa), packet: decoded,
        wireHex: Buffer.from(wire).toString('hex') };
    } catch (caught) { error = caught; }
  }
  throw error;
}

/** Iterative resolution. Bootstrap address lookups also walk from roots; no hidden public resolver. */
export async function walk(name, type, options, context, depth = 0) {
  const steps = [];
  let servers = context.roots ?? ROOTS;
  let zone = '';
  const seen = new Set();
  const ask = context.query ?? queryServer;
  if (depth > 5) return { steps, error: 'Nameserver address dependency depth exceeded' };
  for (let hop = 0; hop < 32; hop++) {
    let result;
    for (const server of servers) {
      if (++context.queries > 100 || context.signal?.aborted) return { steps, error: 'Trace query budget or time limit reached' };
      try {
        const answer = await ask(name, type, server, { ...options, port: 53, rd: false }, context.signal);
        steps.push({ zone: zone || '.', ...answer });
        if (['SERVFAIL', 'REFUSED', 'FORMERR'].includes(answer.packet.rcode)) continue;
        result = answer;
        break;
      } catch (error) { steps.push({ zone: zone || '.', server, error: error.message }); }
    }
    if (!result) return { steps, error: `No usable response at ${zone || 'root'}` };
    if (result.authoritative) return { steps, result, servers, zone: zone || '.' };
    if (result.packet.rcode !== 'NOERROR') return { steps, error: `Non-authoritative ${result.packet.rcode} at ${zone || 'root'}` };
    const referrals = (result.packet.authorities ?? []).filter(r => r.type === 'NS' && beneath(canonical(name), canonical(r.name)));
    referrals.sort((a, b) => canonical(b.name).length - canonical(a.name).length);
    const nextZone = referrals[0] && canonical(referrals[0].name);
    if (!nextZone || nextZone === zone || !beneath(nextZone, zone) || seen.has(nextZone)) return { steps, error: `No advancing referral or authoritative answer at ${zone || 'root'}` };
    seen.add(nextZone);
    const names = [...new Set(referrals.filter(r => canonical(r.name) === nextZone).map(r => canonical(r.data)))];
    const addresses = [];
    for (const ns of names) {
      // Bailiwick is the responding parent zone, not the child. Root referrals
      // legitimately carry com's glue under gtld-servers.net (a sibling TLD).
      const glue = (result.packet.additionals ?? []).filter(r => ['A', 'AAAA'].includes(r.type) && canonical(r.name) === ns && beneath(ns, zone) && isIP(r.data));
      addresses.push(...glue.map(r => r.data));
    }
    if (!addresses.length) {
      for (const ns of names.slice(0, 4)) {
        for (const addressType of ['A', 'AAAA']) {
          const lookup = await walk(ns, addressType, options, context, depth + 1);
          steps.push(...lookup.steps.map(step => ({ ...step, purpose: `Address of ${ns}` })));
          addresses.push(...(lookup.result?.packet.answers ?? []).filter(r => r.type === addressType && canonical(r.name) === ns && isIP(r.data)).map(r => r.data));
          if (addresses.length) break;
        }
        if (addresses.length) break;
      }
    }
    if (!addresses.length) return { steps, error: `Could not resolve nameserver addresses for ${nextZone}` };
    servers = [...new Set(addresses)];
    zone = nextZone;
  }
  return { steps, error: 'Delegation hop limit reached' };
}

function normalizedData(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('hex');
  if (Array.isArray(value)) return value.map(normalizedData);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, normalizedData(value[key])]));
  return value;
}

export function selectAnswerRecords(records, requestedType) {
  if (requestedType !== 'SPF') return records;
  const { postFilter } = prepareQuery('.', 'SPF');
  return records.filter(record => record.type === 'TXT' && parseDnsAnswers({ answers: [record] }, 'TXT').some(postFilter));
}

export function fingerprint(result, requestedType = result.type) {
  const records = selectAnswerRecords(result.packet.answers ?? [], requestedType).filter(r => r.type === result.type && canonical(r.name) === canonical(result.name));
  const cname = (result.packet.answers ?? []).find(r => r.type === 'CNAME' && canonical(r.name) === canonical(result.name));
  // Compare a CNAME at the queried name, not recursion's extra target records.
  const chosen = cname && result.type !== 'CNAME' && requestedType !== 'SPF' ? [cname] : records;
  const normalizeRecord = r => {
    let data = normalizedData(r.data);
    if (['NS', 'CNAME', 'PTR'].includes(r.type)) data = canonical(data);
    if (r.type === 'MX') data.exchange = canonical(data.exchange);
    if (r.type === 'SRV') data.target = canonical(data.target);
    if (r.type === 'TXT') data = (r.data ?? []).map(v => Buffer.from(v).toString('hex')).join('');
    return JSON.stringify({ name: canonical(r.name), type: r.type, data });
  };
  return JSON.stringify({ rcode: result.packet.rcode, records: [...new Set(chosen.map(normalizeRecord))].sort() });
}

export function digCommand(result, request) {
  return `dig @${result.server} -p ${result.port} ${result.name || '.'} ${result.type} ${result.protocol.startsWith('tcp') ? '+tcp' : '+notcp'} ${result.rd ? '+recurse' : '+norecurse'} ${request.cd ? '+cdflag' : '+nocdflag'} ${request.do ? '+dnssec' : '+nodnssec'} +bufsize=${request.edns} +time=${Math.ceil(request.timeoutMs / 1000)} +tries=${request.retries + 1}`;
}

export async function runQuery(input, cancelSignal) {
  const request = validateRequest(input);
  const prepared = prepareQuery(request.name, request.type, request.selector);
  const name = prepared.queryName || '.';
  const type = prepared.underlyingType;
  const timeout = AbortSignal.timeout(60000);
  const signal = cancelSignal ? AbortSignal.any([timeout, cancelSignal]) : timeout;
  const report = { request, name, type, createdAt: new Date().toISOString(), results: [], trace: [], error: undefined };
  if (['authoritative', 'trace', 'compare'].includes(request.mode)) {
    const walked = await walk(name, type, request, { queries: 0, signal });
    report.trace = walked.steps;
    report.error = walked.error;
    if (walked.result) report.results.push({ ...walked.result, label: `Authority · ${walked.zone}` });
  }
  let targets = [];
  if (request.mode === 'system') targets = getServers().map(server => {
    const ipv6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(server);
    if (ipv6) return { server: ipv6[1], port: Number(ipv6[2] ?? 53), label: 'System resolver' };
    const ipv4 = /^(\d+\.\d+\.\d+\.\d+):(\d+)$/.exec(server);
    return { server: ipv4?.[1] ?? server, port: Number(ipv4?.[2] ?? 53), label: 'System resolver' };
  });
  if (request.mode === 'custom') targets = [{ server: request.server, port: request.port, label: 'Custom nameserver' }];
  if (request.mode === 'public') targets = [{ server: PUBLIC.find(r => r.id === request.resolver).servers[0], port: 53, label: PUBLIC.find(r => r.id === request.resolver).label }];
  if (request.mode === 'compare') targets = PUBLIC.map(r => ({ server: r.servers[0], port: 53, label: r.label }));
  if (request.mode === 'system' && !targets.length) report.error = 'No system DNS servers configured';
  for (const target of targets) {
    try {
      const result = await queryServer(name, type, target.server, { ...request, port: target.port, rd: request.mode === 'compare' ? true : request.rd }, signal);
      report.results.push({ ...result, label: target.label });
      if (request.mode === 'system' && !['SERVFAIL', 'REFUSED', 'FORMERR'].includes(result.packet.rcode)) break;
    } catch (error) { report.results.push({ ...target, error: error.message }); }
  }
  const authority = report.results.find(r => r.authoritative);
  for (const result of report.results) {
    if (!result.packet) continue;
    result.dig = digCommand(result, request);
    // Keep the complete packet as evidence; use selected records in result views.
    result.answerRecords = selectAnswerRecords(result.packet.answers ?? [], request.type);
    result.answers = result.answerRecords.flatMap(record => parseDnsAnswers({ answers: [record] }, record.type));
    if (request.mode === 'compare' && result !== authority) {
      result.comparison = !authority ? 'Authority unavailable' : fingerprint(result, request.type) === fingerprint(authority, request.type) ? 'Matches authority' : 'Differs from authority';
    }
  }
  return report;
}
