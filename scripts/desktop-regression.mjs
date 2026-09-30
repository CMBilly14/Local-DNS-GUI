import { _electron as electron } from 'playwright-core';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import packet from 'dns-packet';

const require = createRequire(import.meta.url);
const packaged = process.argv.includes('--packaged');
const executables = {
  win32: 'release/win-unpacked/DNS Local.exe',
  linux: 'release/linux-unpacked/dns-local',
  darwin: 'release/mac/DNS Local.app/Contents/MacOS/DNS Local'
};
const executablePath = process.env.DNS_LOCAL_EXECUTABLE || (packaged ? path.resolve(executables[process.platform]) : require('electron'));
await mkdir('test-output', { recursive: true });
const profile = await mkdtemp(path.resolve('test-output/regression-'));
const checks = [];
let requests = 0;
function respond(wire, tcp = false) {
  const q = packet.decode(wire);
  const { name, type } = q.questions[0];
  requests++;
  if (name === 'timeout.example') return;
  const flags = name === 'missing.example' ? 3 : name === 'recursive.example' ? packet.RECURSION_AVAILABLE : packet.AUTHORITATIVE_ANSWER;
  let answers = ['missing.example', 'empty.example'].includes(name) ? [] : [{ name, type, ttl: 300,
    data: type === 'TXT' ? [Buffer.from('<img src=x onerror="window.dnsInjected=true"> & TXT evidence')] : '192.0.2.42' }];
  if (name === 'spf.example') answers = ['google-site-verification=abc', 'v=spf1 include:example.net -all', 'v=spf10 -all'].map(value => ({ name, type: 'TXT', ttl: 300, data: [Buffer.from(value)] }));
  return packet.encode({ type: 'response', id: q.id, flags: name === 'fallback.example' && !tcp ? packet.TRUNCATED_RESPONSE : flags,
    questions: q.questions, answers,
    authorities: [{ name: 'example', type: 'NS', ttl: 300, data: 'ns.example' }],
    additionals: [{ name: 'ns.example', type: 'A', ttl: 300, data: '192.0.2.53' }] });
}
const tcp = net.createServer(socket => {
  let received = Buffer.alloc(0);
  socket.on('data', data => {
    received = Buffer.concat([received, data]);
    if (received.length < 2 || received.length < received.readUInt16BE(0) + 2) return;
    const response = respond(received.subarray(2), true);
    if (!response) return;
    const frame = Buffer.alloc(response.length + 2); frame.writeUInt16BE(response.length); response.copy(frame, 2); socket.end(frame);
  });
});
await new Promise(resolve => tcp.listen(0, '127.0.0.1', resolve));
const udp = dgram.createSocket('udp4');
await new Promise(resolve => udp.bind(tcp.address().port, '127.0.0.1', resolve));
udp.on('message', (wire, remote) => { const response = respond(wire); if (response) udp.send(response, remote.port, remote.address); });
let app;
let page;
const errors = [];
async function launch() {
  app = await electron.launch({ executablePath, args: [...(packaged || process.env.DNS_LOCAL_EXECUTABLE ? [] : ['.']), '--user-data-dir=' + profile], cwd: process.cwd(), timeout: 30000 });
  app.process().stderr.on('data', data => { if (/UnhandledPromiseRejection/.test(String(data))) errors.push(String(data)); });
  page = await app.firstWindow(); page.setDefaultTimeout(10000); page.on('pageerror', error => errors.push(error.message));
  await page.locator('#name').waitFor();
}
async function ready() { await page.waitForFunction(() => !document.getElementById('run').disabled); }
async function query(name, type = 'A') {
  await page.fill('#name', name); await page.selectOption('#type', type); await page.click('#run'); await ready();
}
try {
  await launch();
  await page.selectOption('#mode', 'custom'); await page.fill('#server', '127.0.0.1'); await page.fill('#port', String(tcp.address().port));
  await page.locator('details').evaluate(node => { node.open = true; });
  await page.locator('[name="timeoutMs"]').fill('200'); await page.locator('[name="retries"]').fill('0');
  await query('success.example');
  assert.match(await page.locator('#content').innerText(), /192\.0\.2\.42/);
  await page.click('[data-tab="authorities"]'); assert.match(await page.locator('#content').innerText(), /ns.example/);
  await page.click('[data-tab="additionals"]'); assert.match(await page.locator('#content').innerText(), /192\.0\.2\.53/);
  checks.push('UDP answer, authority and additional tabs');
  await query('recursive.example'); assert.match(await page.locator('#server-cards').innerText(), /NON-AUTHORITATIVE · AA=0/); checks.push('Recursive response labeling');
  await query('missing.example'); assert.match(await page.locator('#content').innerText(), /NXDOMAIN/);
  await query('empty.example'); assert.match(await page.locator('#content').innerText(), /NOERROR/); assert.match(await page.locator('#content').innerText(), /No records/); checks.push('NXDOMAIN and empty NOERROR responses');
  await query('fallback.example'); assert.match(await page.locator('#server-cards').innerText(), /TCP \(UDP FALLBACK\)/); checks.push('UDP truncation → TCP through the GUI');
  await page.selectOption('[name="protocol"]', 'tcp'); await query('tcp.example'); assert.match(await page.locator('#content').innerText(), /192\.0\.2\.42/); checks.push('TCP-only query');
  await page.selectOption('[name="protocol"]', 'udp'); await query('txt.example', 'TXT');
  assert.match(await page.locator('#content').innerText(), /<img src=x/); assert.equal(await page.locator('#content img').count(), 0); assert.equal(await page.evaluate(() => window.dnsInjected), undefined); checks.push('DNS TXT content displayed as text, never HTML');
  for (const format of ['json', 'text']) {
    await query('txt.example', 'TXT');
    const filePath = path.join(profile, 'report.' + (format === 'text' ? 'txt' : 'json'));
    await app.evaluate(({ dialog }, filePath) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath }); }, filePath);
    await page.click('#export-' + format); await page.waitForFunction(() => document.getElementById('status').textContent === 'Report saved.');
    assert.match(await readFile(filePath, 'utf8'), /txt.example/);
  }
  checks.push('JSON and text exports through the Save action');
  await query('spf.example', 'SPF');
  assert.match(await page.locator('#result-title').innerText(), /· SPF$/);
  assert.equal(await page.locator('#content tbody tr').count(), 1);
  assert.match(await page.locator('#content').innerText(), /v=spf1 include:example.net -all/);
  assert.doesNotMatch(await page.locator('#content').innerText(), /google-site|v=spf10/);
  await page.click('[data-tab="raw"]'); assert.match(await page.locator('#content').innerText(), /wireHex/);
  await query('spf.example', 'TXT'); assert.equal(await page.locator('#content tbody tr').count(), 3);
  await query('txt.example', 'SPF'); assert.match(await page.locator('#content').innerText(), /No SPF records/);
  checks.push('SPF-only results, SPF heading, no-match message, unchanged TXT searches');
  const before = requests; await page.fill('#server', 'not-an-ip'); await query('invalid.example'); assert.match(await page.locator('#status').innerText(), /IPv4 or IPv6/); assert.equal(requests, before); await page.fill('#server', '127.0.0.1'); checks.push('Invalid input rejected without sending a DNS packet');
  await query('timeout.example'); assert.match(await page.locator('#server-cards').innerText(), /timeout/); checks.push('Unresponsive server timeout with usable UI afterward');
  await page.locator('[name="timeoutMs"]').fill('10000'); await page.fill('#name', 'timeout.example'); await page.click('#run'); await page.locator('#cancel').waitFor();
  const cancelledAt = Date.now(); await page.click('#cancel'); await ready(); assert.ok(Date.now() - cancelledAt < 5000); assert.match(await page.locator('#server-cards').innerText(), /cancelled/i); checks.push('Cancel interrupts a pending query');
  await query('restart.example');
  await page.fill('#history-search', 'restart'); assert.equal(await page.locator('.history-item').count(), 1); await page.locator('.history-item').click(); assert.equal(await page.locator('#name').inputValue(), 'restart.example'); checks.push('History search and query recall');
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+l' : 'Control+l'); assert.equal(await page.locator('#name').evaluate(node => node === document.activeElement), true); checks.push('Keyboard focus shortcut');
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(820, 640));
  await page.screenshot({ path: path.join(profile, 'minimum-window.png'), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth), false); checks.push('Minimum window width without page-level horizontal overflow');
  await app.close(); app = undefined; await launch();
  await page.locator('.history-item').first().waitFor(); assert.match(await page.locator('#history').innerText(), /restart.example/); checks.push('History persists across app restart');
  await page.click('#clear'); await page.waitForFunction(() => document.getElementById('history').children.length === 0); checks.push('History clearing');
  assert.deepEqual(errors, []); checks.push('No renderer errors or unhandled main-process rejections');
  await writeFile(path.join(profile, 'results.json'), JSON.stringify({ packaged, platform: process.platform, checks }, null, 2));
  console.log(JSON.stringify({ status: 'passed', packaged, platform: process.platform, checks: checks.length, details: checks, artifacts: profile }, null, 2));
} finally { if (app) await app.close(); udp.close(); tcp.close(); }
