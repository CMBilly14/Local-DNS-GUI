import { _electron as electron } from 'playwright-core';
import dgram from 'node:dgram';
import packet from 'dns-packet';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, readFile, copyFile } from 'node:fs/promises';

// Exercise the real Electron bridge and socket engine against a deterministic DNS fixture.
const server = dgram.createSocket('udp4');
await new Promise(resolve => server.bind(0, '127.0.0.1', resolve));
server.on('message', (wire, remote) => {
  const q = packet.decode(wire);
  server.send(packet.encode({ type: 'response', id: q.id, flags: packet.AUTHORITATIVE_ANSWER,
    questions: q.questions, answers: [{ name: q.questions[0].name, type: 'A', ttl: 300, data: '192.0.2.42' }] }), remote.port, remote.address);
});
await mkdir('test-output', { recursive: true });
const packaged = process.argv.includes('--packaged');
const app = await electron.launch({
  executablePath: path.resolve(packaged ? 'release/win-unpacked/DNS Local.exe' : 'node_modules/electron/dist/electron.exe'),
  args: [...(packaged ? [] : ['.']), '--user-data-dir=' + path.resolve('test-output/profile')], cwd: process.cwd()
});
try {
  const page = await app.firstWindow();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.locator('#name').waitFor();
  await page.screenshot({ path: 'test-output/desktop-empty.png', fullPage: true });
  await page.selectOption('#mode', 'custom');
  await page.fill('#server', '127.0.0.1');
  await page.fill('#port', String(server.address().port));
  await page.fill('#name', 'example.com');
  await page.click('#run');
  await page.getByRole('cell', { name: '192.0.2.42', exact: true }).waitFor();
  await page.waitForFunction(() => !document.getElementById('run').disabled);
  assert.match(await page.locator('#server-cards').innerText(), /AUTHORITATIVE · AA=1/);
  assert.match(await page.locator('#history').innerText(), /example.com/);
  await page.screenshot({ path: 'test-output/desktop-answer.png', fullPage: true });
  if (!packaged) {
    await mkdir('docs', { recursive: true });
    await copyFile('test-output/desktop-answer.png', 'docs/desktop.png');
  }
  await page.click('[data-tab="raw"]');
  assert.match(await page.locator('#content').innerText(), /wireHex/);
  const security = await app.evaluate(({ BrowserWindow }) => {
    const preferences = BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();
    return { sandbox: preferences.sandbox, contextIsolation: preferences.contextIsolation, nodeIntegration: preferences.nodeIntegration };
  });
  assert.deepEqual(security, { sandbox: true, contextIsolation: true, nodeIntegration: false });
  assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
  const exportPath = path.resolve('test-output/export.json');
  await app.evaluate(({ dialog }, filePath) => { dialog.showSaveDialog = async () => ({ canceled: false, filePath }); }, exportPath);
  await page.click('#export-json');
  await page.waitForFunction(() => document.getElementById('status').textContent === 'Report saved.');
  assert.equal(JSON.parse(await readFile(exportPath, 'utf8')).results[0].packet.answers[0].data, '192.0.2.42');
  await page.click('#clear');
  await page.waitForFunction(() => document.getElementById('history').children.length === 0);
  assert.deepEqual(errors, []);
  console.log(`Desktop smoke passed (${packaged ? 'packaged' : 'source'}): real IPC + UDP lookup, authoritative badge, history, raw packet, JSON export, clearing, sandbox.`);
} finally { await app.close(); server.close(); }
