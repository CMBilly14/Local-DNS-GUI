import { _electron as electron } from 'playwright-core';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import dgram from 'node:dgram';
import os from 'node:os';
import path from 'node:path';
import packet from 'dns-packet';

const require = createRequire(import.meta.url);
const output = path.resolve('docs');
await mkdir(output, { recursive: true });
const profile = await mkdtemp(path.join(os.tmpdir(), 'dns-local-screenshots-'));

const udp = dgram.createSocket('udp4');
await new Promise(resolve => udp.bind(0, '127.0.0.1', resolve));
udp.on('message', (wire, remote) => {
  const query = packet.decode(wire);
  const { name, type } = query.questions[0];
  const answers = type === 'TXT'
    ? [
        'google-site-verification=sample-token',
        'v=spf1 include:_spf.example.net -all',
        'verification-token=unrelated'
      ].map(value => ({ name, type: 'TXT', ttl: 300, data: [Buffer.from(value)] }))
    : [{ name, type, ttl: 300, data: '192.0.2.42' }];
  const response = packet.encode({
    type: 'response',
    id: query.id,
    flags: packet.AUTHORITATIVE_ANSWER,
    questions: query.questions,
    answers,
    authorities: [{ name: 'example', type: 'NS', ttl: 300, data: 'ns1.example' }],
    additionals: [{ name: 'ns1.example', type: 'A', ttl: 300, data: '192.0.2.53' }]
  });
  udp.send(response, remote.port, remote.address);
});

let app;
try {
  app = await electron.launch({
    executablePath: require('electron'),
    args: ['.', '--user-data-dir=' + profile],
    cwd: process.cwd(),
    timeout: 30000
  });
  const page = await app.firstWindow();
  await page.locator('#name').waitFor();
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setSize(1320, 900));
  await page.selectOption('#mode', 'custom');
  await page.fill('#server', '127.0.0.1');
  await page.fill('#port', String(udp.address().port));
  await page.fill('#name', 'mail.example');
  await page.selectOption('#type', 'SPF');
  await page.click('#run');
  await page.waitForFunction(() => !document.getElementById('run').disabled);
  await page.screenshot({ path: path.join(output, 'spf-filtering.png') });

  await page.locator('summary').click();
  await page.screenshot({ path: path.join(output, 'protocol-controls.png') });
} finally {
  if (app) await app.close();
  udp.close();
  await rm(profile, { recursive: true, force: true });
}
