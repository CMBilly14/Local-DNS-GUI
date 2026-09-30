import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHistory } from '../src/history.mjs';
test('history serializes concurrent writes, survives restart and clears', async t => {
  const dir = await mkdtemp(path.join(tmpdir(), 'dns-local-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'history.json'); const history = createHistory(file);
  await Promise.all([1, 2, 3].map(n => history.add({ request: { name: `${n}.example` }, createdAt: '2026-09-21' })));
  assert.equal((await createHistory(file).read()).length, 3);
  await history.clear(); assert.deepEqual(await history.read(), []);
  await writeFile(file, 'corrupt'); await assert.rejects(history.read(), /Could not read/);
  await history.clear(); assert.deepEqual(await history.read(), []);
});
