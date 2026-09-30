import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export function createHistory(file) {
  let queue = Promise.resolve();
  async function read() {
    try {
      const data = JSON.parse(await readFile(file, 'utf8'));
      if (!Array.isArray(data)) throw new Error('Invalid history format');
      return data.slice(0, 200);
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw new Error('Could not read local history. Clear it to start fresh.');
    }
  }
  function update(transform) {
    const next = queue.catch(() => {}).then(async () => {
      const rows = await transform();
      await mkdir(dirname(file), { recursive: true });
      await writeFile(file + '.tmp', JSON.stringify(rows, null, 2), { mode: 0o600 });
      await rename(file + '.tmp', file);
      return rows;
    });
    queue = next;
    return next;
  }
  return {
    read: async () => { await queue.catch(() => {}); return read(); },
    add: report => update(async () => [{ request: report.request, createdAt: report.createdAt }, ...await read()].slice(0, 200)),
    clear: () => update(async () => [])
  };
}
