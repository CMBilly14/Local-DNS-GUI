const { app, BrowserWindow, ipcMain, dialog, session } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs/promises');

let window;
let active;
let lastReport;
const page = pathToFileURL(path.join(__dirname, 'ui/index.html')).href;
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');

function trusted(event) {
  if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url !== page) throw new Error('Untrusted IPC sender');
}

app.whenReady().then(async () => {
  const { runQuery } = await import('./engine.mjs');
  const { createHistory } = await import('./history.mjs');
  const history = createHistory(path.join(app.getPath('userData'), 'history.json'));
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*', 'ws://*/*', 'wss://*/*'] }, (_details, callback) => callback({ cancel: true }));
  ipcMain.handle('query', async (event, input) => {
    trusted(event);
    if (active) throw new Error('A query is already running');
    active = new AbortController();
    try {
      const report = await runQuery(input, active.signal);
      lastReport = report;
      try { await history.add(report); } catch (error) { report.historyWarning = error.message; }
      // Convert Buffers into plain structured-clone-safe data for inspection.
      return JSON.parse(JSON.stringify(report));
    } finally { active = undefined; }
  });
  ipcMain.handle('cancel', event => { trusted(event); active?.abort(); });
  ipcMain.handle('history', event => { trusted(event); return history.read(); });
  ipcMain.handle('clear-history', event => { trusted(event); return history.clear(); });
  ipcMain.handle('export', async (event, format) => {
    trusted(event);
    if (!lastReport || !['json', 'txt'].includes(format)) throw new Error('No report to export');
    const report = lastReport;
    const selected = await dialog.showSaveDialog(window, { defaultPath: `dns-${report.name.replace(/[^a-z0-9.-]/gi, '_')}.${format}`, filters: [{ name: format.toUpperCase(), extensions: [format] }] });
    if (selected.canceled || !selected.filePath) return false;
    const text = format === 'json' ? JSON.stringify(report, null, 2) : [
      `DNS Local · ${report.name} ${report.request.type} · ${report.createdAt}`, report.error ?? '',
      ...report.results.map(result => result.error ? `${result.label} ${result.server}: ${result.error}` : [
        `${result.label} ${result.server}:${result.port} · ${result.authoritative ? 'AA flag set (authoritative)' : 'Non-authoritative / recursive'} · ${result.packet.rcode}`,
        result.dig, JSON.stringify(result.packet, null, 2)
      ].join('\n')),
      'Trace', JSON.stringify(report.trace, null, 2)
    ].join('\n\n');
    await fs.writeFile(selected.filePath, text);
    return true;
  });
  function openWindow() {
    window = new BrowserWindow({ width: 1320, height: 900, minWidth: 820, minHeight: 640, backgroundColor: '#101820',
      title: 'DNS Local', autoHideMenuBar: true,
      webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: false } });
    window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    window.webContents.on('will-navigate', event => event.preventDefault());
    window.on('closed', () => { active?.abort(); window = undefined; });
    window.loadFile(path.join(__dirname, 'ui/index.html'));
  }
  openWindow();
  app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) openWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
