const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('dnsLocal', {
  query: input => ipcRenderer.invoke('query', input),
  cancel: () => ipcRenderer.invoke('cancel'),
  history: () => ipcRenderer.invoke('history'),
  clearHistory: () => ipcRenderer.invoke('clear-history'),
  export: format => ipcRenderer.invoke('export', format)
});
