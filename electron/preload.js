const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sstools', {
  // Launcher detection
  detectLaunchers: () => ipcRenderer.invoke('detect-launchers'),

  // Mod scanning
  scanMods: (folderPath) => ipcRenderer.invoke('scan-mods', folderPath),
  scanModFile: (filePath) => ipcRenderer.invoke('scan-mod-file', filePath),

  // Log scanning
  scanLogs: (folderPath) => ipcRenderer.invoke('scan-logs', folderPath),

  // Process scanning
  scanProcesses: () => ipcRenderer.invoke('scan-processes'),

  // Deleted file scanning
  scanDeletedFiles: () => ipcRenderer.invoke('scan-deleted-files'),

  // String/binary scanning
  scanStrings: (dirPath) => ipcRenderer.invoke('scan-strings', dirPath),
  scanBinary: (filePath) => ipcRenderer.invoke('scan-binary', filePath),

  // Full auto-scan
  fullScan: () => ipcRenderer.invoke('full-scan'),

  // Dialog helpers
  selectFolder: () => ipcRenderer.invoke('select-folder'),
  selectFile: () => ipcRenderer.invoke('select-file'),

  // Utilities
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  exportReport: (reportData) => ipcRenderer.invoke('export-report', reportData)
});
