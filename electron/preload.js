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

  // Mouse software scanning
  scanMouse: () => ipcRenderer.invoke('scan-mouse'),

  // Browser scanning
  scanBrowsers: () => ipcRenderer.invoke('scan-browsers'),

  // Kernel driver scanning
  scanKernel: () => ipcRenderer.invoke('scan-kernel'),

  // DLL scanning
  scanDLLs: () => ipcRenderer.invoke('scan-dlls'),

  // Memory scanning
  scanMemory: () => ipcRenderer.invoke('scan-memory'),

  // JAR deep scanning
  scanJar: (filePath) => ipcRenderer.invoke('scan-jar', filePath),
  scanJarDirectory: (mcDir) => ipcRenderer.invoke('scan-jar-directory', mcDir),

  // Full auto-scan
  fullScan: () => ipcRenderer.invoke('full-scan'),

  // Dialog helpers
  selectFolder: () => ipcRenderer.invoke('select-folder'),
  selectFile: () => ipcRenderer.invoke('select-file'),

  // Utilities
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  exportReport: (reportData) => ipcRenderer.invoke('export-report', reportData),

  // Event listeners
  onTriggerFullScan: (callback) => ipcRenderer.on('trigger-full-scan', callback),
  onAdminStatus: (callback) => ipcRenderer.on('admin-status', (_event, status) => callback(status))
});
