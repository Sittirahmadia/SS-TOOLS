/**
 * SS-TOOLS v2.0 -- Web/Native Mode API Bridge
 * Replaces Electron IPC with HTTP fetch calls to server.js
 * This file is loaded by web.html for native (non-Electron) mode.
 */

const API_BASE = window.location.origin;

async function apiCall(endpoint, body = {}) {
  const res = await fetch(`${API_BASE}/api/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

// Expose the same API as Electron preload
window.sstools = {
  detectLaunchers: () => apiCall('detect-launchers'),
  scanMods: (folderPath) => apiCall('scan-mods', { path: folderPath }),
  scanModFile: (filePath) => apiCall('scan-mod-file', { path: filePath }),
  scanLogs: (folderPath) => apiCall('scan-logs', { path: folderPath }),
  scanProcesses: () => apiCall('scan-processes'),
  scanDeletedFiles: () => apiCall('scan-deleted-files'),
  scanStrings: (dirPath) => apiCall('scan-strings', { path: dirPath }),
  scanBinary: (filePath) => apiCall('scan-binary', { path: filePath }),
  scanMouse: () => apiCall('scan-mouse'),
  scanBrowsers: () => apiCall('scan-browsers'),
  scanKernel: () => apiCall('scan-kernel'),
  scanDLLs: () => apiCall('scan-dlls'),
  scanMemory: () => apiCall('scan-memory'),
  scanJar: (filePath) => apiCall('scan-jar', { path: filePath }),
  scanJarDirectory: (mcDir) => apiCall('scan-jar-directory', { path: mcDir }),
  fullScan: () => apiCall('full-scan'),
  exportReport: async (reportData) => {
    const result = await apiCall('export-report', reportData);
    if (result.success && result.data && result.data.html) {
      // Open report in new tab
      const blob = new Blob([result.data.html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      return true;
    }
    return false;
  },

  // In web mode, folder/file selection uses prompt
  selectFolder: async () => {
    return prompt('Enter folder path to scan:');
  },
  selectFile: async () => {
    return prompt('Enter file path to scan:');
  },

  // No-op event listeners for web mode
  onTriggerFullScan: () => {},
  onAdminStatus: () => {}
};
