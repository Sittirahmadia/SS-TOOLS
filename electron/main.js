const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const modScanner = require('../scanners/mod-scanner');
const logScanner = require('../scanners/log-scanner');
const processScanner = require('../scanners/process-scanner');
const deletedFileScanner = require('../scanners/deleted-file-scanner');
const launcherDetector = require('../scanners/launcher-detector');
const stringScanner = require('../scanners/string-scanner');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'SS-TOOLS — Minecraft Cheat Detector',
    icon: path.join(__dirname, '..', 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    autoHideMenuBar: true,
    backgroundColor: '#0a0a0f'
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ── IPC Handlers ──

// Detect installed launchers
ipcMain.handle('detect-launchers', async () => {
  try {
    return { success: true, data: launcherDetector.detectLaunchers() };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan mods folder
ipcMain.handle('scan-mods', async (_event, folderPath) => {
  try {
    const results = modScanner.scanModsFolder(folderPath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan a single mod file
ipcMain.handle('scan-mod-file', async (_event, filePath) => {
  try {
    const results = modScanner.scanModFile(filePath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan logs folder
ipcMain.handle('scan-logs', async (_event, folderPath) => {
  try {
    const results = logScanner.scanLogsFolder(folderPath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan running processes
ipcMain.handle('scan-processes', async () => {
  try {
    const results = processScanner.scanProcesses();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan deleted files
ipcMain.handle('scan-deleted-files', async () => {
  try {
    const results = deletedFileScanner.scanAllDeletedFiles();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// String scan a directory
ipcMain.handle('scan-strings', async (_event, dirPath) => {
  try {
    const results = stringScanner.scanDirectory(dirPath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Scan a binary file
ipcMain.handle('scan-binary', async (_event, filePath) => {
  try {
    const results = stringScanner.scanBinaryFile(filePath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Full auto-scan: detect launchers then scan everything
ipcMain.handle('full-scan', async () => {
  const results = {
    startTime: new Date().toISOString(),
    launchers: [],
    modScans: [],
    logScans: [],
    processScans: null,
    deletedFileScans: null,
    overallStatus: 'clean',
    totalDetections: 0
  };

  try {
    // Step 1: Detect launchers
    results.launchers = launcherDetector.detectLaunchers();

    // Step 2: Scan all mods folders
    for (const launcher of results.launchers) {
      for (const modsLoc of launcher.modsLocations) {
        const modResult = modScanner.scanModsFolder(modsLoc.path);
        modResult.launcher = launcher.name;
        modResult.version = modsLoc.version;
        results.modScans.push(modResult);
        results.totalDetections += modResult.detectedFiles;
      }
    }

    // Step 3: Scan all logs folders
    for (const launcher of results.launchers) {
      for (const logsLoc of launcher.logsLocations) {
        const logResult = logScanner.scanLogsFolder(logsLoc.path);
        logResult.launcher = launcher.name;
        logResult.version = logsLoc.version;
        results.logScans.push(logResult);
        results.totalDetections += logResult.detectedFiles;
      }
    }

    // Step 4: Scan processes
    results.processScans = processScanner.scanProcesses();
    results.totalDetections += (results.processScans.detections || []).length;

    // Step 5: Scan deleted files
    results.deletedFileScans = deletedFileScanner.scanAllDeletedFiles();
    results.totalDetections += results.deletedFileScans.totalDetections;

    results.endTime = new Date().toISOString();

    if (results.totalDetections > 0) {
      results.overallStatus = 'detected';
    }
  } catch (err) {
    results.error = err.message;
  }

  return { success: true, data: results };
});

// Open folder dialog
ipcMain.handle('select-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Mods or Minecraft Folder'
  });
  if (result.canceled) return null;
  return result.filePaths[0];
});

// Open file dialog
ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    title: 'Select File to Scan',
    filters: [
      { name: 'All Files', extensions: ['*'] },
      { name: 'Mod Files', extensions: ['jar', 'zip', 'litemod'] },
      { name: 'Executables', extensions: ['exe', 'dll'] }
    ]
  });
  if (result.canceled) return null;
  return result.filePaths[0];
});

// Open external link
ipcMain.handle('open-external', async (_event, url) => {
  shell.openExternal(url);
});

// Export report
ipcMain.handle('export-report', async (_event, reportData) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Scan Report',
    defaultPath: `SS-TOOLS-Report-${Date.now()}.json`,
    filters: [
      { name: 'JSON Report', extensions: ['json'] },
      { name: 'Text Report', extensions: ['txt'] }
    ]
  });

  if (result.canceled) return false;

  const ext = path.extname(result.filePath).toLowerCase();
  if (ext === '.txt') {
    fs.writeFileSync(result.filePath, formatReportAsText(reportData), 'utf-8');
  } else {
    fs.writeFileSync(result.filePath, JSON.stringify(reportData, null, 2), 'utf-8');
  }

  return true;
});

/**
 * Format report data as readable text
 */
function formatReportAsText(report) {
  let text = '═══════════════════════════════════════════════\n';
  text += '          SS-TOOLS SCAN REPORT\n';
  text += '═══════════════════════════════════════════════\n\n';
  text += `Scan Time: ${report.startTime || new Date().toISOString()}\n`;
  text += `Status: ${(report.overallStatus || 'unknown').toUpperCase()}\n`;
  text += `Total Detections: ${report.totalDetections || 0}\n\n`;

  if (report.launchers && report.launchers.length > 0) {
    text += '── Detected Launchers ──\n';
    for (const launcher of report.launchers) {
      text += `  • ${launcher.name} (${launcher.path})\n`;
      text += `    Versions: ${launcher.versions.length}\n`;
      text += `    Mods folders: ${launcher.modsLocations.length}\n`;
    }
    text += '\n';
  }

  if (report.modScans) {
    text += '── Mod Scan Results ──\n';
    for (const scan of report.modScans) {
      text += `  [${scan.launcher}] ${scan.folder}\n`;
      text += `    Files: ${scan.totalFiles} | Scanned: ${scan.scannedFiles} | Detected: ${scan.detectedFiles}\n`;
      for (const file of (scan.files || [])) {
        if (file.status === 'detected') {
          text += `    ⚠ ${file.file}\n`;
          for (const det of file.detections) {
            for (const match of (det.matches || [])) {
              text += `      → ${match.keyword} (${match.category}, ${match.severity})\n`;
            }
          }
        }
      }
    }
    text += '\n';
  }

  if (report.processScans && report.processScans.detections) {
    text += '── Process Scan Results ──\n';
    for (const det of report.processScans.detections) {
      text += `  ⚠ ${det.processName || det.description} (PID: ${det.pid || 'N/A'})\n`;
      text += `    ${det.description} — Severity: ${det.severity}\n`;
    }
    text += '\n';
  }

  if (report.deletedFileScans && report.deletedFileScans.sources) {
    text += '── Deleted File Scan Results ──\n';
    for (const source of report.deletedFileScans.sources) {
      text += `  [${source.source}] Status: ${source.status}\n`;
      for (const det of (source.detections || [])) {
        text += `    ⚠ ${det.name || det.record || 'Unknown'}\n`;
      }
    }
    text += '\n';
  }

  text += '═══════════════════════════════════════════════\n';
  text += '         Generated by SS-TOOLS\n';
  text += '═══════════════════════════════════════════════\n';

  return text;
}
