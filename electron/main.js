/**
 * SS-TOOLS v2.0 -- Minecraft SS AntiCheat Scanner
 * Electron Main Process
 */

const { app, BrowserWindow, ipcMain, dialog, shell, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const modScanner = require('../scanners/mod-scanner');
const logScanner = require('../scanners/log-scanner');
const processScanner = require('../scanners/process-scanner');
const deletedFileScanner = require('../scanners/deleted-file-scanner');
const launcherDetector = require('../scanners/launcher-detector');
const stringScanner = require('../scanners/string-scanner');
const mouseScanner = require('../scanners/mouse-scanner');
const browserScanner = require('../scanners/browser-scanner');
const kernelScanner = require('../scanners/kernel-scanner');
const dllScanner = require('../scanners/dll-scanner');
const jarScanner = require('../scanners/jar-scanner');
const reportGenerator = require('../scanners/report-generator');

let mainWindow;
let tray = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    title: 'SS-TOOLS v2.0 -- Minecraft SS AntiCheat Scanner',
    icon: path.join(__dirname, '..', 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    autoHideMenuBar: true,
    backgroundColor: '#0a0a0f',
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // Minimize to tray instead of closing
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  try {
    const iconPath = path.join(__dirname, '..', 'assets', 'icon.ico');
    let trayIcon;
    if (fs.existsSync(iconPath)) {
      trayIcon = nativeImage.createFromPath(iconPath);
    } else {
      // Create a simple 16x16 icon if no icon file exists
      trayIcon = nativeImage.createEmpty();
    }

    tray = new Tray(trayIcon);
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Show SS-TOOLS',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        }
      },
      {
        label: 'Quick Full Scan',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.webContents.send('trigger-full-scan');
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          app.isQuitting = true;
          app.quit();
        }
      }
    ]);

    tray.setToolTip('SS-TOOLS - Minecraft AntiCheat Scanner');
    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
  } catch (err) {
    console.error('Failed to create tray:', err.message);
  }
}

// Request admin privileges on Windows
function requestAdminPrivileges() {
  if (process.platform === 'win32') {
    try {
      const { execSync } = require('child_process');
      execSync('net session', { windowsHide: true });
      return true; // Already admin
    } catch (err) {
      // Not admin - the app will still work but some features require elevation
      return false;
    }
  }
  return false;
}

app.whenReady().then(() => {
  const isAdmin = requestAdminPrivileges();
  createWindow();
  createTray();

  // Send admin status to renderer
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('admin-status', isAdmin);
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.isQuitting = true;
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
});

// ============================================================
// IPC Handlers
// ============================================================

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

// ── New Scanner Handlers ──

// Mouse software scanner
ipcMain.handle('scan-mouse', async () => {
  try {
    const results = mouseScanner.scanMouseSoftware();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Browser scanner
ipcMain.handle('scan-browsers', async () => {
  try {
    const results = browserScanner.scanBrowsers();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Kernel driver scanner
ipcMain.handle('scan-kernel', async () => {
  try {
    const results = kernelScanner.scanKernel();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// DLL scanner
ipcMain.handle('scan-dlls', async () => {
  try {
    const results = dllScanner.scanDLLs();
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// JAR deep scanner
ipcMain.handle('scan-jar', async (_event, filePath) => {
  try {
    const results = jarScanner.deepScanJar(filePath);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// JAR deep scan entire .minecraft directory
ipcMain.handle('scan-jar-directory', async (_event, mcDir) => {
  try {
    const results = jarScanner.deepScanMinecraftDirectory(mcDir);
    return { success: true, data: results };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ── Full Auto Scan (Enhanced) ──

ipcMain.handle('full-scan', async () => {
  const results = {
    startTime: new Date().toISOString(),
    launchers: [],
    modScans: [],
    logScans: [],
    jarScans: [],
    processScans: null,
    dllScans: null,
    deletedFileScans: null,
    mouseScans: null,
    browserScans: null,
    kernelScans: null,
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

    // Step 4: Deep JAR scan on all launcher directories
    for (const launcher of results.launchers) {
      try {
        const jarResult = jarScanner.deepScanMinecraftDirectory(launcher.path);
        results.jarScans.push(jarResult);
        results.totalDetections += jarResult.detectedJars;
      } catch (err) {
        // JAR scan failed for this launcher
      }
    }

    // Step 5: Scan processes
    results.processScans = processScanner.scanProcesses();
    results.totalDetections += (results.processScans.detections || []).length;

    // Step 6: Scan DLLs
    try {
      results.dllScans = dllScanner.scanDLLs();
      results.totalDetections += results.dllScans.totalDetections;
    } catch (err) {
      results.dllScans = { error: err.message, totalDetections: 0 };
    }

    // Step 7: Scan deleted files
    results.deletedFileScans = deletedFileScanner.scanAllDeletedFiles();
    results.totalDetections += results.deletedFileScans.totalDetections;

    // Step 8: Scan mouse software
    try {
      results.mouseScans = mouseScanner.scanMouseSoftware();
      results.totalDetections += results.mouseScans.totalDetections;
    } catch (err) {
      results.mouseScans = { error: err.message, totalDetections: 0 };
    }

    // Step 9: Scan browsers
    try {
      results.browserScans = browserScanner.scanBrowsers();
      results.totalDetections += results.browserScans.totalDetections;
    } catch (err) {
      results.browserScans = { error: err.message, totalDetections: 0 };
    }

    // Step 10: Kernel driver scan
    try {
      results.kernelScans = kernelScanner.scanKernel();
      results.totalDetections += results.kernelScans.totalDetections;
    } catch (err) {
      results.kernelScans = { error: err.message, totalDetections: 0 };
    }

    results.endTime = new Date().toISOString();

    if (results.totalDetections > 0) {
      results.overallStatus = 'detected';
    }
  } catch (err) {
    results.error = err.message;
  }

  return { success: true, data: results };
});

// ── Dialog Handlers ──

ipcMain.handle('select-folder', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Mods or Minecraft Folder'
  });
  if (result.canceled) return null;
  return result.filePaths[0];
});

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

ipcMain.handle('open-external', async (_event, url) => {
  shell.openExternal(url);
});

// ── Report Export ──

ipcMain.handle('export-report', async (_event, reportData) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Export Scan Report',
    defaultPath: `SS-TOOLS-Report-${Date.now()}`,
    filters: [
      { name: 'HTML Report', extensions: ['html'] },
      { name: 'JSON Report', extensions: ['json'] },
      { name: 'Text Report', extensions: ['txt'] }
    ]
  });

  if (result.canceled) return false;

  const ext = path.extname(result.filePath).toLowerCase();

  try {
    if (ext === '.html') {
      const htmlContent = reportGenerator.generateHTMLReport(reportData);
      fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
    } else if (ext === '.txt') {
      const textContent = reportGenerator.generateTextReport(reportData);
      fs.writeFileSync(result.filePath, textContent, 'utf-8');
    } else {
      fs.writeFileSync(result.filePath, JSON.stringify(reportData, null, 2), 'utf-8');
    }
    return true;
  } catch (err) {
    return false;
  }
});
