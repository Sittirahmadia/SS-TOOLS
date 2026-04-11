/**
 * SS-TOOLS v2.0 -- Native Node.js Server Mode
 * Runs the scanner as a local web app without Electron (smaller size).
 * Usage: node server.js
 * Then open http://localhost:3847 in your browser.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

// Import all scanners
const modScanner = require('./scanners/mod-scanner');
const logScanner = require('./scanners/log-scanner');
const processScanner = require('./scanners/process-scanner');
const deletedFileScanner = require('./scanners/deleted-file-scanner');
const launcherDetector = require('./scanners/launcher-detector');
const stringScanner = require('./scanners/string-scanner');
const mouseScanner = require('./scanners/mouse-scanner');
const browserScanner = require('./scanners/browser-scanner');
const kernelScanner = require('./scanners/kernel-scanner');
const dllScanner = require('./scanners/dll-scanner');
const jarScanner = require('./scanners/jar-scanner');
const memoryScanner = require('./scanners/memory-scanner');
const reportGenerator = require('./scanners/report-generator');

const PORT = 3847;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

/**
 * Serve static files from renderer/ directory
 */
function serveStatic(req, res) {
  const parsedUrl = url.parse(req.url);
  let pathname = parsedUrl.pathname;

  if (pathname === '/' || pathname === '/index.html') {
    pathname = '/web.html';
  }

  // Only serve from renderer/ and assets/
  const filePath = pathname.startsWith('/assets/')
    ? path.join(__dirname, pathname)
    : path.join(__dirname, 'renderer', pathname);

  const ext = path.extname(filePath);
  const mimeType = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const content = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': mimeType });
      res.end(content);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  }
}

/**
 * Handle API requests
 */
async function handleAPI(req, res, endpoint, body) {
  res.setHeader('Content-Type', 'application/json');

  try {
    let result;

    switch (endpoint) {
      case '/api/detect-launchers':
        result = { success: true, data: launcherDetector.detectLaunchers() };
        break;

      case '/api/scan-mods':
        result = { success: true, data: modScanner.scanModsFolder(body.path) };
        break;

      case '/api/scan-mod-file':
        result = { success: true, data: modScanner.scanModFile(body.path) };
        break;

      case '/api/scan-logs':
        result = { success: true, data: logScanner.scanLogsFolder(body.path) };
        break;

      case '/api/scan-processes':
        result = { success: true, data: processScanner.scanProcesses() };
        break;

      case '/api/scan-deleted-files':
        result = { success: true, data: deletedFileScanner.scanAllDeletedFiles() };
        break;

      case '/api/scan-strings':
        result = { success: true, data: stringScanner.scanDirectory(body.path) };
        break;

      case '/api/scan-binary':
        result = { success: true, data: stringScanner.scanBinaryFile(body.path) };
        break;

      case '/api/scan-mouse':
        result = { success: true, data: mouseScanner.scanMouseSoftware() };
        break;

      case '/api/scan-browsers':
        result = { success: true, data: browserScanner.scanBrowsers() };
        break;

      case '/api/scan-kernel':
        result = { success: true, data: kernelScanner.scanKernel() };
        break;

      case '/api/scan-dlls':
        result = { success: true, data: dllScanner.scanDLLs() };
        break;

      case '/api/scan-memory':
        result = { success: true, data: memoryScanner.scanMemory() };
        break;

      case '/api/scan-jar':
        result = { success: true, data: jarScanner.deepScanJar(body.path) };
        break;

      case '/api/scan-jar-directory':
        result = { success: true, data: jarScanner.deepScanMinecraftDirectory(body.path) };
        break;

      case '/api/full-scan':
        result = await runFullScan();
        break;

      case '/api/export-report':
        const htmlReport = reportGenerator.generateHTMLReport(body);
        result = { success: true, data: { html: htmlReport } };
        break;

      default:
        res.writeHead(404);
        res.end(JSON.stringify({ success: false, error: 'Unknown endpoint' }));
        return;
    }

    res.writeHead(200);
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(200);
    res.end(JSON.stringify({ success: false, error: err.message }));
  }
}

/**
 * Full scan orchestration
 */
async function runFullScan() {
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
    memoryScans: null,
    overallStatus: 'clean',
    totalDetections: 0
  };

  try {
    results.launchers = launcherDetector.detectLaunchers();

    for (const launcher of results.launchers) {
      for (const modsLoc of launcher.modsLocations) {
        const modResult = modScanner.scanModsFolder(modsLoc.path);
        modResult.launcher = launcher.name;
        modResult.version = modsLoc.version;
        results.modScans.push(modResult);
        results.totalDetections += modResult.detectedFiles;
      }
      for (const logsLoc of launcher.logsLocations) {
        const logResult = logScanner.scanLogsFolder(logsLoc.path);
        logResult.launcher = launcher.name;
        logResult.version = logsLoc.version;
        results.logScans.push(logResult);
        results.totalDetections += logResult.detectedFiles;
      }
      try {
        const jarResult = jarScanner.deepScanMinecraftDirectory(launcher.path);
        results.jarScans.push(jarResult);
        results.totalDetections += jarResult.detectedJars;
      } catch (err) { /* skip */ }
    }

    results.processScans = processScanner.scanProcesses();
    results.totalDetections += (results.processScans.detections || []).length;

    try { results.dllScans = dllScanner.scanDLLs(); results.totalDetections += results.dllScans.totalDetections; } catch (e) { results.dllScans = { totalDetections: 0 }; }
    results.deletedFileScans = deletedFileScanner.scanAllDeletedFiles();
    results.totalDetections += results.deletedFileScans.totalDetections;
    try { results.mouseScans = mouseScanner.scanMouseSoftware(); results.totalDetections += results.mouseScans.totalDetections; } catch (e) { results.mouseScans = { totalDetections: 0 }; }
    try { results.browserScans = browserScanner.scanBrowsers(); results.totalDetections += results.browserScans.totalDetections; } catch (e) { results.browserScans = { totalDetections: 0 }; }
    try { results.kernelScans = kernelScanner.scanKernel(); results.totalDetections += results.kernelScans.totalDetections; } catch (e) { results.kernelScans = { totalDetections: 0 }; }
    try { results.memoryScans = memoryScanner.scanMemory(); results.totalDetections += results.memoryScans.totalDetections; } catch (e) { results.memoryScans = { totalDetections: 0 }; }

    results.endTime = new Date().toISOString();
    if (results.totalDetections > 0) results.overallStatus = 'detected';
  } catch (err) {
    results.error = err.message;
  }

  return { success: true, data: results };
}

// Create HTTP server
const server = http.createServer((req, res) => {
  // CORS headers for local development
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url);

  if (parsedUrl.pathname.startsWith('/api/')) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let parsedBody = {};
      try { parsedBody = body ? JSON.parse(body) : {}; } catch (e) { /* empty */ }
      handleAPI(req, res, parsedUrl.pathname, parsedBody);
    });
  } else {
    serveStatic(req, res);
  }
});

server.listen(PORT, () => {
  console.log(`\n  SS-TOOLS v2.0 -- Minecraft SS AntiCheat Scanner`);
  console.log(`  ================================================`);
  console.log(`  Server running at http://localhost:${PORT}`);
  console.log(`  Open this URL in your browser to use the scanner.\n`);

  // Try to open browser automatically on Windows
  try {
    const { exec } = require('child_process');
    if (process.platform === 'win32') {
      exec(`start http://localhost:${PORT}`);
    }
  } catch (err) {
    // Ignore
  }
});
