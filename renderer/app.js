/**
 * SS-TOOLS v2.0 -- Renderer Application Logic
 * Enhanced with all scanner integrations and 3D visualization
 */

// ── State ──
let lastScanResults = null;
let isScanning = false;

// ── Tab Navigation ──

function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  document.getElementById(`tab-${tabId}`).classList.add('active');
  document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
}

// ── Progress Helpers ──

function showProgress(text, detail) {
  const container = document.getElementById('scan-progress');
  container.style.display = 'block';
  container.querySelector('.progress-text').textContent = text;
  document.getElementById('progress-detail').textContent = detail || '';
}

function updateProgress(percent, detail) {
  document.getElementById('progress-fill').style.width = `${percent}%`;
  if (detail) {
    document.getElementById('progress-detail').textContent = detail;
  }
  // Update 3D visualization
  if (viz) {
    viz.setProgress(percent);
  }
}

function hideProgress() {
  document.getElementById('scan-progress').style.display = 'none';
  document.getElementById('progress-fill').style.width = '0%';
}

function setScanning(scanning) {
  isScanning = scanning;
  document.querySelectorAll('.btn').forEach(btn => {
    btn.disabled = scanning;
  });
  if (viz) {
    viz.setScanning(scanning);
  }
}

// ── Stats Update ──

function updateStats(data) {
  if (data.launchers !== undefined) {
    document.querySelector('#stat-launchers .stat-value').textContent = data.launchers;
  }
  if (data.mods !== undefined) {
    document.querySelector('#stat-mods .stat-value').textContent = data.mods;
  }
  if (data.processes !== undefined) {
    document.querySelector('#stat-processes .stat-value').textContent = data.processes;
  }
  if (data.detections !== undefined) {
    const el = document.querySelector('#stat-detections .stat-value');
    el.textContent = data.detections;
    el.className = data.detections > 0 ? 'stat-value status-detected' : 'stat-value status-clean';
  }
  if (data.status !== undefined) {
    const el = document.querySelector('#stat-status .stat-value');
    el.textContent = data.status;
    el.className = 'stat-value ' + (
      data.status === 'CLEAN' ? 'status-clean' :
      data.status === 'DETECTED' ? 'status-detected' :
      data.status === 'SCANNING' ? 'status-scanning' : ''
    );
    if (viz) viz.setStatus(data.status);
  }
}

// ── Full Auto Scan (Enhanced) ──

async function runFullScan() {
  if (isScanning) return;
  setScanning(true);

  showProgress('Starting full system SS scan...', 'Initializing all scanners...');
  updateStats({ launchers: '-', mods: '-', processes: '-', detections: '-', status: 'SCANNING' });

  try {
    updateProgress(5, 'Detecting installed launchers...');

    const result = await window.sstools.fullScan();

    if (!result.success) {
      throw new Error(result.error || 'Scan failed');
    }

    const data = result.data;
    lastScanResults = data;

    updateProgress(100, 'Scan complete!');

    // Update stats
    const totalMods = (data.modScans || []).reduce((sum, s) => sum + (s.scannedFiles || 0), 0);
    const totalProcesses = data.processScans ? (data.processScans.totalProcesses || 0) : 0;

    updateStats({
      launchers: (data.launchers || []).length,
      mods: totalMods,
      processes: totalProcesses,
      detections: data.totalDetections,
      status: data.totalDetections > 0 ? 'DETECTED' : 'CLEAN'
    });

    // Add threat indicators to 3D viz
    if (viz && data.totalDetections > 0) {
      for (let i = 0; i < Math.min(data.totalDetections, 20); i++) {
        setTimeout(() => viz.addThreat(i < 3 ? 'critical' : 'high'), i * 200);
      }
    }

    // Update threat graph
    if (threatGraph) {
      const severityCounts = countSeverities(data);
      threatGraph.update(severityCounts);
      document.getElementById('threat-graph').style.display = 'block';
    }

    // Render results
    renderFullScanResults(data);

    setTimeout(hideProgress, 2000);
  } catch (err) {
    updateStats({ launchers: '-', mods: '-', processes: '-', detections: '-', status: 'ERROR' });
    document.getElementById('dashboard-results').innerHTML = renderError(err.message);
    hideProgress();
  }

  setScanning(false);
}

/**
 * Count severity levels across all scan results
 */
function countSeverities(data) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  // Process detections
  for (const det of (data.processScans?.detections || [])) {
    const sev = (det.severity || 'medium').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }

  // DLL detections
  for (const det of (data.dllScans?.suspiciousDLLs || [])) {
    const sev = (det.severity || 'medium').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }

  // Mouse detections
  for (const det of (data.mouseScans?.suspiciousMacros || [])) {
    const sev = (det.severity || 'medium').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }

  // Kernel detections
  for (const det of (data.kernelScans?.suspiciousDrivers || [])) {
    const sev = (det.severity || 'medium').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }

  // Mod file detections
  for (const scan of (data.modScans || [])) {
    for (const file of (scan.files || [])) {
      if (file.status === 'detected') {
        for (const det of (file.detections || [])) {
          for (const match of (det.matches || [])) {
            const sev = (match.severity || 'medium').toLowerCase();
            if (counts[sev] !== undefined) counts[sev]++;
          }
        }
      }
    }
  }

  // Browser detections
  for (const browser of (data.browserScans?.browsers || [])) {
    for (const det of (browser.detections || [])) {
      const sev = (det.severity || 'medium').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    }
  }

  // Deleted file detections
  for (const source of (data.deletedFileScans?.sources || [])) {
    for (const det of (source.detections || [])) {
      const sev = (det.severity || 'medium').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    }
  }

  return counts;
}

// ── Render Full Scan Results ──

function renderFullScanResults(data) {
  const container = document.getElementById('dashboard-results');
  let html = '';

  // Launchers summary
  if (data.launchers && data.launchers.length > 0) {
    html += renderResultSection(
      'Detected Launchers', 'badge-info', `${data.launchers.length} found`,
      data.launchers.map(l => `
        <div class="detection-item">
          <div class="detection-title">${escapeHtml(l.name)}</div>
          <div class="detection-detail">
            Path: ${escapeHtml(l.path)}<br>
            Versions: ${(l.versions || []).length} | Mods folders: ${(l.modsLocations || []).length}
          </div>
        </div>
      `).join('')
    );
  }

  // Mod scan results
  if (data.modScans && data.modScans.length > 0) {
    const modDetections = data.modScans.filter(s => s.detectedFiles > 0);
    const badgeClass = modDetections.length > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = modDetections.length > 0
      ? `${modDetections.reduce((s, m) => s + m.detectedFiles, 0)} suspicious`
      : 'Clean';

    let modHtml = '';
    for (const scan of data.modScans) {
      modHtml += `<div class="detection-item ${scan.detectedFiles > 0 ? 'severity-critical' : ''}">
        <div class="detection-title">[${escapeHtml(scan.launcher || 'Unknown')}] ${escapeHtml(scan.version || 'default')}</div>
        <div class="detection-detail">
          Folder: ${escapeHtml(scan.folder || '')}<br>
          Files: ${scan.totalFiles || 0} | Scanned: ${scan.scannedFiles || 0} | Detected: ${scan.detectedFiles || 0}
        </div>`;
      if (scan.files) {
        for (const file of scan.files) {
          if (file.status === 'detected') {
            modHtml += renderDetections(file);
          }
        }
      }
      modHtml += '</div>';
    }
    html += renderResultSection('Mod Scan Results', badgeClass, badgeText, modHtml);
  }

  // JAR deep scan
  if (data.jarScans && data.jarScans.length > 0) {
    const jarDetected = data.jarScans.filter(s => s.detectedJars > 0);
    const badgeClass = jarDetected.length > 0 ? 'badge-detected' : 'badge-clean';
    const totalDetected = data.jarScans.reduce((s, j) => s + (j.detectedJars || 0), 0);
    const badgeText = totalDetected > 0 ? `${totalDetected} detected` : 'Clean';

    let jarHtml = '';
    for (const scan of data.jarScans) {
      jarHtml += `<div class="detection-item">
        <div class="detection-detail">
          Directory: ${escapeHtml(scan.directory || '')}<br>
          Total JARs: ${scan.totalJars || 0} | Scanned: ${scan.scannedJars || 0} | Detected: ${scan.detectedJars || 0}
        </div>`;
      for (const jar of (scan.jars || [])) {
        if (jar.status === 'detected' || jar.status === 'suspicious') {
          jarHtml += `<div class="detection-item ${jar.status === 'detected' ? 'severity-critical' : 'severity-high'}" style="margin-left:16px;">
            <div class="detection-title">${escapeHtml(jar.file || '')}</div>
            <div class="detection-detail">
              Classes: ${jar.classFilesScanned || 0} | Suspicious: ${jar.suspiciousClassCount || 0}
            </div>`;
          for (const det of (jar.detections || []).slice(0, 10)) {
            jarHtml += `<div class="detection-detail">
              <span class="detection-tag tag-${det.severity}">${det.severity}</span>
              ${escapeHtml(det.description)} ${det.location ? `(${escapeHtml(det.location)})` : ''}
            </div>`;
          }
          if ((jar.detections || []).length > 10) {
            jarHtml += `<div class="detection-detail">... +${jar.detections.length - 10} more</div>`;
          }
          jarHtml += '</div>';
        }
      }
      jarHtml += '</div>';
    }
    html += renderResultSection('JAR Deep Scan', badgeClass, badgeText, jarHtml);
  }

  // Process scan
  if (data.processScans) {
    const procDetections = data.processScans.detections || [];
    const badgeClass = procDetections.length > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = procDetections.length > 0 ? `${procDetections.length} found` : 'Clean';

    let procHtml = `<div class="detection-detail" style="margin-bottom:12px;">
      Total processes scanned: ${data.processScans.totalProcesses || 0}
    </div>`;

    for (const det of procDetections) {
      procHtml += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(det.processName || det.description)}</div>
        <div class="detection-detail">
          PID: ${det.pid || 'N/A'}<br>
          ${escapeHtml(det.description)}<br>
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        </div>
      </div>`;
    }
    html += renderResultSection('Process Scanner', badgeClass, badgeText, procHtml);
  }

  // DLL scan
  if (data.dllScans) {
    const dllDets = data.dllScans.totalDetections || 0;
    const badgeClass = dllDets > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = dllDets > 0 ? `${dllDets} suspicious` : 'Clean';

    let dllHtml = `<div class="detection-detail" style="margin-bottom:12px;">
      Processes: ${data.dllScans.totalProcesses || 0} | Total DLLs: ${data.dllScans.totalDLLs || 0}
    </div>`;

    for (const det of (data.dllScans.suspiciousDLLs || [])) {
      dllHtml += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(det.dll || '')}</div>
        <div class="detection-detail">
          Process: ${escapeHtml(det.processName || '')} (PID: ${det.pid || 'N/A'})<br>
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.description)}
        </div>
      </div>`;
    }
    html += renderResultSection('DLL Scanner', badgeClass, badgeText, dllHtml);
  }

  // Mouse software
  if (data.mouseScans) {
    const mouseDets = data.mouseScans.totalDetections || 0;
    const badgeClass = mouseDets > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = mouseDets > 0 ? `${mouseDets} suspicious` : 'Clean';

    let mouseHtml = '';
    for (const sw of (data.mouseScans.detectedSoftware || [])) {
      mouseHtml += `<div class="detection-item ${sw.macroDetections.length > 0 ? 'severity-critical' : ''}">
        <div class="detection-title">${escapeHtml(sw.name)} ${sw.running ? '(Running)' : '(Installed)'}</div>
        <div class="detection-detail">
          ${sw.isLegitimate ? 'Legitimate software' : 'Suspicious software'} |
          Macro detections: ${sw.macroDetections.length}
        </div>`;
      for (const det of (sw.macroDetections || [])) {
        mouseHtml += `<div class="detection-detail">
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.description)}
        </div>`;
      }
      mouseHtml += '</div>';
    }
    if (!mouseHtml) mouseHtml = '<div class="detection-detail">No mouse software detected</div>';
    html += renderResultSection('Mouse Software', badgeClass, badgeText, mouseHtml);
  }

  // Browser scan
  if (data.browserScans) {
    const browserDets = data.browserScans.totalDetections || 0;
    const badgeClass = browserDets > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = browserDets > 0 ? `${browserDets} found` : 'Clean';

    let browserHtml = '';
    for (const browser of (data.browserScans.browsers || [])) {
      if (!browser.installed) continue;
      browserHtml += `<div class="detection-item ${browser.totalDetections > 0 ? 'severity-high' : ''}">
        <div class="detection-title">${escapeHtml(browser.name)}</div>
        <div class="detection-detail">Detections: ${browser.totalDetections || 0}</div>`;
      for (const det of (browser.detections || []).slice(0, 10)) {
        browserHtml += `<div class="detection-detail">
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          [${det.type}] ${escapeHtml(det.value || det.name || '')}
        </div>`;
      }
      browserHtml += '</div>';
    }
    html += renderResultSection('Browser Scanner', badgeClass, badgeText, browserHtml);
  }

  // Kernel scan
  if (data.kernelScans) {
    const kernelDets = data.kernelScans.totalDetections || 0;
    const badgeClass = kernelDets > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = kernelDets > 0 ? `${kernelDets} suspicious` : 'Clean';

    let kernelHtml = `<div class="detection-detail" style="margin-bottom:12px;">
      Loaded drivers: ${(data.kernelScans.loadedDrivers || []).length} |
      Filter drivers: ${(data.kernelScans.filterDrivers || []).length}
    </div>`;

    for (const det of (data.kernelScans.suspiciousDrivers || [])) {
      kernelHtml += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(det.moduleName || det.displayName || '')}</div>
        <div class="detection-detail">
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.matchDescription || det.description || '')}
        </div>
      </div>`;
    }
    for (const det of (data.kernelScans.hiddenProcesses || [])) {
      kernelHtml += `<div class="detection-item severity-critical">
        <div class="detection-title">Hidden Process (PID: ${det.pid})</div>
        <div class="detection-detail">
          <span class="detection-tag tag-critical">critical</span>
          ${escapeHtml(det.description)}
        </div>
      </div>`;
    }
    html += renderResultSection('Kernel Driver Scanner', badgeClass, badgeText, kernelHtml);
  }

  // Deleted files
  if (data.deletedFileScans) {
    const delDetections = data.deletedFileScans.totalDetections || 0;
    const badgeClass = delDetections > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = delDetections > 0 ? `${delDetections} found` : 'Clean';

    let delHtml = '';
    for (const source of (data.deletedFileScans.sources || [])) {
      delHtml += `<div class="detection-item ${source.detections && source.detections.length > 0 ? 'severity-high' : ''}">
        <div class="detection-title">[${escapeHtml(source.source)}] ${escapeHtml(source.status)}</div>`;
      for (const det of (source.detections || [])) {
        delHtml += `<div class="detection-detail">
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.name || det.record || det.command || 'Unknown')}
        </div>`;
      }
      delHtml += '</div>';
    }
    html += renderResultSection('Deleted File Scanner', badgeClass, badgeText, delHtml);
  }

  container.innerHTML = html;
}

// ── Individual Scanner Functions ──

async function detectLaunchers() {
  if (isScanning) return;
  setScanning(true);
  try {
    const result = await window.sstools.detectLaunchers();
    const container = document.getElementById('launcher-results') || document.getElementById('dashboard-results');
    if (result.success) {
      container.innerHTML = renderResultSection(
        'Detected Launchers', 'badge-info', `${result.data.length} found`,
        result.data.length > 0 ? result.data.map(l => `
          <div class="detection-item">
            <div class="detection-title">${escapeHtml(l.name)}</div>
            <div class="detection-detail">
              Path: ${escapeHtml(l.path)}<br>
              Versions: ${(l.versions || []).length} | Mods: ${(l.modsLocations || []).length} | Logs: ${(l.logsLocations || []).length}
            </div>
          </div>
        `).join('') : '<div class="detection-detail">No Minecraft launchers detected</div>'
      );
    } else {
      container.innerHTML = renderError(result.error);
    }
  } catch (err) {
    document.getElementById('dashboard-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanModsFolder() {
  if (isScanning) return;
  const folder = await window.sstools.selectFolder();
  if (!folder) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanMods(folder);
    document.getElementById('mod-results').innerHTML = result.success
      ? renderModResults(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('mod-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanSingleMod() {
  if (isScanning) return;
  const file = await window.sstools.selectFile();
  if (!file) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanModFile(file);
    document.getElementById('mod-results').innerHTML = result.success
      ? renderSingleFileResult(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('mod-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanJarDeep() {
  if (isScanning) return;
  const file = await window.sstools.selectFile();
  if (!file) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanJar(file);
    document.getElementById('jar-results').innerHTML = result.success
      ? renderJarResult(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('jar-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanMinecraftDir() {
  if (isScanning) return;
  const folder = await window.sstools.selectFolder();
  if (!folder) return;
  setScanning(true);
  showProgress('Deep scanning .minecraft directory...', 'Analyzing all JAR files...');
  try {
    const result = await window.sstools.scanJarDirectory(folder);
    hideProgress();
    document.getElementById('jar-results').innerHTML = result.success
      ? renderJarDirResult(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('jar-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanLogsFolder() {
  if (isScanning) return;
  const folder = await window.sstools.selectFolder();
  if (!folder) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanLogs(folder);
    document.getElementById('log-results').innerHTML = result.success
      ? renderLogResults(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('log-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanProcesses() {
  if (isScanning) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanProcesses();
    document.getElementById('process-results').innerHTML = result.success
      ? renderProcessResults(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('process-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanDLLs() {
  if (isScanning) return;
  setScanning(true);
  showProgress('Scanning loaded DLLs...', 'Enumerating all processes...');
  try {
    const result = await window.sstools.scanDLLs();
    hideProgress();
    document.getElementById('dll-results').innerHTML = result.success
      ? renderDLLResults(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('dll-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanMouseSoftware() {
  if (isScanning) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanMouse();
    document.getElementById('mouse-results').innerHTML = result.success
      ? renderMouseResults(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('mouse-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanBrowserHistory() {
  if (isScanning) return;
  setScanning(true);
  showProgress('Scanning browsers...', 'Checking download history, extensions, and bookmarks...');
  try {
    const result = await window.sstools.scanBrowsers();
    hideProgress();
    document.getElementById('browser-results').innerHTML = result.success
      ? renderBrowserResults(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('browser-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanKernelDrivers() {
  if (isScanning) return;
  setScanning(true);
  showProgress('Scanning kernel drivers...', 'Querying loaded drivers and filter managers...');
  try {
    const result = await window.sstools.scanKernel();
    hideProgress();
    document.getElementById('kernel-results').innerHTML = result.success
      ? renderKernelResults(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('kernel-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanMemoryProcesses() {
  if (isScanning) return;
  setScanning(true);
  showProgress('Scanning Java process memory...', 'Inspecting JVM arguments, modules, and memory strings...');
  try {
    const result = await window.sstools.scanMemory();
    hideProgress();
    document.getElementById('memory-results').innerHTML = result.success
      ? renderMemoryResults(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('memory-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanDeletedFiles() {
  if (isScanning) return;
  setScanning(true);
  showProgress('Scanning for deleted files...', 'Checking Recycle Bin, Prefetch, USN Journal...');
  try {
    const result = await window.sstools.scanDeletedFiles();
    hideProgress();
    document.getElementById('deleted-results').innerHTML = result.success
      ? renderDeletedResults(result.data)
      : renderError(result.error);
  } catch (err) {
    hideProgress();
    document.getElementById('deleted-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanStringDir() {
  if (isScanning) return;
  const folder = await window.sstools.selectFolder();
  if (!folder) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanStrings(folder);
    document.getElementById('string-results').innerHTML = result.success
      ? renderStringResults(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('string-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function scanBinaryFile() {
  if (isScanning) return;
  const file = await window.sstools.selectFile();
  if (!file) return;
  setScanning(true);
  try {
    const result = await window.sstools.scanBinary(file);
    document.getElementById('string-results').innerHTML = result.success
      ? renderSingleFileResult(result.data)
      : renderError(result.error);
  } catch (err) {
    document.getElementById('string-results').innerHTML = renderError(err.message);
  }
  setScanning(false);
}

async function exportReport() {
  if (!lastScanResults) {
    alert('Run a scan first before exporting a report.');
    return;
  }
  await window.sstools.exportReport(lastScanResults);
}

// ── Render Helpers ──

function renderResultSection(title, badgeClass, badgeText, contentHtml) {
  return `
    <div class="result-section">
      <div class="result-header">
        <h3>${escapeHtml(title)}</h3>
        <span class="badge ${badgeClass}">${escapeHtml(badgeText)}</span>
      </div>
      <div class="result-body">${contentHtml}</div>
    </div>`;
}

function renderDetections(file) {
  let html = `<div class="detection-item severity-critical" style="margin-left:16px;">
    <div class="detection-title">${escapeHtml(file.file)}</div>`;
  for (const det of (file.detections || [])) {
    for (const match of (det.matches || [])) {
      html += `<div class="detection-detail">
        <span class="detection-tag tag-${match.severity}">${match.severity}</span>
        ${escapeHtml(match.keyword)} (${escapeHtml(match.category)})
      </div>`;
    }
  }
  html += '</div>';
  return html;
}

function renderError(message) {
  return `<div class="result-section">
    <div class="result-header"><h3>Error</h3><span class="badge badge-detected">Error</span></div>
    <div class="result-body"><div class="detection-item severity-critical">
      <div class="detection-detail">${escapeHtml(message)}</div>
    </div></div>
  </div>`;
}

function renderModResults(data) {
  const badgeClass = data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean';
  const badgeText = data.detectedFiles > 0 ? `${data.detectedFiles} suspicious` : 'Clean';

  let filesHtml = `<div class="detection-detail">
    Total: ${data.totalFiles} | Scanned: ${data.scannedFiles} | Detected: ${data.detectedFiles}
  </div>`;

  for (const file of (data.files || [])) {
    if (file.status === 'detected') {
      filesHtml += renderDetections(file);
    }
  }

  return renderResultSection('Mod Scan Results', badgeClass, badgeText, filesHtml);
}

function renderSingleFileResult(data) {
  const badgeClass = data.status === 'detected' ? 'badge-detected' : 'badge-clean';
  const badgeText = data.status === 'detected' ? 'Suspicious' : 'Clean';

  let html = `<div class="detection-detail">
    File: ${escapeHtml(data.file || data.name || '')}<br>
    Size: ${formatBytes(data.size)} | Entries: ${data.scannedEntries || data.stringsFound || 0}
  </div>`;

  for (const det of (data.detections || [])) {
    html += `<div class="detection-item severity-${det.severity || 'medium'}">
      <div class="detection-detail">
        <span class="detection-tag tag-${det.severity || 'medium'}">${det.severity || 'medium'}</span>
        ${escapeHtml(det.description || det.pattern || '')}
        ${det.matches ? det.matches.map(m => `<br>${escapeHtml(m.keyword)} (${escapeHtml(m.category)})`).join('') : ''}
      </div>
    </div>`;
  }

  return renderResultSection('File Scan Result', badgeClass, badgeText, html);
}

function renderJarResult(data) {
  const badgeClass = data.status === 'detected' ? 'badge-detected' :
                     data.status === 'suspicious' ? 'badge-warning' : 'badge-clean';
  const badgeText = data.status === 'detected' ? 'Detected' :
                    data.status === 'suspicious' ? 'Suspicious' : 'Clean';

  let html = `<div class="detection-detail">
    File: ${escapeHtml(data.file)}<br>
    Size: ${formatBytes(data.size)} | Entries: ${data.totalEntries} | Classes: ${data.classFilesScanned}<br>
    Suspicious classes: ${data.suspiciousClassCount} | Vanilla mods: ${data.vanillaClassModifications}<br>
    Mod type: ${data.isFabric ? 'Fabric' : data.isForge ? 'Forge' : data.isQuilt ? 'Quilt' : 'Unknown'}
  </div>`;

  for (const det of (data.detections || [])) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        [${det.type}] ${escapeHtml(det.description)}
        ${det.location ? `<br>Location: ${escapeHtml(det.location)}` : ''}
        ${det.match ? `<br>Match: ${escapeHtml(det.match)}` : ''}
      </div>
    </div>`;
  }

  return renderResultSection('JAR Deep Scan', badgeClass, badgeText, html);
}

function renderJarDirResult(data) {
  const badgeClass = data.detectedJars > 0 ? 'badge-detected' : 'badge-clean';
  const badgeText = data.detectedJars > 0 ? `${data.detectedJars} detected` : 'Clean';

  let html = `<div class="detection-detail">
    Directory: ${escapeHtml(data.directory)}<br>
    Total JARs: ${data.totalJars} | Scanned: ${data.scannedJars} | Detected: ${data.detectedJars} | Suspicious: ${data.suspiciousJars}
  </div>`;

  for (const jar of (data.jars || [])) {
    if (jar.status === 'detected' || jar.status === 'suspicious') {
      html += renderJarResult(jar);
    }
  }

  return renderResultSection('Minecraft Directory Scan', badgeClass, badgeText, html);
}

function renderLogResults(data) {
  const badgeClass = data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">Files: ${data.totalFiles} | Scanned: ${data.scannedFiles}</div>`;
  for (const file of (data.files || [])) {
    if (file.status === 'detected') {
      html += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(file.file)}</div>`;
      for (const det of (file.detections || [])) {
        html += `<div class="detection-detail">
          Line ${det.line}: <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.description)}<br>
          <code>${escapeHtml(det.content || '')}</code>
        </div>`;
      }
      html += '</div>';
    }
  }
  return renderResultSection('Log Scan Results', badgeClass, data.detectedFiles > 0 ? `${data.detectedFiles} files` : 'Clean', html);
}

function renderProcessResults(data) {
  const dets = data.detections || [];
  const badgeClass = dets.length > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">Processes scanned: ${data.totalProcesses}</div>`;
  for (const det of dets) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-title">${escapeHtml(det.processName || '')}</div>
      <div class="detection-detail">
        PID: ${det.pid} | <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  return renderResultSection('Process Results', badgeClass, dets.length > 0 ? `${dets.length} found` : 'Clean', html);
}

function renderDLLResults(data) {
  const dets = data.suspiciousDLLs || [];
  const badgeClass = dets.length > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">Processes: ${data.totalProcesses} | DLLs: ${data.totalDLLs}</div>`;
  for (const det of dets) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-title">${escapeHtml(det.dll)}</div>
      <div class="detection-detail">
        Process: ${escapeHtml(det.processName)} (PID: ${det.pid}) |
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  return renderResultSection('DLL Results', badgeClass, dets.length > 0 ? `${dets.length} suspicious` : 'Clean', html);
}

function renderMouseResults(data) {
  const dets = data.totalDetections || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = '';
  for (const sw of (data.detectedSoftware || [])) {
    html += `<div class="detection-item ${sw.macroDetections.length > 0 ? 'severity-critical' : ''}">
      <div class="detection-title">${escapeHtml(sw.name)} ${sw.running ? '(Running)' : '(Installed)'}</div>
      <div class="detection-detail">
        ${sw.isLegitimate ? 'Legitimate' : 'Suspicious'} |
        Install: ${escapeHtml(sw.installPath || 'N/A')} |
        Macros flagged: ${sw.macroDetections.length}
      </div>`;
    for (const det of (sw.macroDetections || [])) {
      html += `<div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>`;
    }
    html += '</div>';
  }
  if (!html) html = '<div class="detection-detail">No mouse software detected on this system</div>';
  return renderResultSection('Mouse Software', badgeClass, dets > 0 ? `${dets} flagged` : 'Clean', html);
}

function renderBrowserResults(data) {
  const dets = data.totalDetections || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = '';
  for (const browser of (data.browsers || [])) {
    if (!browser.installed) continue;
    html += `<div class="detection-item ${browser.totalDetections > 0 ? 'severity-high' : ''}">
      <div class="detection-title">${escapeHtml(browser.name)}</div>
      <div class="detection-detail">Detections: ${browser.totalDetections}</div>`;
    for (const det of (browser.detections || []).slice(0, 15)) {
      html += `<div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        [${escapeHtml(det.type)}] ${escapeHtml(det.value || det.name || '')}
      </div>`;
    }
    html += '</div>';
  }
  if (!html) html = '<div class="detection-detail">No browsers found or no detections</div>';
  return renderResultSection('Browser Results', badgeClass, dets > 0 ? `${dets} found` : 'Clean', html);
}

function renderKernelResults(data) {
  const dets = data.totalDetections || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">
    Loaded drivers: ${(data.loadedDrivers || []).length} |
    Filter drivers: ${(data.filterDrivers || []).length}
  </div>`;
  for (const det of (data.suspiciousDrivers || [])) {
    html += `<div class="detection-item severity-critical">
      <div class="detection-title">${escapeHtml(det.moduleName || '')}</div>
      <div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.matchDescription || '')}
      </div>
    </div>`;
  }
  for (const det of (data.driverFileScans || [])) {
    html += `<div class="detection-item severity-critical">
      <div class="detection-title">${escapeHtml(det.file)}</div>
      <div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  for (const det of (data.hiddenProcesses || [])) {
    html += `<div class="detection-item severity-critical">
      <div class="detection-title">Hidden Process PID: ${det.pid}</div>
      <div class="detection-detail">
        <span class="detection-tag tag-critical">critical</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  return renderResultSection('Kernel Results', badgeClass, dets > 0 ? `${dets} suspicious` : 'Clean', html);
}

function renderDeletedResults(data) {
  const dets = data.totalDetections || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = '';
  for (const source of (data.sources || [])) {
    html += `<div class="detection-item ${source.detections && source.detections.length > 0 ? 'severity-high' : ''}">
      <div class="detection-title">[${escapeHtml(source.source)}] ${escapeHtml(source.status)}</div>`;
    if (source.totalItems) html += `<div class="detection-detail">Items checked: ${source.totalItems}</div>`;
    if (source.totalFiles) html += `<div class="detection-detail">Files checked: ${source.totalFiles}</div>`;
    for (const det of (source.detections || [])) {
      html += `<div class="detection-detail">
        <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.name || det.record || det.command || 'Unknown')}
      </div>`;
    }
    html += '</div>';
  }
  return renderResultSection('Deleted File Results', badgeClass, dets > 0 ? `${dets} found` : 'Clean', html);
}

function renderMemoryResults(data) {
  const dets = data.totalDetections || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">
    Java processes found: ${(data.javaProcesses || []).length}
  </div>`;

  for (const proc of (data.javaProcesses || [])) {
    html += `<div class="detection-item">
      <div class="detection-detail">${escapeHtml(proc.name)} (PID: ${proc.pid})</div>
    </div>`;
  }

  for (const det of (data.jvmArgDetections || [])) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-title">[JVM Args] ${escapeHtml(det.description)}</div>
      <div class="detection-detail">
        PID: ${det.pid} | <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${det.match ? `Match: ${escapeHtml(det.match)}` : ''}
      </div>
    </div>`;
  }

  for (const det of (data.moduleDetections || [])) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-title">[Module] ${escapeHtml(det.module || '')}</div>
      <div class="detection-detail">
        PID: ${det.pid} | <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }

  for (const det of (data.memoryStringDetections || [])) {
    html += `<div class="detection-item severity-${det.severity}">
      <div class="detection-title">[Memory String] ${escapeHtml(det.description)}</div>
      <div class="detection-detail">
        PID: ${det.pid} | <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        Match type: ${det.matchType} | Score: ${det.score ? det.score.toFixed(2) : 'N/A'}
      </div>
    </div>`;
  }

  for (const det of (data.agentDetections || [])) {
    html += `<div class="detection-item severity-critical">
      <div class="detection-title">[Java Agent] ${escapeHtml(det.description)}</div>
      <div class="detection-detail">
        PID: ${det.pid} | <span class="detection-tag tag-critical">critical</span>
      </div>
    </div>`;
  }

  return renderResultSection('Memory Scanner', badgeClass, dets > 0 ? `${dets} found` : 'Clean', html);
}

function renderStringResults(data) {
  const dets = data.detectedFiles || 0;
  const badgeClass = dets > 0 ? 'badge-detected' : 'badge-clean';
  let html = `<div class="detection-detail">Files: ${data.totalFiles} | Scanned: ${data.scannedFiles}</div>`;
  for (const file of (data.files || [])) {
    if (file.status === 'detected') {
      html += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(file.file)}</div>
        <div class="detection-detail">Strings: ${file.stringsFound} | Size: ${formatBytes(file.size)}</div>`;
      for (const det of (file.detections || [])) {
        html += `<div class="detection-detail">
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
          ${escapeHtml(det.description || det.pattern || '')}
        </div>`;
      }
      html += '</div>';
    }
  }
  return renderResultSection('String Scan Results', badgeClass, dets > 0 ? `${dets} files` : 'Clean', html);
}

// ── Utilities ──

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

// ── Event Listeners ──

document.addEventListener('DOMContentLoaded', () => {
  // Listen for tray-triggered scans
  if (window.sstools.onTriggerFullScan) {
    window.sstools.onTriggerFullScan(() => runFullScan());
  }

  // Admin status
  if (window.sstools.onAdminStatus) {
    window.sstools.onAdminStatus((isAdmin) => {
      const el = document.getElementById('admin-status');
      if (el) {
        el.textContent = isAdmin ? 'Admin' : 'User';
        el.className = isAdmin ? 'admin-badge admin-yes' : 'admin-badge admin-no';
      }
    });
  }
});
