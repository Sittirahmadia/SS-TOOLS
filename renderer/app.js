/**
 * SS-TOOLS — Renderer Application Logic
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
}

// ── Stats Update ──

function updateStats(launchers, mods, detections, status) {
  if (launchers !== undefined) {
    document.querySelector('#stat-launchers .stat-value').textContent = launchers;
  }
  if (mods !== undefined) {
    document.querySelector('#stat-mods .stat-value').textContent = mods;
  }
  if (detections !== undefined) {
    const el = document.querySelector('#stat-detections .stat-value');
    el.textContent = detections;
    el.className = detections > 0 ? 'stat-value status-detected' : 'stat-value status-clean';
  }
  if (status !== undefined) {
    const el = document.querySelector('#stat-status .stat-value');
    el.textContent = status;
    el.className = 'stat-value ' + (
      status === 'CLEAN' ? 'status-clean' :
      status === 'DETECTED' ? 'status-detected' :
      status === 'SCANNING' ? 'status-scanning' : ''
    );
  }
}

// ── Full Auto Scan ──

async function runFullScan() {
  if (isScanning) return;
  setScanning(true);

  showProgress('Starting full scan...', 'Detecting launchers and scanning all data...');
  updateStats('-', '-', '-', 'SCANNING');

  try {
    updateProgress(10, 'Detecting installed launchers...');

    const result = await window.sstools.fullScan();

    if (!result.success) {
      throw new Error(result.error || 'Scan failed');
    }

    const data = result.data;
    lastScanResults = data;

    updateProgress(100, 'Scan complete!');

    // Update stats
    const totalMods = data.modScans.reduce((sum, s) => sum + s.scannedFiles, 0);
    updateStats(
      data.launchers.length,
      totalMods,
      data.totalDetections,
      data.totalDetections > 0 ? 'DETECTED' : 'CLEAN'
    );

    // Render results
    renderFullScanResults(data);

    setTimeout(hideProgress, 2000);
  } catch (err) {
    updateStats('-', '-', '-', 'ERROR');
    document.getElementById('dashboard-results').innerHTML = renderError(err.message);
    hideProgress();
  }

  setScanning(false);
}

function renderFullScanResults(data) {
  const container = document.getElementById('dashboard-results');
  let html = '';

  // Launchers summary
  if (data.launchers.length > 0) {
    html += renderResultSection(
      'Detected Launchers',
      'badge-info',
      `${data.launchers.length} found`,
      data.launchers.map(l => `
        <div class="detection-item">
          <div class="detection-title">${escapeHtml(l.name)}</div>
          <div class="detection-detail">
            Path: ${escapeHtml(l.path)}<br>
            Versions/Instances: ${l.versions.length} | Mods folders: ${l.modsLocations.length}
          </div>
        </div>
      `).join('')
    );
  }

  // Mod scan results
  if (data.modScans.length > 0) {
    const modDetections = data.modScans.filter(s => s.detectedFiles > 0);
    const badgeClass = modDetections.length > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = modDetections.length > 0 
      ? `${modDetections.reduce((s, m) => s + m.detectedFiles, 0)} suspicious` 
      : 'Clean';

    let modHtml = '';
    for (const scan of data.modScans) {
      modHtml += `<div class="detection-item ${scan.detectedFiles > 0 ? 'severity-critical' : ''}">
        <div class="detection-title">[${escapeHtml(scan.launcher)}] ${escapeHtml(scan.version || 'default')}</div>
        <div class="detection-detail">
          Folder: ${escapeHtml(scan.folder)}<br>
          Files: ${scan.totalFiles} | Scanned: ${scan.scannedFiles} | Detected: ${scan.detectedFiles}
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

  // Process scan
  if (data.processScans) {
    const procDetections = data.processScans.detections || [];
    const badgeClass = procDetections.length > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = procDetections.length > 0 ? `${procDetections.length} found` : 'Clean';

    let procHtml = `<div class="detection-detail" style="margin-bottom:12px;">
      Total processes scanned: ${data.processScans.totalProcesses}
    </div>`;

    for (const det of procDetections) {
      procHtml += `<div class="detection-item severity-critical">
        <div class="detection-title">${escapeHtml(det.processName || det.description)}</div>
        <div class="detection-detail">
          PID: ${det.pid || 'N/A'}<br>
          ${det.description}<br>
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        </div>
      </div>`;
    }

    html += renderResultSection('Process Scanner', badgeClass, badgeText, procHtml);
  }

  // Deleted files
  if (data.deletedFileScans) {
    const delDetections = data.deletedFileScans.totalDetections || 0;
    const badgeClass = delDetections > 0 ? 'badge-detected' : 'badge-clean';
    const badgeText = delDetections > 0 ? `${delDetections} found` : 'Clean';

    let delHtml = '';
    for (const source of (data.deletedFileScans.sources || [])) {
      delHtml += `<div class="detection-item ${source.detections && source.detections.length > 0 ? 'severity-high' : ''}">
        <div class="detection-title">${escapeHtml(source.source)}</div>
        <div class="detection-detail">Status: ${source.status}${source.error ? ' — ' + escapeHtml(source.error) : ''}</div>`;

      for (const det of (source.detections || [])) {
        delHtml += `<div class="detection-detail" style="margin-top:6px;padding-left:12px;border-left:2px solid var(--danger);">
          ${escapeHtml(det.name || det.record || det.command || 'Unknown')}<br>
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        </div>`;
      }

      delHtml += '</div>';
    }

    html += renderResultSection('Deleted File Scanner', badgeClass, badgeText, delHtml);
  }

  if (html === '') {
    html = renderEmptyState('No results', 'Run a full scan to check all launchers for cheats.');
  }

  container.innerHTML = html;
}

// ── Mod Scanner ──

async function scanModsFolder() {
  if (isScanning) return;

  const folderPath = await window.sstools.selectFolder();
  if (!folderPath) return;

  setScanning(true);
  const container = document.getElementById('mod-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning mods folder...</h3></div>';

  try {
    const result = await window.sstools.scanMods(folderPath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = '';

    // Summary
    html += `<div class="result-section">
      <div class="result-header">
        <div class="result-title">Scan Summary</div>
        <span class="result-badge ${data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.detectedFiles > 0 ? `${data.detectedFiles} DETECTED` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <table class="summary-table">
          <tr><th>Metric</th><th>Value</th></tr>
          <tr><td>Total Files</td><td>${data.totalFiles}</td></tr>
          <tr><td>Scanned</td><td>${data.scannedFiles}</td></tr>
          <tr><td>Detected</td><td>${data.detectedFiles}</td></tr>
          <tr><td>Clean</td><td>${data.cleanFiles}</td></tr>
          <tr><td>Errors</td><td>${data.errorFiles}</td></tr>
          <tr><td>Total Size</td><td>${formatBytes(data.totalSize)}</td></tr>
        </table>
      </div>
    </div>`;

    // Individual file results
    for (const file of (data.files || [])) {
      if (file.status === 'detected') {
        html += `<div class="result-section">
          <div class="result-header" onclick="toggleResultBody(this)">
            <div class="result-title">${escapeHtml(file.file)}</div>
            <span class="result-badge badge-detected">DETECTED</span>
          </div>
          <div class="result-body">
            <div class="detection-detail" style="margin-bottom:12px;">
              Size: ${formatBytes(file.size)} | Entries scanned: ${file.scannedEntries}
            </div>
            ${renderDetections(file)}
          </div>
        </div>`;
      }
    }

    if (data.detectedFiles === 0) {
      html += renderEmptyState('All Clear', 'No cheat mods detected in this folder.');
    }

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

async function scanSingleMod() {
  if (isScanning) return;

  const filePath = await window.sstools.selectFile();
  if (!filePath) return;

  setScanning(true);
  const container = document.getElementById('mod-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning file...</h3></div>';

  try {
    const result = await window.sstools.scanModFile(filePath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">${escapeHtml(data.file)}</div>
        <span class="result-badge ${data.status === 'detected' ? 'badge-detected' : 'badge-clean'}">
          ${data.status.toUpperCase()}
        </span>
      </div>
      <div class="result-body">
        <div class="detection-detail" style="margin-bottom:12px;">
          Size: ${formatBytes(data.size)} | Entries scanned: ${data.scannedEntries}
        </div>
        ${data.status === 'detected' ? renderDetections(data) : '<p style="color:var(--success);">No cheats detected.</p>'}
      </div>
    </div>`;

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── Log Scanner ──

async function scanLogsFolder() {
  if (isScanning) return;

  const folderPath = await window.sstools.selectFolder();
  if (!folderPath) return;

  setScanning(true);
  const container = document.getElementById('log-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning logs...</h3></div>';

  try {
    const result = await window.sstools.scanLogs(folderPath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">Log Scan Summary</div>
        <span class="result-badge ${data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.detectedFiles > 0 ? `${data.detectedFiles} DETECTED` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <p>Files scanned: ${data.scannedFiles} of ${data.totalFiles}</p>
      </div>
    </div>`;

    for (const file of (data.files || [])) {
      if (file.status === 'detected') {
        html += `<div class="result-section">
          <div class="result-header" onclick="toggleResultBody(this)">
            <div class="result-title">${escapeHtml(file.file)}</div>
            <span class="result-badge badge-detected">${file.detections.length} issues</span>
          </div>
          <div class="result-body">
            <div class="detection-detail" style="margin-bottom:12px;">
              Lines scanned: ${file.linesScanned}
            </div>
            ${file.detections.map(det => `
              <div class="detection-item severity-${det.severity}">
                <div class="detection-title">Line ${det.line}: ${escapeHtml(det.description)}</div>
                <div class="detection-detail">
                  <code style="font-size:11px;color:var(--text-muted);">${escapeHtml(det.content)}</code>
                  ${det.keywords ? '<br>Keywords: ' + det.keywords.map(k => `<span class="detection-tag tag-critical">${escapeHtml(k)}</span>`).join('') : ''}
                  <span class="detection-tag tag-${det.severity}">${det.severity}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>`;
      }
    }

    if (data.detectedFiles === 0) {
      html += renderEmptyState('All Clear', 'No cheat indicators found in logs.');
    }

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── Process Scanner ──

async function scanProcesses() {
  if (isScanning) return;
  setScanning(true);

  const container = document.getElementById('process-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning processes...</h3></div>';

  try {
    const result = await window.sstools.scanProcesses();
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">Process Scan</div>
        <span class="result-badge ${data.detections.length > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.detections.length > 0 ? `${data.detections.length} FOUND` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <div class="detection-detail" style="margin-bottom:12px;">
          Total processes: ${data.totalProcesses} | Scanned at: ${data.scannedAt}
        </div>
        ${data.detections.map(det => `
          <div class="detection-item severity-${det.severity}">
            <div class="detection-title">${escapeHtml(det.processName || 'Unknown')}</div>
            <div class="detection-detail">
              PID: ${det.pid || 'N/A'}<br>
              ${det.description}<br>
              ${det.commandLine && det.commandLine !== 'N/A' ? 'Command: <code>' + escapeHtml(det.commandLine.substring(0, 150)) + '</code><br>' : ''}
              ${det.executablePath && det.executablePath !== 'N/A' ? 'Path: ' + escapeHtml(det.executablePath) + '<br>' : ''}
              <span class="detection-tag tag-${det.severity}">${det.severity}</span>
            </div>
          </div>
        `).join('')}
        ${data.detections.length === 0 ? '<p style="color:var(--success);">No suspicious processes found.</p>' : ''}
      </div>
    </div>`;

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── Deleted File Scanner ──

async function scanDeletedFiles() {
  if (isScanning) return;
  setScanning(true);

  const container = document.getElementById('deleted-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning for deleted files...</h3><p>This may take a moment...</p></div>';

  try {
    const result = await window.sstools.scanDeletedFiles();
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">Deleted File Scan</div>
        <span class="result-badge ${data.totalDetections > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.totalDetections > 0 ? `${data.totalDetections} FOUND` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <div class="detection-detail" style="margin-bottom:12px;">
          Scanned at: ${data.scannedAt}
        </div>`;

    for (const source of (data.sources || [])) {
      html += `<div class="detection-item ${source.detections && source.detections.length > 0 ? 'severity-high' : ''}">
        <div class="detection-title">${escapeHtml(source.source)}</div>
        <div class="detection-detail">
          Status: ${source.status}
          ${source.totalItems !== undefined ? ' | Items: ' + source.totalItems : ''}
          ${source.totalFiles !== undefined ? ' | Files: ' + source.totalFiles : ''}
          ${source.error ? '<br><span style="color:var(--warning);">' + escapeHtml(source.error) + '</span>' : ''}
        </div>`;

      for (const det of (source.detections || [])) {
        html += `<div style="margin-top:8px;padding:8px 12px;background:var(--danger-bg);border-radius:var(--radius);border-left:3px solid var(--danger);">
          <strong>${escapeHtml(det.name || det.record || det.command || 'Unknown')}</strong><br>
          <span style="font-size:11px;color:var(--text-secondary);">
            ${det.originalPath ? 'Original: ' + escapeHtml(det.originalPath) + '<br>' : ''}
            ${det.deletedDate ? 'Deleted: ' + escapeHtml(det.deletedDate) + '<br>' : ''}
            ${det.lastRun ? 'Last run: ' + escapeHtml(det.lastRun) + '<br>' : ''}
            ${det.description ? escapeHtml(det.description) + '<br>' : ''}
          </span>
          <span class="detection-tag tag-${det.severity}">${det.severity}</span>
        </div>`;
      }

      html += '</div>';
    }

    html += '</div></div>';
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── String Scanner ──

async function scanStringsFolder() {
  if (isScanning) return;

  const dirPath = await window.sstools.selectFolder();
  if (!dirPath) return;

  setScanning(true);
  const container = document.getElementById('string-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning binaries...</h3></div>';

  try {
    const result = await window.sstools.scanStrings(dirPath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">String Scan Summary</div>
        <span class="result-badge ${data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.detectedFiles > 0 ? `${data.detectedFiles} DETECTED` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <table class="summary-table">
          <tr><th>Metric</th><th>Value</th></tr>
          <tr><td>Total files</td><td>${data.totalFiles}</td></tr>
          <tr><td>Binaries scanned</td><td>${data.scannedFiles}</td></tr>
          <tr><td>Detected</td><td>${data.detectedFiles}</td></tr>
        </table>
      </div>
    </div>`;

    for (const file of (data.files || [])) {
      if (file.status === 'detected') {
        html += `<div class="result-section">
          <div class="result-header" onclick="toggleResultBody(this)">
            <div class="result-title">${escapeHtml(file.file)}</div>
            <span class="result-badge badge-detected">${file.detections.length} issues</span>
          </div>
          <div class="result-body">
            <div class="detection-detail" style="margin-bottom:12px;">
              Size: ${formatBytes(file.size)} | Strings found: ${file.stringsFound}
            </div>
            ${file.detections.map(det => `
              <div class="detection-item severity-${det.severity}">
                <div class="detection-title">${escapeHtml(det.pattern)}</div>
                <div class="detection-detail">
                  ${escapeHtml(det.description)}
                  <span class="detection-tag tag-${det.severity}">${det.severity}</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>`;
      }
    }

    if (data.detectedFiles === 0) {
      html += renderEmptyState('All Clear', 'No suspicious strings found in scanned binaries.');
    }

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

async function scanBinaryFile() {
  if (isScanning) return;

  const filePath = await window.sstools.selectFile();
  if (!filePath) return;

  setScanning(true);
  const container = document.getElementById('string-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning binary...</h3></div>';

  try {
    const result = await window.sstools.scanBinary(filePath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">${escapeHtml(data.file)}</div>
        <span class="result-badge ${data.status === 'detected' ? 'badge-detected' : 'badge-clean'}">
          ${data.status.toUpperCase()}
        </span>
      </div>
      <div class="result-body">
        <div class="detection-detail" style="margin-bottom:12px;">
          Size: ${formatBytes(data.size)} | Strings found: ${data.stringsFound}
        </div>
        ${data.detections.map(det => `
          <div class="detection-item severity-${det.severity}">
            <div class="detection-title">${escapeHtml(det.pattern)}</div>
            <div class="detection-detail">
              ${escapeHtml(det.description)}
              <span class="detection-tag tag-${det.severity}">${det.severity}</span>
            </div>
          </div>
        `).join('')}
        ${data.detections.length === 0 ? '<p style="color:var(--success);">No suspicious patterns detected.</p>' : ''}
      </div>
    </div>`;

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── Launcher Detection ──

async function detectLaunchers() {
  if (isScanning) return;
  setScanning(true);

  const container = document.getElementById('launcher-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Detecting launchers...</h3></div>';

  try {
    const result = await window.sstools.detectLaunchers();
    if (!result.success) throw new Error(result.error);

    const launchers = result.data;
    updateStats(launchers.length);

    if (launchers.length === 0) {
      container.innerHTML = renderEmptyState('No Launchers Found', 'No Minecraft launchers were detected on this PC.');
      setScanning(false);
      return;
    }

    let html = '';
    for (const launcher of launchers) {
      html += `<div class="launcher-card">
        <div class="launcher-name">${escapeHtml(launcher.name)}</div>
        <div class="launcher-path">${escapeHtml(launcher.path)}</div>
        <div class="launcher-info">
          <div class="launcher-stat">
            <strong>${launcher.versions.length}</strong> versions/instances
          </div>
          <div class="launcher-stat">
            <strong>${launcher.modsLocations.length}</strong> mods folders
          </div>
          <div class="launcher-stat">
            <strong>${launcher.logsLocations.length}</strong> logs folders
          </div>
          <div class="launcher-stat">
            Version Isolation: <strong>${launcher.versionIsolation ? 'Yes' : 'No'}</strong>
          </div>
        </div>
        ${launcher.versions.length > 0 ? `
          <div style="margin-top:12px;">
            <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;">Versions/Instances:</div>
            ${launcher.versions.map(v => `
              <span style="display:inline-block;padding:3px 10px;background:var(--bg-input);border-radius:4px;font-size:11px;margin:2px 4px 2px 0;color:var(--text-primary);">${escapeHtml(v.name)}</span>
            `).join('')}
          </div>
        ` : ''}
        <div style="margin-top:12px;">
          ${launcher.modsLocations.map(m => `
            <button class="btn btn-secondary" style="margin:4px 4px 0 0;font-size:11px;padding:6px 12px;" onclick="scanSpecificMods('${escapeAttr(m.path)}')">
              Scan mods (${escapeHtml(m.version)})
            </button>
          `).join('')}
        </div>
      </div>`;
    }

    container.innerHTML = html;

    // Also update dashboard launcher results
    document.getElementById('dashboard-results').innerHTML = '';
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

async function scanSpecificMods(folderPath) {
  switchTab('mod-scanner');
  setScanning(true);

  const container = document.getElementById('mod-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning mods folder...</h3></div>';

  try {
    const result = await window.sstools.scanMods(folderPath);
    if (!result.success) throw new Error(result.error);

    const data = result.data;
    let html = `<div class="result-section">
      <div class="result-header">
        <div class="result-title">Scan: ${escapeHtml(folderPath)}</div>
        <span class="result-badge ${data.detectedFiles > 0 ? 'badge-detected' : 'badge-clean'}">
          ${data.detectedFiles > 0 ? `${data.detectedFiles} DETECTED` : 'CLEAN'}
        </span>
      </div>
      <div class="result-body">
        <p>Scanned ${data.scannedFiles} of ${data.totalFiles} files (${formatBytes(data.totalSize)})</p>
      </div>
    </div>`;

    for (const file of (data.files || [])) {
      if (file.status === 'detected') {
        html += `<div class="result-section">
          <div class="result-header" onclick="toggleResultBody(this)">
            <div class="result-title">${escapeHtml(file.file)}</div>
            <span class="result-badge badge-detected">DETECTED</span>
          </div>
          <div class="result-body">${renderDetections(file)}</div>
        </div>`;
      }
    }

    if (data.detectedFiles === 0) {
      html += renderEmptyState('All Clear', 'No cheat mods detected.');
    }

    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = renderError(err.message);
  }

  setScanning(false);
}

// ── Export Report ──

async function exportReport() {
  if (!lastScanResults) {
    alert('No scan results to export. Run a full scan first.');
    return;
  }

  try {
    const success = await window.sstools.exportReport(lastScanResults);
    if (success) {
      alert('Report exported successfully!');
    }
  } catch (err) {
    alert('Failed to export: ' + err.message);
  }
}

// ── Utility Renderers ──

function renderDetections(fileResult) {
  let html = '';
  for (const det of (fileResult.detections || [])) {
    const matches = det.matches || [];
    html += `<div style="margin-bottom:8px;">
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">
        Location: ${escapeHtml(det.location)} (${det.type || 'match'})
      </div>`;

    for (const match of matches) {
      html += `<span class="detection-tag tag-${match.severity}">${escapeHtml(match.keyword)}</span>`;
    }

    html += '</div>';
  }
  return html;
}

function renderResultSection(title, badgeClass, badgeText, bodyHtml) {
  return `<div class="result-section">
    <div class="result-header" onclick="toggleResultBody(this)">
      <div class="result-title">${title}</div>
      <span class="result-badge ${badgeClass}">${badgeText}</span>
    </div>
    <div class="result-body">${bodyHtml}</div>
  </div>`;
}

function renderEmptyState(title, description) {
  return `<div class="empty-state">
    <div class="empty-icon">&#x2705;</div>
    <h3>${title}</h3>
    <p>${description}</p>
  </div>`;
}

function renderError(message) {
  return `<div class="result-section">
    <div class="result-header">
      <div class="result-title" style="color:var(--danger);">Error</div>
      <span class="result-badge badge-detected">ERROR</span>
    </div>
    <div class="result-body">
      <p style="color:var(--danger);">${escapeHtml(message)}</p>
    </div>
  </div>`;
}

function toggleResultBody(headerEl) {
  const body = headerEl.nextElementSibling;
  if (body) {
    body.classList.toggle('collapsed');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}
