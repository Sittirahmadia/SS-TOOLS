/**
 * Report Generator Module
 * Generates detailed HTML reports after scans with:
 * - Summary statistics
 * - Detailed findings per scanner
 * - Severity breakdown
 * - Timestamp and system info
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Generate a complete HTML report from scan results
 */
function generateHTMLReport(scanData) {
  const timestamp = new Date().toISOString();
  const systemInfo = getSystemInfo();

  const totalDetections = scanData.totalDetections || 0;
  const overallStatus = totalDetections > 0 ? 'DETECTED' : 'CLEAN';
  const statusColor = totalDetections > 0 ? '#ff4757' : '#2ed573';

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SS-TOOLS Scan Report - ${timestamp}</title>
  <style>
    :root {
      --bg: #0a0a0f;
      --bg-card: #1a1a2e;
      --text: #e8e8f0;
      --text-secondary: #8888a0;
      --accent: #6c5ce7;
      --danger: #ff4757;
      --warning: #ffa502;
      --success: #2ed573;
      --border: #2a2a40;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 40px;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .header {
      text-align: center;
      padding: 40px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: var(--bg-card);
      margin-bottom: 30px;
    }
    .header h1 { font-size: 28px; color: var(--accent); margin-bottom: 8px; }
    .header .status {
      font-size: 36px;
      font-weight: 700;
      color: ${statusColor};
      margin: 16px 0;
    }
    .header .meta { color: var(--text-secondary); font-size: 13px; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .stat-value { font-size: 28px; font-weight: 700; color: var(--accent); }
    .stat-label { color: var(--text-secondary); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .section {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 20px;
      overflow: hidden;
    }
    .section-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .section-header h2 { font-size: 16px; }
    .badge {
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge-clean { background: rgba(46,213,115,0.15); color: var(--success); }
    .badge-detected { background: rgba(255,71,87,0.15); color: var(--danger); }
    .badge-warning { background: rgba(255,165,2,0.15); color: var(--warning); }
    .badge-info { background: rgba(108,92,231,0.15); color: var(--accent); }
    .section-body { padding: 16px 20px; }
    .detection-item {
      padding: 12px 16px;
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 8px;
      background: rgba(0,0,0,0.2);
    }
    .detection-item.critical { border-left: 3px solid var(--danger); }
    .detection-item.high { border-left: 3px solid var(--warning); }
    .detection-item.medium { border-left: 3px solid var(--accent); }
    .detection-title { font-weight: 600; margin-bottom: 4px; }
    .detection-detail { color: var(--text-secondary); font-size: 13px; }
    .severity-tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .severity-critical { background: rgba(255,71,87,0.2); color: var(--danger); }
    .severity-high { background: rgba(255,165,2,0.2); color: var(--warning); }
    .severity-medium { background: rgba(108,92,231,0.2); color: var(--accent); }
    .severity-low { background: rgba(136,136,160,0.2); color: var(--text-secondary); }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { color: var(--text-secondary); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
    .footer {
      text-align: center;
      padding: 30px;
      color: var(--text-secondary);
      font-size: 12px;
    }
    @media print {
      body { background: white; color: black; }
      .section, .stat-card, .header { border-color: #ddd; background: #f9f9f9; }
      .detection-item { background: #f0f0f0; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>SS-TOOLS - Minecraft Cheat Detection Report</h1>
      <div class="status">${overallStatus}</div>
      <div class="meta">
        Generated: ${timestamp}<br>
        Scan Duration: ${scanData.startTime && scanData.endTime ? calculateDuration(scanData.startTime, scanData.endTime) : 'N/A'}<br>
        System: ${systemInfo.os} | ${systemInfo.hostname}
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">${totalDetections}</div>
        <div class="stat-label">Total Detections</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${(scanData.launchers || []).length}</div>
        <div class="stat-label">Launchers Found</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${countModsScanned(scanData)}</div>
        <div class="stat-label">Mods Scanned</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${countProcessesScanned(scanData)}</div>
        <div class="stat-label">Processes Scanned</div>
      </div>
    </div>`;

  // Launchers section
  if (scanData.launchers && scanData.launchers.length > 0) {
    html += renderSection('Detected Launchers', 'info', `${scanData.launchers.length} found`,
      scanData.launchers.map(l => `
        <div class="detection-item medium">
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
  if (scanData.modScans && scanData.modScans.length > 0) {
    const modDetections = scanData.modScans.filter(s => s.detectedFiles > 0);
    html += renderSection('Mod Scanner Results',
      modDetections.length > 0 ? 'detected' : 'clean',
      modDetections.length > 0 ? `${modDetections.reduce((s, m) => s + m.detectedFiles, 0)} suspicious` : 'Clean',
      renderModScanResults(scanData.modScans)
    );
  }

  // JAR deep scan results
  if (scanData.jarScans && scanData.jarScans.length > 0) {
    const jarDetections = scanData.jarScans.filter(s => s.detectedJars > 0);
    html += renderSection('JAR Deep Scanner Results',
      jarDetections.length > 0 ? 'detected' : 'clean',
      jarDetections.length > 0 ? `${jarDetections.reduce((s, j) => s + j.detectedJars, 0)} suspicious JARs` : 'Clean',
      renderJarScanResults(scanData.jarScans)
    );
  }

  // Process scan results
  if (scanData.processScans) {
    const procDetections = (scanData.processScans.detections || []).length;
    html += renderSection('Process Scanner',
      procDetections > 0 ? 'detected' : 'clean',
      procDetections > 0 ? `${procDetections} found` : 'Clean',
      renderProcessResults(scanData.processScans)
    );
  }

  // DLL scan results
  if (scanData.dllScans) {
    html += renderSection('DLL Scanner',
      scanData.dllScans.totalDetections > 0 ? 'detected' : 'clean',
      scanData.dllScans.totalDetections > 0 ? `${scanData.dllScans.totalDetections} suspicious` : 'Clean',
      renderDLLResults(scanData.dllScans)
    );
  }

  // Mouse software results
  if (scanData.mouseScans) {
    html += renderSection('Mouse Software Scanner',
      scanData.mouseScans.totalDetections > 0 ? 'detected' : 'clean',
      scanData.mouseScans.totalDetections > 0 ? `${scanData.mouseScans.totalDetections} suspicious` : 'Clean',
      renderMouseResults(scanData.mouseScans)
    );
  }

  // Browser scan results
  if (scanData.browserScans) {
    html += renderSection('Browser Scanner',
      scanData.browserScans.totalDetections > 0 ? 'detected' : 'clean',
      scanData.browserScans.totalDetections > 0 ? `${scanData.browserScans.totalDetections} found` : 'Clean',
      renderBrowserResults(scanData.browserScans)
    );
  }

  // Kernel scan results
  if (scanData.kernelScans) {
    html += renderSection('Kernel Driver Scanner',
      scanData.kernelScans.totalDetections > 0 ? 'detected' : 'clean',
      scanData.kernelScans.totalDetections > 0 ? `${scanData.kernelScans.totalDetections} suspicious` : 'Clean',
      renderKernelResults(scanData.kernelScans)
    );
  }

  // Deleted file results
  if (scanData.deletedFileScans) {
    const delDetections = scanData.deletedFileScans.totalDetections || 0;
    html += renderSection('Deleted File Scanner',
      delDetections > 0 ? 'detected' : 'clean',
      delDetections > 0 ? `${delDetections} found` : 'Clean',
      renderDeletedFileResults(scanData.deletedFileScans)
    );
  }

  html += `
    <div class="footer">
      <p>SS-TOOLS v2.0.0 - Minecraft SS AntiCheat Scanner</p>
      <p>Report generated at ${timestamp}</p>
    </div>
  </div>
</body>
</html>`;

  return html;
}

// Helper functions for rendering sections

function renderSection(title, badgeType, badgeText, content) {
  return `
    <div class="section">
      <div class="section-header">
        <h2>${escapeHtml(title)}</h2>
        <span class="badge badge-${badgeType}">${escapeHtml(badgeText)}</span>
      </div>
      <div class="section-body">
        ${content}
      </div>
    </div>`;
}

function renderModScanResults(modScans) {
  let html = '';
  for (const scan of modScans) {
    html += `<div class="detection-item ${scan.detectedFiles > 0 ? 'critical' : 'medium'}">
      <div class="detection-title">[${escapeHtml(scan.launcher || 'Unknown')}] ${escapeHtml(scan.version || 'default')}</div>
      <div class="detection-detail">
        Folder: ${escapeHtml(scan.folder || '')}<br>
        Files: ${scan.totalFiles || 0} | Scanned: ${scan.scannedFiles || 0} | Detected: ${scan.detectedFiles || 0}
      </div>`;

    if (scan.files) {
      for (const file of scan.files) {
        if (file.status === 'detected') {
          html += `<div class="detection-item high" style="margin-top:8px;margin-left:16px;">
            <div class="detection-title">${escapeHtml(file.file)}</div>`;
          for (const det of (file.detections || [])) {
            for (const match of (det.matches || [])) {
              html += `<div class="detection-detail">
                <span class="severity-tag severity-${match.severity}">${match.severity}</span>
                ${escapeHtml(match.keyword)} (${escapeHtml(match.category)})
              </div>`;
            }
          }
          html += '</div>';
        }
      }
    }
    html += '</div>';
  }
  return html;
}

function renderJarScanResults(jarScans) {
  let html = '';
  for (const scan of jarScans) {
    html += `<div class="detection-item medium">
      <div class="detection-title">Directory: ${escapeHtml(scan.directory || '')}</div>
      <div class="detection-detail">Total JARs: ${scan.totalJars} | Scanned: ${scan.scannedJars} | Detected: ${scan.detectedJars} | Suspicious: ${scan.suspiciousJars}</div>`;

    for (const jar of (scan.jars || [])) {
      if (jar.status === 'detected' || jar.status === 'suspicious') {
        html += `<div class="detection-item ${jar.status === 'detected' ? 'critical' : 'high'}" style="margin-top:8px;margin-left:16px;">
          <div class="detection-title">${escapeHtml(jar.file)}</div>
          <div class="detection-detail">
            Size: ${formatBytes(jar.size)} | Classes scanned: ${jar.classFilesScanned || 0} | 
            Suspicious classes: ${jar.suspiciousClassCount || 0}
          </div>`;
        for (const det of (jar.detections || []).slice(0, 20)) {
          html += `<div class="detection-detail">
            <span class="severity-tag severity-${det.severity}">${det.severity}</span>
            ${escapeHtml(det.description)} ${det.location ? `(${escapeHtml(det.location)})` : ''}
          </div>`;
        }
        if ((jar.detections || []).length > 20) {
          html += `<div class="detection-detail">... and ${jar.detections.length - 20} more detections</div>`;
        }
        html += '</div>';
      }
    }
    html += '</div>';
  }
  return html;
}

function renderProcessResults(processScans) {
  if (!processScans) return '<p>No data</p>';
  let html = `<p>Total processes scanned: ${processScans.totalProcesses || 0}</p>`;
  for (const det of (processScans.detections || [])) {
    html += `<div class="detection-item critical">
      <div class="detection-title">${escapeHtml(det.processName || det.description)}</div>
      <div class="detection-detail">
        PID: ${det.pid || 'N/A'} |
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  return html;
}

function renderDLLResults(dllScans) {
  if (!dllScans) return '<p>No data</p>';
  let html = `<p>Processes scanned: ${dllScans.totalProcesses || 0} | Total DLLs: ${dllScans.totalDLLs || 0}</p>`;
  for (const det of (dllScans.suspiciousDLLs || [])) {
    html += `<div class="detection-item critical">
      <div class="detection-title">${escapeHtml(det.dll || '')}</div>
      <div class="detection-detail">
        Process: ${escapeHtml(det.processName || '')} (PID: ${det.pid || 'N/A'}) |
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }
  return html;
}

function renderMouseResults(mouseScans) {
  if (!mouseScans) return '<p>No data</p>';
  let html = '';
  for (const sw of (mouseScans.detectedSoftware || [])) {
    html += `<div class="detection-item ${sw.isLegitimate ? 'medium' : 'critical'}">
      <div class="detection-title">${escapeHtml(sw.name)} ${sw.running ? '(Running)' : '(Installed)'}</div>
      <div class="detection-detail">
        ${sw.isLegitimate ? 'Legitimate software' : 'Suspicious software'} |
        Install: ${escapeHtml(sw.installPath || 'N/A')} |
        Macro detections: ${sw.macroDetections.length}
      </div>`;
    for (const det of (sw.macroDetections || [])) {
      html += `<div class="detection-detail">
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)}
      </div>`;
    }
    html += '</div>';
  }
  return html || '<p>No mouse software detected</p>';
}

function renderBrowserResults(browserScans) {
  if (!browserScans) return '<p>No data</p>';
  let html = '';
  for (const browser of (browserScans.browsers || [])) {
    if (!browser.installed) continue;
    html += `<div class="detection-item ${browser.totalDetections > 0 ? 'high' : 'medium'}">
      <div class="detection-title">${escapeHtml(browser.name)} ${browser.totalDetections > 0 ? `(${browser.totalDetections} findings)` : '(Clean)'}</div>`;
    for (const det of (browser.detections || []).slice(0, 20)) {
      html += `<div class="detection-detail">
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        [${det.type}] ${escapeHtml(det.value || det.name || '')}
      </div>`;
    }
    html += '</div>';
  }
  return html || '<p>No browsers scanned</p>';
}

function renderKernelResults(kernelScans) {
  if (!kernelScans) return '<p>No data</p>';
  let html = `<p>Loaded drivers: ${(kernelScans.loadedDrivers || []).length} | Filter drivers: ${(kernelScans.filterDrivers || []).length}</p>`;
  
  for (const det of (kernelScans.suspiciousDrivers || [])) {
    html += `<div class="detection-item critical">
      <div class="detection-title">${escapeHtml(det.moduleName || det.displayName || '')}</div>
      <div class="detection-detail">
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.matchDescription || det.description || '')}
        ${det.source ? `(Source: ${det.source})` : ''}
      </div>
    </div>`;
  }

  for (const det of (kernelScans.driverFileScans || [])) {
    html += `<div class="detection-item critical">
      <div class="detection-title">${escapeHtml(det.file || '')}</div>
      <div class="detection-detail">
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.description)} | Path: ${escapeHtml(det.path || '')}
      </div>
    </div>`;
  }

  for (const det of (kernelScans.hiddenProcesses || [])) {
    html += `<div class="detection-item critical">
      <div class="detection-title">Hidden Process (PID: ${det.pid})</div>
      <div class="detection-detail">
        <span class="severity-tag severity-critical">critical</span>
        ${escapeHtml(det.description)}
      </div>
    </div>`;
  }

  return html;
}

function renderDeletedFileResults(deletedScans) {
  if (!deletedScans) return '<p>No data</p>';
  let html = '';
  for (const source of (deletedScans.sources || [])) {
    html += `<div class="detection-item ${source.detections && source.detections.length > 0 ? 'high' : 'medium'}">
      <div class="detection-title">[${escapeHtml(source.source)}] Status: ${escapeHtml(source.status)}</div>`;
    for (const det of (source.detections || [])) {
      html += `<div class="detection-detail">
        <span class="severity-tag severity-${det.severity}">${det.severity}</span>
        ${escapeHtml(det.name || det.record || det.command || 'Unknown')}
      </div>`;
    }
    html += '</div>';
  }
  return html;
}

// Utility functions

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

function calculateDuration(start, end) {
  const ms = new Date(end) - new Date(start);
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function getSystemInfo() {
  return {
    os: `${os.type()} ${os.release()}`,
    hostname: os.hostname(),
    arch: os.arch(),
    cpus: os.cpus().length,
    memory: formatBytes(os.totalmem())
  };
}

function countModsScanned(data) {
  return (data.modScans || []).reduce((sum, s) => sum + (s.scannedFiles || 0), 0);
}

function countProcessesScanned(data) {
  return data.processScans ? (data.processScans.totalProcesses || 0) : 0;
}

/**
 * Generate a plain text report
 */
function generateTextReport(scanData) {
  let text = '='.repeat(60) + '\n';
  text += '          SS-TOOLS v2.0 SCAN REPORT\n';
  text += '='.repeat(60) + '\n\n';
  text += `Scan Time: ${scanData.startTime || new Date().toISOString()}\n`;
  text += `Status: ${(scanData.overallStatus || 'unknown').toUpperCase()}\n`;
  text += `Total Detections: ${scanData.totalDetections || 0}\n\n`;

  if (scanData.launchers && scanData.launchers.length > 0) {
    text += '-- Detected Launchers --\n';
    for (const l of scanData.launchers) {
      text += `  * ${l.name} (${l.path})\n`;
      text += `    Versions: ${(l.versions || []).length} | Mods folders: ${(l.modsLocations || []).length}\n`;
    }
    text += '\n';
  }

  if (scanData.modScans) {
    text += '-- Mod Scan Results --\n';
    for (const scan of scanData.modScans) {
      text += `  [${scan.launcher || 'Unknown'}] ${scan.folder || ''}\n`;
      text += `    Files: ${scan.totalFiles} | Scanned: ${scan.scannedFiles} | Detected: ${scan.detectedFiles}\n`;
      for (const file of (scan.files || [])) {
        if (file.status === 'detected') {
          text += `    ! ${file.file}\n`;
          for (const det of (file.detections || [])) {
            for (const match of (det.matches || [])) {
              text += `      -> ${match.keyword} (${match.category}, ${match.severity})\n`;
            }
          }
        }
      }
    }
    text += '\n';
  }

  if (scanData.processScans && scanData.processScans.detections) {
    text += '-- Process Scan Results --\n';
    for (const det of scanData.processScans.detections) {
      text += `  ! ${det.processName || det.description} (PID: ${det.pid || 'N/A'})\n`;
      text += `    ${det.description} -- Severity: ${det.severity}\n`;
    }
    text += '\n';
  }

  if (scanData.mouseScans && scanData.mouseScans.detectedSoftware) {
    text += '-- Mouse Software Results --\n';
    for (const sw of scanData.mouseScans.detectedSoftware) {
      text += `  ${sw.name} (${sw.running ? 'Running' : 'Installed'})\n`;
      for (const det of (sw.macroDetections || [])) {
        text += `    ! ${det.description} [${det.severity}]\n`;
      }
    }
    text += '\n';
  }

  if (scanData.browserScans && scanData.browserScans.browsers) {
    text += '-- Browser Scan Results --\n';
    for (const browser of scanData.browserScans.browsers) {
      if (!browser.installed) continue;
      text += `  ${browser.name}: ${browser.totalDetections > 0 ? browser.totalDetections + ' findings' : 'Clean'}\n`;
      for (const det of (browser.detections || []).slice(0, 10)) {
        text += `    ! [${det.type}] ${det.value || det.name || ''}\n`;
      }
    }
    text += '\n';
  }

  if (scanData.kernelScans) {
    text += '-- Kernel Driver Results --\n';
    for (const det of (scanData.kernelScans.suspiciousDrivers || [])) {
      text += `  ! ${det.moduleName || ''} -- ${det.matchDescription || ''} [${det.severity}]\n`;
    }
    text += '\n';
  }

  if (scanData.deletedFileScans && scanData.deletedFileScans.sources) {
    text += '-- Deleted File Results --\n';
    for (const source of scanData.deletedFileScans.sources) {
      text += `  [${source.source}] Status: ${source.status}\n`;
      for (const det of (source.detections || [])) {
        text += `    ! ${det.name || det.record || 'Unknown'}\n`;
      }
    }
    text += '\n';
  }

  text += '='.repeat(60) + '\n';
  text += '         Generated by SS-TOOLS v2.0\n';
  text += '='.repeat(60) + '\n';

  return text;
}

module.exports = {
  generateHTMLReport,
  generateTextReport,
  escapeHtml,
  formatBytes
};
