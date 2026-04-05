/**
 * SS-TOOLS Web Scanner
 * Client-side scanning for the web version
 * Runs entirely in the browser — no server needed
 */

// ── Load cheat signatures ──
let cheatKeywords = null;

async function loadKeywords() {
  try {
    const response = await fetch('../cheat-signatures/keywords.json');
    cheatKeywords = await response.json();
  } catch (err) {
    // Fallback: embedded minimal keywords
    cheatKeywords = getEmbeddedKeywords();
  }
}

function getEmbeddedKeywords() {
  return {
    categories: {
      crystal_pvp: {
        name: "Crystal PvP Cheats", severity: "high",
        keywords: ["AutoCrystal","CrystalAura","AnchorMacro","AnchorAura","BedAura","CevBreak","AutoCity","HoleFill","PistonCrystal"]
      },
      sword_pvp: {
        name: "Sword PvP Cheats", severity: "high",
        keywords: ["KillAura","AimAssist","AimBot","Triggerbot","TriggerBot","AutoClicker","Reach","HitBox","Velocity","AntiKnockback","AntiKB","Criticals","WTap","BackTrack"]
      },
      movement: {
        name: "Movement Cheats", severity: "high",
        keywords: ["SpeedHack","FlyHack","NoFall","NoSlow","Spider","Phase","NoClip","Teleport","PacketFly","Scaffold"]
      },
      client_indicators: {
        name: "Client Indicators", severity: "critical",
        keywords: ["booleansetting","clickGUI","ClickGui","HudEditor","ModuleManager","CheatModule","HackModule","ModuleCategory"]
      },
      known_clients: {
        name: "Known Cheat Clients", severity: "critical",
        keywords: ["WurstClient","ImpactClient","MeteorClient","meteor-client","Aristois","RusherHack","LambdaClient","FutureClient","ThunderHack","BleachHack","GameSense","3arthh4ck","KonasClient"]
      },
      macro_tools: {
        name: "Macro/Injection Tools", severity: "critical",
        keywords: ["198macro","198Macro","zenithmacro","ZenithMacro","CrystalSpKMacro","injector","Injector","DLLInjector","LoadLibrary","CreateRemoteThread","WriteProcessMemory"]
      }
    }
  };
}

// Initialize keywords on page load
loadKeywords();

// ── Keyword Scanning ──

function getAllKeywordsFlat() {
  if (!cheatKeywords) return [];
  const result = [];
  for (const [catId, cat] of Object.entries(cheatKeywords.categories)) {
    for (const kw of cat.keywords) {
      result.push({ keyword: kw, category: cat.name, severity: cat.severity });
    }
  }
  return result;
}

function scanTextForKeywords(text) {
  const keywords = getAllKeywordsFlat();
  const matches = [];
  const textLower = text.toLowerCase();
  const seen = new Set();

  for (const entry of keywords) {
    const kwLower = entry.keyword.toLowerCase();
    if (textLower.includes(kwLower)) {
      // Short keyword check
      if (entry.keyword.length <= 4 && !text.includes(entry.keyword)) continue;
      const key = `${entry.keyword}:${entry.category}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push(entry);
    }
  }
  return matches;
}

// ── Log Patterns ──

const LOG_PATTERNS = [
  { pattern: /\[Client thread\/INFO\].*(?:hack|cheat|exploit|inject)/i, severity: 'critical', description: 'Cheat client initialization detected' },
  { pattern: /Loading\s+(?:mod|module).*(?:hack|cheat|aura|aimbot|triggerbot|crystal)/i, severity: 'critical', description: 'Cheat mod loading detected' },
  { pattern: /\[Wurst\]/i, severity: 'critical', description: 'Wurst client detected' },
  { pattern: /\[MeteorClient\]/i, severity: 'critical', description: 'Meteor client detected' },
  { pattern: /\[Aristois\]/i, severity: 'critical', description: 'Aristois client detected' },
  { pattern: /\[RusherHack\]/i, severity: 'critical', description: 'RusherHack client detected' },
  { pattern: /\[ThunderHack\]/i, severity: 'critical', description: 'ThunderHack client detected' },
  { pattern: /\[BleachHack\]/i, severity: 'critical', description: 'BleachHack client detected' },
  { pattern: /(?:Enabled|Toggled|Activated)\s+(?:KillAura|AimAssist|Triggerbot|AutoCrystal|CrystalAura|Reach|Velocity|AntiKB|NoFall|Speed|Fly|Scaffold)/i, severity: 'critical', description: 'Cheat module toggle detected' }
];

// ── Binary Patterns ──

const BINARY_PATTERNS = [
  { pattern: 'LoadLibraryA', severity: 'high', description: 'DLL loading function' },
  { pattern: 'CreateRemoteThread', severity: 'critical', description: 'Remote thread injection' },
  { pattern: 'WriteProcessMemory', severity: 'critical', description: 'Process memory write' },
  { pattern: 'ReadProcessMemory', severity: 'high', description: 'Process memory read' },
  { pattern: 'NtWriteVirtualMemory', severity: 'critical', description: 'NT virtual memory write' },
  { pattern: 'VirtualAllocEx', severity: 'high', description: 'Remote virtual memory allocation' },
  { pattern: '198macro', severity: 'critical', description: '198Macro reference' },
  { pattern: 'zenithmacro', severity: 'critical', description: 'ZenithMacro reference' },
  { pattern: 'autocrystal', severity: 'critical', description: 'AutoCrystal reference' },
  { pattern: 'aimassist', severity: 'critical', description: 'AimAssist reference' },
  { pattern: 'triggerbot', severity: 'critical', description: 'Triggerbot reference' },
  { pattern: 'killaura', severity: 'critical', description: 'KillAura reference' }
];

// ── File Processing ──

const MAX_UPLOAD = 500 * 1024 * 1024; // 500MB

async function processModFiles(fileList) {
  const container = document.getElementById('web-mod-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning mod files...</h3></div>';

  const results = [];
  let totalSize = 0;

  for (const file of fileList) {
    totalSize += file.size;
    if (totalSize > MAX_UPLOAD) {
      container.innerHTML = renderError('Total upload exceeds 500MB limit.');
      return;
    }

    try {
      const arrayBuffer = await file.arrayBuffer();
      const result = await scanZipBuffer(file.name, arrayBuffer);
      results.push(result);
    } catch (err) {
      results.push({ file: file.name, status: 'error', error: err.message, detections: [] });
    }
  }

  renderModResults(container, results);
}

async function scanZipBuffer(filename, arrayBuffer) {
  const result = {
    file: filename,
    size: arrayBuffer.byteLength,
    detections: [],
    scannedEntries: 0,
    status: 'clean'
  };

  try {
    // Use JSZip-like approach — extract strings from the archive
    const uint8 = new Uint8Array(arrayBuffer);
    const text = extractStringsFromUint8(uint8);

    // Scan filename
    const nameMatches = scanTextForKeywords(filename);
    if (nameMatches.length > 0) {
      result.detections.push({ location: 'filename', type: 'filename', matches: nameMatches });
    }

    // Scan extracted strings
    const contentMatches = scanTextForKeywords(text);
    if (contentMatches.length > 0) {
      result.detections.push({ location: 'archive content', type: 'content', matches: contentMatches });
    }

    if (result.detections.length > 0) {
      result.status = 'detected';
    }
  } catch (err) {
    result.status = 'error';
    result.error = err.message;
  }

  return result;
}

function extractStringsFromUint8(uint8, minLen = 4) {
  const strings = [];
  let current = '';

  for (let i = 0; i < uint8.length; i++) {
    const b = uint8[i];
    if (b >= 32 && b < 127) {
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) strings.push(current);
      current = '';
    }
  }
  if (current.length >= minLen) strings.push(current);

  return strings.join(' ');
}

async function processBinaryFiles(fileList) {
  const container = document.getElementById('web-binary-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning binary files...</h3></div>';

  const results = [];
  let totalSize = 0;

  for (const file of fileList) {
    totalSize += file.size;
    if (totalSize > MAX_UPLOAD) {
      container.innerHTML = renderError('Total upload exceeds 500MB limit.');
      return;
    }

    try {
      const arrayBuffer = await file.arrayBuffer();
      const uint8 = new Uint8Array(arrayBuffer);
      const text = extractStringsFromUint8(uint8);

      const result = { file: file.name, size: file.size, detections: [], stringsFound: 0, status: 'clean' };

      // Count strings
      result.stringsFound = text.split(' ').length;

      // Check binary patterns
      const textLower = text.toLowerCase();
      for (const pat of BINARY_PATTERNS) {
        if (textLower.includes(pat.pattern.toLowerCase())) {
          result.detections.push({ pattern: pat.pattern, description: pat.description, severity: pat.severity });
        }
      }

      // Check cheat keywords
      const kwMatches = scanTextForKeywords(text);
      for (const m of kwMatches) {
        result.detections.push({ pattern: m.keyword, description: `Cheat keyword: ${m.category}`, severity: m.severity });
      }

      result.status = result.detections.length > 0 ? 'detected' : 'clean';
      results.push(result);
    } catch (err) {
      results.push({ file: file.name, status: 'error', error: err.message, detections: [] });
    }
  }

  renderBinaryResults(container, results);
}

async function processLogFiles(fileList) {
  const container = document.getElementById('web-log-results');
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div><h3>Scanning log files...</h3></div>';

  const results = [];

  for (const file of fileList) {
    if (file.size > 50 * 1024 * 1024) {
      results.push({ file: file.name, status: 'skipped', error: 'File too large (>50MB)', detections: [] });
      continue;
    }

    try {
      const text = await file.text();
      const lines = text.split('\n');
      const result = { file: file.name, size: file.size, linesScanned: lines.length, detections: [], status: 'clean' };

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        for (const pat of LOG_PATTERNS) {
          if (pat.pattern.test(line)) {
            result.detections.push({
              line: i + 1,
              content: line.trim().substring(0, 200),
              description: pat.description,
              severity: pat.severity
            });
          }
        }

        const kwMatches = scanTextForKeywords(line);
        const critical = kwMatches.filter(m => m.severity === 'critical');
        if (critical.length > 0 || kwMatches.length >= 2) {
          result.detections.push({
            line: i + 1,
            content: line.trim().substring(0, 200),
            description: 'Cheat keyword in log',
            severity: critical.length > 0 ? 'critical' : 'high',
            keywords: kwMatches.map(m => m.keyword)
          });
        }
      }

      result.status = result.detections.length > 0 ? 'detected' : 'clean';
      results.push(result);
    } catch (err) {
      results.push({ file: file.name, status: 'error', error: err.message, detections: [] });
    }
  }

  renderLogResults(container, results);
}

// ── Renderers ──

function renderModResults(container, results) {
  const detected = results.filter(r => r.status === 'detected');
  let html = `<div class="result-section">
    <div class="result-header">
      <div class="result-title">Mod Scan Results</div>
      <span class="result-badge ${detected.length > 0 ? 'badge-detected' : 'badge-clean'}">
        ${detected.length > 0 ? detected.length + ' DETECTED' : 'CLEAN'}
      </span>
    </div>
    <div class="result-body">
      <p>Scanned ${results.length} file(s)</p>
    </div>
  </div>`;

  for (const r of results) {
    if (r.status === 'detected') {
      html += `<div class="result-section">
        <div class="result-header">
          <div class="result-title">${esc(r.file)}</div>
          <span class="result-badge badge-detected">DETECTED</span>
        </div>
        <div class="result-body">
          <p style="margin-bottom:8px;">Size: ${formatBytes(r.size)}</p>
          ${renderWebDetections(r.detections)}
        </div>
      </div>`;
    } else if (r.status === 'error') {
      html += `<div class="result-section">
        <div class="result-header">
          <div class="result-title">${esc(r.file)}</div>
          <span class="result-badge badge-warning">ERROR</span>
        </div>
        <div class="result-body"><p style="color:var(--warning);">${esc(r.error)}</p></div>
      </div>`;
    }
  }

  container.innerHTML = html;
}

function renderBinaryResults(container, results) {
  const detected = results.filter(r => r.status === 'detected');
  let html = `<div class="result-section">
    <div class="result-header">
      <div class="result-title">Binary Scan Results</div>
      <span class="result-badge ${detected.length > 0 ? 'badge-detected' : 'badge-clean'}">
        ${detected.length > 0 ? detected.length + ' DETECTED' : 'CLEAN'}
      </span>
    </div>
    <div class="result-body"><p>Scanned ${results.length} file(s)</p></div>
  </div>`;

  for (const r of results) {
    if (r.status === 'detected') {
      html += `<div class="result-section">
        <div class="result-header">
          <div class="result-title">${esc(r.file)}</div>
          <span class="result-badge badge-detected">${r.detections.length} issues</span>
        </div>
        <div class="result-body">
          <p style="margin-bottom:8px;">Size: ${formatBytes(r.size)} | Strings: ${r.stringsFound}</p>
          ${r.detections.map(d => `
            <div class="detection-item severity-${d.severity}">
              <div class="detection-title">${esc(d.pattern)}</div>
              <div class="detection-detail">${esc(d.description)}
                <span class="detection-tag tag-${d.severity}">${d.severity}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>`;
    }
  }

  if (detected.length === 0 && results.length > 0) {
    html += '<div class="empty-state"><h3>All Clear</h3><p>No suspicious patterns found.</p></div>';
  }

  container.innerHTML = html;
}

function renderLogResults(container, results) {
  const detected = results.filter(r => r.status === 'detected');
  let html = `<div class="result-section">
    <div class="result-header">
      <div class="result-title">Log Scan Results</div>
      <span class="result-badge ${detected.length > 0 ? 'badge-detected' : 'badge-clean'}">
        ${detected.length > 0 ? detected.length + ' DETECTED' : 'CLEAN'}
      </span>
    </div>
    <div class="result-body"><p>Scanned ${results.length} file(s)</p></div>
  </div>`;

  for (const r of results) {
    if (r.status === 'detected') {
      html += `<div class="result-section">
        <div class="result-header">
          <div class="result-title">${esc(r.file)}</div>
          <span class="result-badge badge-detected">${r.detections.length} issues</span>
        </div>
        <div class="result-body">
          <p style="margin-bottom:8px;">Lines: ${r.linesScanned}</p>
          ${r.detections.map(d => `
            <div class="detection-item severity-${d.severity}">
              <div class="detection-title">Line ${d.line}: ${esc(d.description)}</div>
              <div class="detection-detail">
                <code style="font-size:11px;color:var(--text-muted);">${esc(d.content)}</code>
                ${d.keywords ? '<br>' + d.keywords.map(k => `<span class="detection-tag tag-critical">${esc(k)}</span>`).join('') : ''}
                <span class="detection-tag tag-${d.severity}">${d.severity}</span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>`;
    }
  }

  if (detected.length === 0 && results.length > 0) {
    html += '<div class="empty-state"><h3>All Clear</h3><p>No cheat indicators found in logs.</p></div>';
  }

  container.innerHTML = html;
}

function renderWebDetections(detections) {
  return detections.map(det => {
    const matches = det.matches || [];
    return `<div style="margin-bottom:8px;">
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px;">
        Location: ${esc(det.location)} (${det.type || 'match'})
      </div>
      ${matches.map(m => `<span class="detection-tag tag-${m.severity}">${esc(m.keyword)}</span>`).join('')}
    </div>`;
  }).join('');
}

function renderError(message) {
  return `<div class="result-section">
    <div class="result-header">
      <div class="result-title" style="color:var(--danger);">Error</div>
      <span class="result-badge badge-detected">ERROR</span>
    </div>
    <div class="result-body"><p style="color:var(--danger);">${esc(message)}</p></div>
  </div>`;
}

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const s = ['B','KB','MB','GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + s[i];
}
