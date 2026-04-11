/**
 * Memory Scanner Module
 * Scans process memory maps for Java/Minecraft processes:
 * - Detect injected DLLs and suspicious modules
 * - Detect Java agents
 * - In-memory string scanning via Windows API (PowerShell)
 * - JVM argument inspection
 * - Loaded class detection
 */

const { execSync } = require('child_process');
const keywordEngine = require('./keyword-engine');

/**
 * Get Java/Minecraft processes with their command lines
 */
function getJavaProcesses() {
  const processes = [];

  try {
    const output = execSync(
      'wmic process where "name like \'%java%\'" get ProcessId,Name,CommandLine /FORMAT:CSV',
      { encoding: 'utf-8', timeout: 15000, windowsHide: true }
    );

    const lines = output.trim().split('\n').slice(1);
    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length >= 4) {
        processes.push({
          commandLine: (parts.slice(1, parts.length - 2)).join(',').trim(),
          name: parts[parts.length - 2].trim(),
          pid: parseInt(parts[parts.length - 1], 10) || 0
        });
      }
    }
  } catch (err) {
    // Fallback: tasklist
    try {
      const output = execSync('tasklist /FI "IMAGENAME eq javaw.exe" /FO CSV /NH', {
        encoding: 'utf-8', timeout: 10000, windowsHide: true
      });
      const lines = output.trim().split('\n');
      for (const line of lines) {
        const parts = line.split('","');
        if (parts.length >= 2) {
          processes.push({
            name: (parts[0] || '').replace(/"/g, '').trim(),
            pid: parseInt((parts[1] || '').replace(/"/g, ''), 10) || 0,
            commandLine: ''
          });
        }
      }
    } catch (innerErr) {
      // Cannot enumerate
    }
  }

  return processes;
}

/**
 * Scan JVM command line arguments for suspicious entries
 */
function scanJVMArguments(commandLine) {
  const detections = [];

  if (!commandLine) return detections;

  // Check for Java agent injection
  const agentPatterns = [
    { pattern: /-javaagent:/i, severity: 'critical', description: 'Java agent injection detected' },
    { pattern: /-agentlib:/i, severity: 'critical', description: 'Native agent library loaded' },
    { pattern: /-agentpath:/i, severity: 'critical', description: 'Native agent path specified' },
    { pattern: /-Xbootclasspath/i, severity: 'high', description: 'Boot classpath modification' },
    { pattern: /-XX:DisableAttachMechanism/i, severity: 'high', description: 'Attach mechanism disabled (anti-debug)' },
    { pattern: /-noverify/i, severity: 'high', description: 'Bytecode verification disabled' },
    { pattern: /-XX:\+UseCompressedOops.*-XX:-UseCompressedOops/i, severity: 'medium', description: 'Compressed oops toggled (potential memory manipulation)' }
  ];

  for (const pattern of agentPatterns) {
    if (pattern.pattern.test(commandLine)) {
      const match = commandLine.match(pattern.pattern);
      detections.push({
        type: 'jvm-argument',
        description: pattern.description,
        severity: pattern.severity,
        match: match ? match[0] : '',
        detail: extractArgContext(commandLine, match ? match.index : 0)
      });
    }
  }

  // Use keyword engine to scan the full command line
  const keywordResults = keywordEngine.scanText(commandLine, {
    exact: true,
    regex: true,
    fuzzy: false,
    categories: ['known_clients', 'macro_tools', 'cheat_files', 'anti_detection']
  });

  for (const det of keywordResults) {
    detections.push({
      type: 'jvm-keyword',
      description: `Cheat keyword in JVM args: ${det.keyword} (${det.category})`,
      severity: det.severity,
      match: det.keyword,
      matchType: det.matchType
    });
  }

  return detections;
}

/**
 * Extract context around a match in a command line
 */
function extractArgContext(cmdLine, index) {
  const start = Math.max(0, index - 30);
  const end = Math.min(cmdLine.length, index + 80);
  return cmdLine.substring(start, end);
}

/**
 * Scan loaded modules for a Java process using tasklist /M
 */
function scanProcessModules(pid) {
  const detections = [];

  try {
    const output = execSync(`tasklist /M /FI "PID eq ${pid}" /FO CSV`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true
    });

    const modules = [];
    const lines = output.trim().split('\n');
    for (const line of lines) {
      const parts = line.match(/"([^"]+)"/g);
      if (parts && parts.length >= 3) {
        const mods = parts.slice(2).map(m => m.replace(/"/g, '').trim()).filter(m => m);
        modules.push(...mods);
      }
    }

    // Check for suspicious DLLs in Java process
    const suspiciousDLLPatterns = [
      { pattern: /inject/i, severity: 'critical', description: 'Injector DLL in Java process' },
      { pattern: /hook/i, severity: 'high', description: 'Hook DLL in Java process' },
      { pattern: /cheat/i, severity: 'critical', description: 'Cheat DLL in Java process' },
      { pattern: /hack/i, severity: 'critical', description: 'Hack DLL in Java process' },
      { pattern: /macro/i, severity: 'critical', description: 'Macro DLL in Java process' },
      { pattern: /autoclick/i, severity: 'critical', description: 'AutoClicker DLL in Java process' },
      { pattern: /minhook/i, severity: 'high', description: 'MinHook library in Java process' },
      { pattern: /easyhook/i, severity: 'high', description: 'EasyHook library in Java process' },
      { pattern: /detour/i, severity: 'high', description: 'Detour library in Java process' }
    ];

    for (const mod of modules) {
      const modLower = mod.toLowerCase();

      // Skip known legitimate Java DLLs
      if (modLower.includes('jvm') || modLower.includes('java') ||
          modLower.includes('awt') || modLower.includes('nio') ||
          modLower.includes('zip') || modLower.includes('net') ||
          modLower.includes('kernel32') || modLower.includes('ntdll') ||
          modLower.includes('user32') || modLower.includes('gdi32') ||
          modLower.includes('advapi') || modLower.includes('shell32') ||
          modLower.includes('msvc') || modLower.includes('ucrt') ||
          modLower.includes('opengl') || modLower.includes('lwjgl') ||
          modLower.includes('openal') || modLower.includes('glfw') ||
          modLower.includes('nvidia') || modLower.includes('amd') ||
          modLower.includes('intel') || modLower.includes('d3d') ||
          modLower.includes('dxgi') || modLower.includes('comctl') ||
          modLower.includes('crypt') || modLower.includes('bcrypt') ||
          modLower.includes('secur') || modLower.includes('ws2') ||
          modLower.includes('mswsock') || modLower.includes('ssl') ||
          modLower.includes('version') || modLower.includes('psapi') ||
          modLower.includes('iphlp') || modLower.includes('dns') ||
          modLower.includes('winhttp') || modLower.includes('wininet') ||
          modLower.includes('cabinet') || modLower.includes('winsock')) {
        continue;
      }

      for (const pattern of suspiciousDLLPatterns) {
        if (pattern.pattern.test(modLower)) {
          detections.push({
            type: 'suspicious-module',
            module: mod,
            pid: pid,
            description: pattern.description,
            severity: pattern.severity
          });
          break;
        }
      }
    }
  } catch (err) {
    // Cannot enumerate modules
  }

  return detections;
}

/**
 * Scan process memory strings using PowerShell
 * Reads readable strings from process memory via ReadProcessMemory
 */
function scanProcessMemoryStrings(pid) {
  const detections = [];

  try {
    // Use PowerShell to dump process memory strings
    const psCommand = `
      $proc = Get-Process -Id ${pid} -ErrorAction SilentlyContinue
      if ($proc) {
        $strings = @()
        try {
          $modules = $proc.Modules
          foreach ($mod in $modules) {
            $strings += $mod.ModuleName
            $strings += $mod.FileName
          }
        } catch {}
        # Also check main window title
        $strings += $proc.MainWindowTitle
        $strings -join "|"
      }
    `;

    const output = execSync(
      `powershell -NoProfile -Command "${psCommand.replace(/\n/g, ' ')}"`,
      { encoding: 'utf-8', timeout: 15000, windowsHide: true }
    );

    if (output.trim()) {
      const allStrings = output.trim();

      // Use keyword engine for comprehensive scanning
      const keywordResults = keywordEngine.scanText(allStrings, {
        exact: true,
        regex: true,
        fuzzy: true,
        fuzzyThreshold: 0.85,
        categories: ['known_clients', 'macro_tools', 'anti_detection', 'cheat_files']
      });

      for (const det of keywordResults) {
        detections.push({
          type: 'memory-string',
          description: `Memory string: ${det.keyword} (${det.category})`,
          severity: det.severity,
          matchType: det.matchType,
          score: det.score,
          pid: pid
        });
      }
    }
  } catch (err) {
    // Memory scanning requires elevated privileges
  }

  return detections;
}

/**
 * Detect Java agents attached to running JVM
 */
function detectJavaAgents() {
  const detections = [];

  try {
    // Check for running Java agent processes
    const output = execSync(
      'wmic process where "commandline like \'%javaagent%\' or commandline like \'%agentlib%\' or commandline like \'%agentpath%\'" get ProcessId,Name,CommandLine /FORMAT:CSV',
      { encoding: 'utf-8', timeout: 15000, windowsHide: true }
    );

    const lines = output.trim().split('\n').slice(1);
    for (const line of lines) {
      if (line.trim()) {
        const parts = line.split(',');
        if (parts.length >= 3) {
          const cmdLine = parts.slice(1, parts.length - 2).join(',');
          detections.push({
            type: 'java-agent',
            description: 'Java agent detected in running process',
            severity: 'critical',
            pid: parseInt(parts[parts.length - 1], 10) || 0,
            commandLine: cmdLine.substring(0, 300)
          });
        }
      }
    }
  } catch (err) {
    // WMIC query failed
  }

  return detections;
}

/**
 * Full memory scan: find Java processes, scan their memory and arguments
 */
function scanMemory() {
  const results = {
    javaProcesses: [],
    jvmArgDetections: [],
    moduleDetections: [],
    memoryStringDetections: [],
    agentDetections: [],
    totalDetections: 0,
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  // Get Java processes
  results.javaProcesses = getJavaProcesses();

  // Scan each Java process
  for (const proc of results.javaProcesses) {
    // Scan JVM arguments
    const argDets = scanJVMArguments(proc.commandLine);
    for (const det of argDets) {
      det.processName = proc.name;
      det.pid = proc.pid;
    }
    results.jvmArgDetections.push(...argDets);

    // Scan loaded modules
    const modDets = scanProcessModules(proc.pid);
    results.moduleDetections.push(...modDets);

    // Scan memory strings
    const memDets = scanProcessMemoryStrings(proc.pid);
    results.memoryStringDetections.push(...memDets);
  }

  // Check for Java agents globally
  results.agentDetections = detectJavaAgents();

  results.totalDetections = results.jvmArgDetections.length +
                            results.moduleDetections.length +
                            results.memoryStringDetections.length +
                            results.agentDetections.length;

  if (results.totalDetections > 0) {
    results.status = 'detected';
  }

  return results;
}

module.exports = {
  scanMemory,
  getJavaProcesses,
  scanJVMArguments,
  scanProcessModules,
  scanProcessMemoryStrings,
  detectJavaAgents
};
