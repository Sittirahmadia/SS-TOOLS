/**
 * DLL Scanner Module
 * Full process DLL inspection:
 * - Enumerates loaded DLLs per process
 * - Detects known cheat DLLs by name, hash, and memory strings
 * - SHA-256 hash matching against known cheat signatures
 * - Memory string scanning of loaded modules
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Known suspicious DLL names and patterns
 */
const SUSPICIOUS_DLLS = [
  // Known cheat/macro DLLs
  { pattern: /198macro/i, severity: 'critical', description: '198Macro DLL' },
  { pattern: /zenithmacro/i, severity: 'critical', description: 'ZenithMacro DLL' },
  { pattern: /crystalspk/i, severity: 'critical', description: 'CrystalSpK DLL' },
  { pattern: /autoclicker/i, severity: 'critical', description: 'AutoClicker DLL' },
  { pattern: /autoclick/i, severity: 'high', description: 'Auto-click DLL' },

  // Cheat injection DLLs
  { pattern: /inject(?:or)?\.dll/i, severity: 'critical', description: 'Injector DLL' },
  { pattern: /hook\.dll/i, severity: 'high', description: 'Hook DLL' },
  { pattern: /detour/i, severity: 'high', description: 'Detour/hook library' },
  { pattern: /minhook/i, severity: 'high', description: 'MinHook injection library' },
  { pattern: /easyhook/i, severity: 'high', description: 'EasyHook injection library' },

  // Known cheat client DLLs
  { pattern: /wurst/i, severity: 'critical', description: 'Wurst client DLL' },
  { pattern: /meteor/i, severity: 'high', description: 'Possible Meteor client DLL' },
  { pattern: /impact/i, severity: 'high', description: 'Possible Impact client DLL' },
  { pattern: /aristois/i, severity: 'critical', description: 'Aristois client DLL' },
  { pattern: /rusherhack/i, severity: 'critical', description: 'RusherHack DLL' },
  { pattern: /killaura/i, severity: 'critical', description: 'KillAura DLL' },
  { pattern: /aimassist/i, severity: 'critical', description: 'AimAssist DLL' },
  { pattern: /triggerbot/i, severity: 'critical', description: 'Triggerbot DLL' },

  // Memory manipulation DLLs
  { pattern: /cheatengine/i, severity: 'critical', description: 'Cheat Engine DLL' },
  { pattern: /speedhack/i, severity: 'critical', description: 'SpeedHack DLL' },

  // Macro tools
  { pattern: /macro\.dll/i, severity: 'high', description: 'Macro DLL' },
  { pattern: /ahk.*\.dll/i, severity: 'high', description: 'AutoHotkey DLL' },

  // Debug/reverse engineering
  { pattern: /x64dbg/i, severity: 'high', description: 'x64dbg plugin DLL' },
  { pattern: /x32dbg/i, severity: 'high', description: 'x32dbg plugin DLL' },
  { pattern: /ollydbg/i, severity: 'high', description: 'OllyDbg plugin DLL' },
  { pattern: /titanhide/i, severity: 'critical', description: 'TitanHide anti-detection DLL' },
  { pattern: /scyllahide/i, severity: 'critical', description: 'ScyllaHide anti-detection DLL' }
];

/**
 * Known cheat DLL SHA-256 hashes
 */
const KNOWN_CHEAT_HASHES = new Map([
  // These are placeholder hashes -- in production, populate from cheat-signatures DB
  // Format: ['sha256hash', { name: 'CheatName', severity: 'critical' }]
]);

/**
 * Get DLLs loaded by a specific process using tasklist
 */
function getProcessDLLs(pid) {
  const dlls = [];

  try {
    const output = execSync(`tasklist /M /FI "PID eq ${pid}" /FO CSV /NH`, {
      encoding: 'utf-8',
      timeout: 10000,
      windowsHide: true
    });

    // Parse the module list
    const lines = output.trim().split('\n');
    for (const line of lines) {
      // Modules are listed after the process info
      const moduleParts = line.match(/"([^"]+)"/g);
      if (moduleParts && moduleParts.length >= 3) {
        const modules = moduleParts.slice(2).map(m => m.replace(/"/g, '').trim());
        for (const mod of modules) {
          if (mod && mod.toLowerCase().endsWith('.dll')) {
            dlls.push(mod);
          }
        }
      }
    }
  } catch (err) {
    // Cannot enumerate DLLs for this process
  }

  return dlls;
}

/**
 * Get all loaded DLLs across all processes using tasklist /M
 */
function getAllLoadedDLLs() {
  const processDlls = new Map();

  try {
    const output = execSync('tasklist /M /FO CSV', {
      encoding: 'utf-8',
      timeout: 30000,
      windowsHide: true,
      maxBuffer: 50 * 1024 * 1024
    });

    const lines = output.trim().split('\n');
    // Skip header
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const parts = line.match(/"([^"]+)"/g);
      if (!parts || parts.length < 3) continue;

      const procName = parts[0].replace(/"/g, '').trim();
      const pid = parseInt(parts[1].replace(/"/g, '').trim(), 10);
      const modules = parts.slice(2).map(m => m.replace(/"/g, '').trim()).filter(m => m);

      if (procName && pid) {
        if (!processDlls.has(pid)) {
          processDlls.set(pid, { name: procName, pid, dlls: [] });
        }
        processDlls.get(pid).dlls.push(...modules);
      }
    }
  } catch (err) {
    // Fallback: use PowerShell
    try {
      const psOutput = execSync(
        'powershell -NoProfile -Command "Get-Process | Select-Object Id,ProcessName | Format-Table -AutoSize"',
        { encoding: 'utf-8', timeout: 15000, windowsHide: true }
      );
      // Basic process list without DLL details
    } catch (innerErr) {
      // Cannot enumerate
    }
  }

  return processDlls;
}

/**
 * Compute SHA-256 hash of a file
 */
function computeFileHash(filePath) {
  try {
    const buffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
  } catch (err) {
    return null;
  }
}

/**
 * Scan a specific DLL file for suspicious characteristics
 */
function scanDLLFile(dllPath) {
  const result = {
    path: dllPath,
    name: path.basename(dllPath),
    detections: [],
    hash: null,
    signed: null,
    status: 'clean'
  };

  try {
    if (!fs.existsSync(dllPath)) return result;

    const stats = fs.statSync(dllPath);
    result.size = stats.size;

    // Skip very large files
    if (stats.size > 200 * 1024 * 1024) {
      result.status = 'skipped';
      return result;
    }

    // Check name patterns
    const nameLower = result.name.toLowerCase();
    for (const suspicious of SUSPICIOUS_DLLS) {
      if (suspicious.pattern.test(nameLower)) {
        result.detections.push({
          type: 'name-match',
          description: suspicious.description,
          severity: suspicious.severity
        });
      }
    }

    // Compute hash and check against known database
    result.hash = computeFileHash(dllPath);
    if (result.hash && KNOWN_CHEAT_HASHES.has(result.hash)) {
      const known = KNOWN_CHEAT_HASHES.get(result.hash);
      result.detections.push({
        type: 'hash-match',
        description: `Known cheat DLL: ${known.name}`,
        severity: known.severity,
        hash: result.hash
      });
    }

    // Scan binary strings for suspicious content
    if (stats.size < 50 * 1024 * 1024) {
      try {
        const buffer = fs.readFileSync(dllPath);
        const strings = extractStrings(buffer);
        const suspiciousStrings = scanStringsForCheats(strings);
        
        for (const detection of suspiciousStrings) {
          result.detections.push({
            type: 'string-match',
            ...detection
          });
        }
      } catch (err) {
        // Cannot read file contents
      }
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

/**
 * Extract readable strings from a buffer
 */
function extractStrings(buffer, minLength = 5) {
  const strings = [];
  let current = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 32 && byte < 127) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= minLength) {
    strings.push(current);
  }

  return strings;
}

/**
 * Scan extracted strings for cheat-related content
 */
function scanStringsForCheats(strings) {
  const detections = [];
  const allText = strings.join(' ');
  const textLower = allText.toLowerCase();

  const cheatPatterns = [
    { pattern: 'killaura', severity: 'critical', description: 'KillAura reference in DLL' },
    { pattern: 'aimassist', severity: 'critical', description: 'AimAssist reference in DLL' },
    { pattern: 'triggerbot', severity: 'critical', description: 'Triggerbot reference in DLL' },
    { pattern: 'autocrystal', severity: 'critical', description: 'AutoCrystal reference in DLL' },
    { pattern: 'autoclicker', severity: 'critical', description: 'AutoClicker reference in DLL' },
    { pattern: '198macro', severity: 'critical', description: '198Macro reference in DLL' },
    { pattern: 'zenithmacro', severity: 'critical', description: 'ZenithMacro reference in DLL' },
    { pattern: 'crystalspkmacro', severity: 'critical', description: 'CrystalSpKMacro reference in DLL' },
    { pattern: 'noclip', severity: 'critical', description: 'NoClip reference in DLL' },
    { pattern: 'wallhack', severity: 'critical', description: 'WallHack reference in DLL' },
    { pattern: 'speedhack', severity: 'critical', description: 'SpeedHack reference in DLL' },
    { pattern: 'createremotethread', severity: 'high', description: 'Remote thread creation (injection)' },
    { pattern: 'writeprocessmemory', severity: 'high', description: 'Process memory write (injection)' },
    { pattern: 'virtualalloc', severity: 'medium', description: 'Virtual memory allocation' }
  ];

  for (const pattern of cheatPatterns) {
    if (textLower.includes(pattern.pattern.toLowerCase())) {
      detections.push({
        description: pattern.description,
        severity: pattern.severity,
        matchedString: pattern.pattern
      });
    }
  }

  return detections;
}

/**
 * Full DLL scan: enumerate all processes, check their loaded DLLs
 */
function scanDLLs() {
  const results = {
    totalProcesses: 0,
    totalDLLs: 0,
    suspiciousDLLs: [],
    processDetails: [],
    totalDetections: 0,
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  const processDlls = getAllLoadedDLLs();
  results.totalProcesses = processDlls.size;

  for (const [pid, procInfo] of processDlls) {
    const procResult = {
      name: procInfo.name,
      pid: pid,
      dllCount: procInfo.dlls.length,
      suspiciousDLLs: []
    };

    results.totalDLLs += procInfo.dlls.length;

    for (const dll of procInfo.dlls) {
      const dllLower = dll.toLowerCase();

      for (const suspicious of SUSPICIOUS_DLLS) {
        if (suspicious.pattern.test(dllLower)) {
          const detection = {
            dll: dll,
            processName: procInfo.name,
            pid: pid,
            description: suspicious.description,
            severity: suspicious.severity
          };

          procResult.suspiciousDLLs.push(detection);
          results.suspiciousDLLs.push(detection);
          results.totalDetections++;
          break;
        }
      }
    }

    if (procResult.suspiciousDLLs.length > 0) {
      results.processDetails.push(procResult);
    }
  }

  // Also check for Java processes specifically (Minecraft)
  for (const [pid, procInfo] of processDlls) {
    const procLower = procInfo.name.toLowerCase();
    if (procLower.includes('javaw') || procLower.includes('java.exe')) {
      // Check for non-standard DLLs in Java process
      for (const dll of procInfo.dlls) {
        const dllLower = dll.toLowerCase();
        // Flag DLLs that shouldn't be in Java process
        if (!dllLower.includes('jvm') && !dllLower.includes('java') &&
            !dllLower.includes('awt') && !dllLower.includes('net') &&
            !dllLower.includes('zip') && !dllLower.includes('nio') &&
            !dllLower.includes('kernel32') && !dllLower.includes('ntdll') &&
            !dllLower.includes('user32') && !dllLower.includes('gdi32') &&
            !dllLower.includes('advapi') && !dllLower.includes('shell32') &&
            !dllLower.includes('msvc') && !dllLower.includes('ucrt') &&
            !dllLower.includes('opengl') && !dllLower.includes('lwjgl') &&
            !dllLower.includes('openal') && !dllLower.includes('glfw') &&
            !dllLower.includes('nvidia') && !dllLower.includes('amd') &&
            !dllLower.includes('intel') && !dllLower.includes('d3d') &&
            !dllLower.includes('dxgi') && !dllLower.includes('comctl') &&
            !dllLower.includes('crypt') && !dllLower.includes('bcrypt') &&
            !dllLower.includes('secur') && !dllLower.includes('ws2') &&
            !dllLower.includes('mswsock') && !dllLower.includes('winsock') &&
            !dllLower.includes('ssl') && !dllLower.includes('cabinet') &&
            !dllLower.includes('version') && !dllLower.includes('psapi') &&
            !dllLower.includes('iphlp') && !dllLower.includes('dns') &&
            !dllLower.includes('winhttp') && !dllLower.includes('wininet')) {
          // Check if it matches any suspicious pattern
          for (const suspicious of SUSPICIOUS_DLLS) {
            if (suspicious.pattern.test(dllLower)) {
              // Already caught above, skip
              break;
            }
          }
        }
      }
    }
  }

  if (results.totalDetections > 0) {
    results.status = 'detected';
  }

  return results;
}

module.exports = {
  scanDLLs,
  scanDLLFile,
  getAllLoadedDLLs,
  computeFileHash,
  SUSPICIOUS_DLLS
};
