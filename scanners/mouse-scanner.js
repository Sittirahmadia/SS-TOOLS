/**
 * Mouse Software Scanner Module
 * Detects and scans gaming mouse software for suspicious macros,
 * auto-click configurations, and cheat-related bindings.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Known gaming mouse software definitions with install paths and config locations
 */
const MOUSE_SOFTWARE = {
  logitech: {
    name: 'Logitech G HUB',
    processNames: ['lghub.exe', 'lghub_agent.exe', 'lghub_updater.exe'],
    installPaths: [
      '%PROGRAMFILES%\\LGHUB',
      '%LOCALAPPDATA%\\LGHUB',
      '%PROGRAMFILES(X86)%\\Logitech\\LogiOptions'
    ],
    configPaths: [
      '%LOCALAPPDATA%\\LGHUB\\settings.db',
      '%LOCALAPPDATA%\\LGHUB\\current_user',
      '%APPDATA%\\Logitech\\G HUB'
    ],
    isLegitimate: true,
    macroExtensions: ['.xml', '.json', '.db'],
    notes: 'Legitimate gaming software - only flag suspicious macros'
  },
  razer: {
    name: 'Razer Synapse',
    processNames: ['razersynapse.exe', 'rzsynapse.exe', 'razercentral.exe', 'rzdevicemgr.exe'],
    installPaths: [
      '%PROGRAMFILES%\\Razer\\Synapse3',
      '%PROGRAMFILES(X86)%\\Razer\\Synapse3',
      '%PROGRAMFILES%\\Razer\\RazerCentral'
    ],
    configPaths: [
      '%LOCALAPPDATA%\\Razer\\Synapse3\\Profiles',
      '%APPDATA%\\Razer\\Synapse3',
      '%PROGRAMDATA%\\Razer\\Synapse3\\ProductUpdates'
    ],
    isLegitimate: true,
    macroExtensions: ['.json', '.razersynapse'],
    notes: 'Legitimate gaming software - only flag suspicious macros'
  },
  bloody: {
    name: 'Bloody Mouse Software',
    processNames: ['bloody7.exe', 'bloody.exe', 'bloody6.exe', 'bloodycore.exe', 'oscar.exe'],
    installPaths: [
      '%PROGRAMFILES%\\Bloody7',
      '%PROGRAMFILES(X86)%\\Bloody7',
      '%PROGRAMFILES%\\Bloody',
      '%PROGRAMFILES(X86)%\\Bloody',
      '%PROGRAMFILES%\\A4Tech\\Bloody'
    ],
    configPaths: [
      '%PROGRAMFILES%\\Bloody7\\Data',
      '%PROGRAMFILES(X86)%\\Bloody7\\Data',
      '%APPDATA%\\Bloody'
    ],
    isLegitimate: false,
    macroExtensions: ['.bpf', '.amc', '.mgr'],
    notes: 'Bloody mice have hardware-level macros - highly suspicious for Minecraft SS'
  },
  redragon: {
    name: 'Redragon Mouse Software',
    processNames: ['redragon.exe', 'redragondriver.exe'],
    installPaths: [
      '%PROGRAMFILES%\\Redragon',
      '%PROGRAMFILES(X86)%\\Redragon'
    ],
    configPaths: [
      '%PROGRAMFILES%\\Redragon\\Config',
      '%APPDATA%\\Redragon'
    ],
    isLegitimate: false,
    macroExtensions: ['.cfg', '.xml'],
    notes: 'Redragon software with macro support - check for auto-click macros'
  },
  corsair: {
    name: 'Corsair iCUE',
    processNames: ['icue.exe', 'corsair.service.exe', 'icue4.exe'],
    installPaths: [
      '%PROGRAMFILES%\\Corsair\\CORSAIR iCUE 4 Software',
      '%PROGRAMFILES%\\Corsair\\CORSAIR iCUE 5 Software',
      '%PROGRAMFILES(X86)%\\Corsair'
    ],
    configPaths: [
      '%APPDATA%\\Corsair\\CUE',
      '%LOCALAPPDATA%\\Corsair\\CUE'
    ],
    isLegitimate: true,
    macroExtensions: ['.cueprofile', '.json'],
    notes: 'Legitimate gaming software - only flag suspicious macros'
  },
  steelseries: {
    name: 'SteelSeries GG / Engine',
    processNames: ['steelseriesgg.exe', 'steelseriesengine3.exe', 'ssengine3.exe'],
    installPaths: [
      '%PROGRAMFILES%\\SteelSeries\\GG',
      '%PROGRAMFILES%\\SteelSeries\\SteelSeries Engine 3'
    ],
    configPaths: [
      '%PROGRAMDATA%\\SteelSeries\\SteelSeries Engine 3',
      '%APPDATA%\\SteelSeries Engine 3'
    ],
    isLegitimate: true,
    macroExtensions: ['.json', '.ssp'],
    notes: 'Legitimate gaming software - only flag suspicious macros'
  },
  glorious: {
    name: 'Glorious Core / Model O Software',
    processNames: ['gloriouscore.exe', 'glorioussoftware.exe'],
    installPaths: [
      '%PROGRAMFILES%\\Glorious',
      '%PROGRAMFILES(X86)%\\Glorious'
    ],
    configPaths: [
      '%APPDATA%\\Glorious',
      '%LOCALAPPDATA%\\Glorious'
    ],
    isLegitimate: true,
    macroExtensions: ['.json'],
    notes: 'Legitimate - check for rapid-click macros'
  },
  roccat: {
    name: 'ROCCAT Swarm',
    processNames: ['roccatswarm.exe', 'roccat_swarm_monitor.exe'],
    installPaths: [
      '%PROGRAMFILES%\\ROCCAT\\ROCCAT Swarm',
      '%PROGRAMFILES(X86)%\\ROCCAT'
    ],
    configPaths: [
      '%APPDATA%\\ROCCAT\\Swarm',
      '%LOCALAPPDATA%\\ROCCAT'
    ],
    isLegitimate: true,
    macroExtensions: ['.json', '.xml'],
    notes: 'Legitimate - check for suspicious macros'
  }
};

/**
 * Suspicious macro patterns to look for in config files
 */
const SUSPICIOUS_MACRO_PATTERNS = [
  // Rapid click / auto-click patterns
  { pattern: /delay['":\s]*([0-9]{1,2})\b/gi, description: 'Very short delay macro (potential auto-clicker)', severity: 'critical', minDelay: 0, maxDelay: 50 },
  { pattern: /repeat['":\s]*(?:true|1|-1|infinite|forever)/gi, description: 'Infinite repeat macro', severity: 'high' },
  { pattern: /click['":\s]*(?:left|right|mouse1|mouse2).*?delay['":\s]*[0-9]{1,2}\b/gi, description: 'Rapid mouse click macro', severity: 'critical' },
  { pattern: /auto[_\-\s]?click/gi, description: 'Auto-click macro reference', severity: 'critical' },
  { pattern: /jitter[_\-\s]?click/gi, description: 'Jitter-click macro reference', severity: 'critical' },
  { pattern: /butterfly[_\-\s]?click/gi, description: 'Butterfly-click macro reference', severity: 'high' },
  { pattern: /drag[_\-\s]?click/gi, description: 'Drag-click macro reference', severity: 'high' },
  { pattern: /double[_\-\s]?click.*?(?:fast|rapid|speed)/gi, description: 'Fast double-click macro', severity: 'high' },
  
  // CPS-related patterns
  { pattern: /cps['":\s]*(?:[1-9][0-9]|[2-9][0-9]{2})/gi, description: 'High CPS macro configuration', severity: 'critical' },
  { pattern: /clicks?[_\-\s]?per[_\-\s]?second/gi, description: 'CPS manipulation reference', severity: 'high' },
  
  // Minecraft-specific macro patterns
  { pattern: /(?:left|right)[_\-\s]?click.*?(?:hold|spam|rapid)/gi, description: 'Rapid click hold macro', severity: 'critical' },
  { pattern: /w[_\-\s]?tap|s[_\-\s]?tap|sprint[_\-\s]?reset/gi, description: 'PvP combo macro (W-tap/S-tap)', severity: 'critical' },
  { pattern: /(?:crystal|anchor|bed)[_\-\s]?(?:place|break|macro)/gi, description: 'Crystal/Anchor PvP macro', severity: 'critical' },
  { pattern: /hotbar[_\-\s]?(?:switch|swap|scroll)/gi, description: 'Hotbar switching macro', severity: 'high' },
  { pattern: /(?:block|shield)[_\-\s]?(?:hit|combo|place)/gi, description: 'Block-hit combo macro', severity: 'high' }
];

/**
 * Resolve environment variables in a path
 */
function resolveEnvPath(pathStr) {
  return pathStr.replace(/%([^%]+)%/g, (_, envVar) => {
    return process.env[envVar] || '';
  });
}

/**
 * Check if a mouse software is running
 */
function isProcessRunning(processNames) {
  try {
    const output = execSync('tasklist /FO CSV /NH', {
      encoding: 'utf-8',
      timeout: 15000,
      windowsHide: true
    });

    const outputLower = output.toLowerCase();
    const running = [];

    for (const procName of processNames) {
      if (outputLower.includes(procName.toLowerCase())) {
        running.push(procName);
      }
    }

    return running;
  } catch (err) {
    return [];
  }
}

/**
 * Scan a config/profile file for suspicious macro patterns
 */
function scanConfigFile(filePath) {
  const results = {
    file: path.basename(filePath),
    path: filePath,
    detections: [],
    status: 'clean'
  };

  try {
    const stats = fs.statSync(filePath);
    // Skip files larger than 50MB
    if (stats.size > 50 * 1024 * 1024) {
      results.status = 'skipped';
      results.error = 'File too large';
      return results;
    }

    const content = fs.readFileSync(filePath, 'utf-8');

    for (const macroPattern of SUSPICIOUS_MACRO_PATTERNS) {
      const matches = content.match(macroPattern.pattern);
      if (matches) {
        // For delay patterns, check the actual delay value
        if (macroPattern.minDelay !== undefined) {
          for (const match of matches) {
            const delayMatch = match.match(/([0-9]+)/);
            if (delayMatch) {
              const delay = parseInt(delayMatch[1], 10);
              if (delay >= macroPattern.minDelay && delay <= macroPattern.maxDelay) {
                results.detections.push({
                  pattern: match.trim().substring(0, 100),
                  description: macroPattern.description,
                  severity: macroPattern.severity,
                  detail: `Delay: ${delay}ms`
                });
              }
            }
          }
        } else {
          results.detections.push({
            pattern: matches[0].trim().substring(0, 100),
            description: macroPattern.description,
            severity: macroPattern.severity,
            matchCount: matches.length
          });
        }
      }
    }

    if (results.detections.length > 0) {
      results.status = 'detected';
    }
  } catch (err) {
    results.status = 'error';
    results.error = err.message;
  }

  return results;
}

/**
 * Recursively scan a directory for config files
 */
function scanConfigDirectory(dirPath, extensions, maxDepth = 3, currentDepth = 0) {
  const results = [];

  if (currentDepth > maxDepth) return results;

  try {
    if (!fs.existsSync(dirPath)) return results;

    const items = fs.readdirSync(dirPath);
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      try {
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) {
          results.push(...scanConfigDirectory(fullPath, extensions, maxDepth, currentDepth + 1));
        } else if (stats.isFile()) {
          const ext = path.extname(item).toLowerCase();
          if (extensions.includes(ext)) {
            const scanResult = scanConfigFile(fullPath);
            if (scanResult.detections.length > 0) {
              results.push(scanResult);
            }
          }
        }
      } catch (err) {
        // Skip inaccessible
      }
    }
  } catch (err) {
    // Skip inaccessible directories
  }

  return results;
}

/**
 * Detect installed mouse software and scan for suspicious macros
 */
function scanMouseSoftware() {
  const results = {
    detectedSoftware: [],
    suspiciousMacros: [],
    totalDetections: 0,
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  for (const [softwareId, software] of Object.entries(MOUSE_SOFTWARE)) {
    const softwareResult = {
      id: softwareId,
      name: software.name,
      installed: false,
      running: false,
      runningProcesses: [],
      installPath: null,
      configFiles: [],
      macroDetections: [],
      isLegitimate: software.isLegitimate,
      notes: software.notes
    };

    // Check if running
    const runningProcs = isProcessRunning(software.processNames);
    if (runningProcs.length > 0) {
      softwareResult.running = true;
      softwareResult.runningProcesses = runningProcs;
    }

    // Check install paths
    for (const installPath of software.installPaths) {
      const resolved = resolveEnvPath(installPath);
      if (resolved && fs.existsSync(resolved)) {
        softwareResult.installed = true;
        softwareResult.installPath = resolved;
        break;
      }
    }

    // If Bloody mouse is installed or running, flag it immediately
    if (!software.isLegitimate && (softwareResult.installed || softwareResult.running)) {
      softwareResult.macroDetections.push({
        description: `${software.name} detected - known for hardware-level macro capabilities`,
        severity: 'critical',
        source: 'software-detection'
      });
    }

    // Scan config/profile directories for suspicious macros
    for (const configPath of software.configPaths) {
      const resolved = resolveEnvPath(configPath);
      if (resolved && fs.existsSync(resolved)) {
        const configScans = scanConfigDirectory(resolved, software.macroExtensions);
        softwareResult.configFiles.push(...configScans);

        for (const scan of configScans) {
          for (const det of scan.detections) {
            softwareResult.macroDetections.push({
              ...det,
              file: scan.file,
              filePath: scan.path,
              source: 'config-scan'
            });
          }
        }
      }
    }

    if (softwareResult.installed || softwareResult.running) {
      results.detectedSoftware.push(softwareResult);

      if (softwareResult.macroDetections.length > 0) {
        results.suspiciousMacros.push(...softwareResult.macroDetections);
        results.totalDetections += softwareResult.macroDetections.length;
      }
    }
  }

  if (results.totalDetections > 0) {
    results.status = 'detected';
  }

  return results;
}

module.exports = {
  scanMouseSoftware,
  scanConfigFile,
  MOUSE_SOFTWARE,
  SUSPICIOUS_MACRO_PATTERNS
};
