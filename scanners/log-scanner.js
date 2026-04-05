/**
 * Log Scanner Module
 * Scans Minecraft log files for cheat-related indicators
 */

const fs = require('fs');
const path = require('path');
const { scanStringForKeywords } = require('./mod-scanner');

/**
 * Log-specific cheat indicators that appear in Minecraft logs
 */
const LOG_PATTERNS = [
  // Client initialization patterns
  { pattern: /\[Client thread\/INFO\].*(?:hack|cheat|exploit|inject)/i, severity: 'critical', description: 'Cheat client initialization detected' },
  { pattern: /Loading\s+(?:mod|module).*(?:hack|cheat|aura|aimbot|triggerbot|crystal)/i, severity: 'critical', description: 'Cheat mod loading detected' },
  
  // Known cheat client log signatures
  { pattern: /\[Wurst\]/i, severity: 'critical', description: 'Wurst client detected' },
  { pattern: /\[Impact\]/i, severity: 'critical', description: 'Impact client detected' },
  { pattern: /\[Meteor\]/i, severity: 'high', description: 'Possible Meteor client detected' },
  { pattern: /\[MeteorClient\]/i, severity: 'critical', description: 'Meteor client detected' },
  { pattern: /\[Aristois\]/i, severity: 'critical', description: 'Aristois client detected' },
  { pattern: /\[RusherHack\]/i, severity: 'critical', description: 'RusherHack client detected' },
  { pattern: /\[Lambda\]/i, severity: 'high', description: 'Possible Lambda client detected' },
  { pattern: /\[LambdaClient\]/i, severity: 'critical', description: 'Lambda client detected' },
  { pattern: /\[Future\]/i, severity: 'high', description: 'Possible Future client detected' },
  { pattern: /\[FutureClient\]/i, severity: 'critical', description: 'Future client detected' },
  { pattern: /\[ThunderHack\]/i, severity: 'critical', description: 'ThunderHack client detected' },
  { pattern: /\[BleachHack\]/i, severity: 'critical', description: 'BleachHack client detected' },
  { pattern: /\[GameSense\]/i, severity: 'critical', description: 'GameSense client detected' },
  
  // Module toggle patterns
  { pattern: /(?:Enabled|Toggled|Activated)\s+(?:KillAura|AimAssist|Triggerbot|AutoCrystal|CrystalAura|Reach|Velocity|AntiKB|NoFall|Speed|Fly|Scaffold)/i, severity: 'critical', description: 'Cheat module toggle detected' },
  
  // Fabric/Forge mod loading
  { pattern: /Loading.*(?:fabric|forge).*mod.*(?:hack|cheat|hacked|client)/i, severity: 'critical', description: 'Cheat mod loaded via mod loader' },
  
  // Injection-related
  { pattern: /(?:inject|hook|patch).*(?:render|tick|player|entity|world)/i, severity: 'medium', description: 'Suspicious code injection pattern' },
  
  // Command patterns from cheat clients
  { pattern: /\.(?:toggle|bind|set|prefix|module|hack|cheat)\s/i, severity: 'high', description: 'Cheat client command detected' },
  
  // Macro indicators
  { pattern: /(?:macro|autoclick|autoclicker).*(?:enabled|started|running)/i, severity: 'high', description: 'Macro/AutoClicker activity detected' },
  
  // Config loading
  { pattern: /(?:Loading|Loaded)\s+(?:config|configuration).*(?:hack|cheat|module|client)/i, severity: 'critical', description: 'Cheat configuration loaded' }
];

/**
 * Scan a single log file
 */
function scanLogFile(filePath) {
  const results = {
    file: path.basename(filePath),
    path: filePath,
    size: 0,
    detections: [],
    linesScanned: 0,
    status: 'clean'
  };

  try {
    const stats = fs.statSync(filePath);
    results.size = stats.size;

    // Skip very large log files (> 50MB)
    if (stats.size > 50 * 1024 * 1024) {
      results.status = 'skipped';
      results.error = 'Log file too large (>50MB)';
      return results;
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    results.linesScanned = lines.length;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check against log patterns
      for (const pattern of LOG_PATTERNS) {
        if (pattern.pattern.test(line)) {
          results.detections.push({
            line: lineNum,
            content: line.trim().substring(0, 200),
            description: pattern.description,
            severity: pattern.severity
          });
        }
      }

      // Also check for keyword matches in log lines
      const keywordMatches = scanStringForKeywords(line);
      if (keywordMatches.length > 0) {
        // Only include if there's strong context (multiple matches or critical severity)
        const criticalMatches = keywordMatches.filter(m => m.severity === 'critical');
        if (criticalMatches.length > 0 || keywordMatches.length >= 2) {
          results.detections.push({
            line: lineNum,
            content: line.trim().substring(0, 200),
            description: 'Cheat keyword detected in log',
            severity: criticalMatches.length > 0 ? 'critical' : 'high',
            keywords: keywordMatches.map(m => m.keyword)
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
 * Scan a logs folder
 */
function scanLogsFolder(folderPath) {
  const results = {
    folder: folderPath,
    totalFiles: 0,
    scannedFiles: 0,
    detectedFiles: 0,
    files: []
  };

  if (!fs.existsSync(folderPath)) {
    results.error = 'Folder does not exist';
    return results;
  }

  const files = fs.readdirSync(folderPath);
  const logExtensions = ['.log', '.txt', '.gz'];

  for (const file of files) {
    const filePath = path.join(folderPath, file);
    const ext = path.extname(file).toLowerCase();

    try {
      const stats = fs.statSync(filePath);
      if (stats.isDirectory()) continue;

      results.totalFiles++;

      // Skip .gz files for now (compressed logs)
      if (ext === '.gz') continue;

      if (ext === '.log' || ext === '.txt' || file === 'latest.log' || file === 'debug.log') {
        const fileResult = scanLogFile(filePath);
        results.files.push(fileResult);
        results.scannedFiles++;

        if (fileResult.status === 'detected') {
          results.detectedFiles++;
        }
      }
    } catch (err) {
      // Skip unreadable files
    }
  }

  return results;
}

module.exports = {
  scanLogFile,
  scanLogsFolder,
  LOG_PATTERNS
};
