/**
 * Deleted File Scanner Module
 * Scans for recently deleted files using multiple techniques:
 * - Windows Recycle Bin analysis
 * - NTFS journal scanning (USN Journal)
 * - Prefetch file analysis
 * - Recent file activity from registry
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Suspicious file patterns to look for in deleted files
 */
const SUSPICIOUS_PATTERNS = [
  /198macro/i, /zenithmacro/i, /crystalspkmacro/i,
  /autoclicker/i, /aimassist/i, /triggerbot/i,
  /killaura/i, /autocrystal/i, /anchormacro/i,
  /injector/i, /dll.?inject/i, /cheatengine/i,
  /wurst/i, /impact.*client/i, /meteor.*client/i,
  /aristois/i, /rusherhack/i, /futureclient/i,
  /thunderhack/i, /bleachhack/i, /gamesense/i,
  /hack.*client/i, /cheat.*client/i,
  /autohotkey/i, /\.ahk$/i,
  /macro.*tool/i, /click.*bot/i,
  /x64dbg/i, /x32dbg/i, /ollydbg/i,
  /process.*hacker/i
];

/**
 * Scan Windows Recycle Bin for recently deleted suspicious files
 */
function scanRecycleBin() {
  const results = {
    source: 'Recycle Bin',
    detections: [],
    totalItems: 0,
    status: 'clean'
  };

  try {
    // Use PowerShell to enumerate Recycle Bin contents
    const psCommand = `
      $shell = New-Object -ComObject Shell.Application
      $recycleBin = $shell.NameSpace(0x0a)
      $items = $recycleBin.Items()
      foreach ($item in $items) {
        $name = $item.Name
        $path = $item.Path
        $size = $item.Size
        $modified = $item.ModifyDate
        Write-Output "$name|$path|$size|$modified"
      }
    `;

    const output = execSync(
      `powershell -NoProfile -Command "${psCommand.replace(/\n/g, ' ')}"`,
      { encoding: 'utf-8', timeout: 30000, windowsHide: true }
    );

    const lines = output.trim().split('\n').filter(l => l.trim());
    results.totalItems = lines.length;

    for (const line of lines) {
      const [name, filePath, size, modified] = line.split('|');
      if (!name) continue;

      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(name) || (filePath && pattern.test(filePath))) {
          results.detections.push({
            name: name.trim(),
            originalPath: filePath ? filePath.trim() : 'Unknown',
            size: size ? size.trim() : 'Unknown',
            deletedDate: modified ? modified.trim() : 'Unknown',
            matchedPattern: pattern.source,
            severity: 'critical'
          });
          break;
        }
      }
    }

    if (results.detections.length > 0) {
      results.status = 'detected';
    }
  } catch (err) {
    results.error = err.message;
    results.status = 'error';
  }

  return results;
}

/**
 * Scan USN Journal for deleted file records (NTFS file system journal)
 * Requires admin privileges
 */
function scanUSNJournal() {
  const results = {
    source: 'USN Journal (NTFS)',
    detections: [],
    totalRecords: 0,
    status: 'clean'
  };

  try {
    // Query USN journal for delete operations
    const output = execSync(
      'fsutil usn readjournal C: csv | findstr /I "delete"',
      { encoding: 'utf-8', timeout: 60000, windowsHide: true, maxBuffer: 50 * 1024 * 1024 }
    );

    const lines = output.trim().split('\n').filter(l => l.trim());
    results.totalRecords = lines.length;

    for (const line of lines) {
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(line)) {
          results.detections.push({
            record: line.trim().substring(0, 300),
            matchedPattern: pattern.source,
            severity: 'critical',
            source: 'NTFS USN Journal'
          });
          break;
        }
      }
    }

    if (results.detections.length > 0) {
      results.status = 'detected';
    }
  } catch (err) {
    results.status = 'unavailable';
    results.error = 'USN Journal scan requires administrator privileges';
  }

  return results;
}

/**
 * Scan Windows Prefetch folder for evidence of previously run programs
 */
function scanPrefetch() {
  const results = {
    source: 'Windows Prefetch',
    detections: [],
    totalFiles: 0,
    status: 'clean'
  };

  try {
    const prefetchPath = 'C:\\Windows\\Prefetch';
    if (!fs.existsSync(prefetchPath)) {
      results.status = 'unavailable';
      results.error = 'Prefetch folder not accessible';
      return results;
    }

    const files = fs.readdirSync(prefetchPath);
    results.totalFiles = files.length;

    for (const file of files) {
      const fileLower = file.toLowerCase();

      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(fileLower)) {
          const filePath = path.join(prefetchPath, file);
          let modified = 'Unknown';
          try {
            const stats = fs.statSync(filePath);
            modified = stats.mtime.toISOString();
          } catch (e) {
            // ignore
          }

          results.detections.push({
            name: file,
            path: filePath,
            lastRun: modified,
            matchedPattern: pattern.source,
            severity: 'critical',
            description: 'Evidence of previously executed suspicious program'
          });
          break;
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
 * Scan Windows Recent files for evidence of recently accessed suspicious files
 */
function scanRecentFiles() {
  const results = {
    source: 'Recent Files',
    detections: [],
    totalFiles: 0,
    status: 'clean'
  };

  try {
    const recentPath = path.join(process.env.APPDATA || '', 'Microsoft', 'Windows', 'Recent');
    if (!fs.existsSync(recentPath)) {
      results.status = 'unavailable';
      return results;
    }

    const files = fs.readdirSync(recentPath);
    results.totalFiles = files.length;

    for (const file of files) {
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(file)) {
          results.detections.push({
            name: file,
            path: path.join(recentPath, file),
            matchedPattern: pattern.source,
            severity: 'high',
            description: 'Suspicious file found in Recent files'
          });
          break;
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
 * Scan PowerShell command history for suspicious commands
 */
function scanCommandHistory() {
  const results = {
    source: 'Command History',
    detections: [],
    status: 'clean'
  };

  try {
    // PowerShell history file
    const psHistoryPath = path.join(
      process.env.APPDATA || '',
      'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt'
    );

    if (fs.existsSync(psHistoryPath)) {
      const content = fs.readFileSync(psHistoryPath, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SUSPICIOUS_PATTERNS) {
          if (pattern.test(line)) {
            results.detections.push({
              line: i + 1,
              command: line.trim().substring(0, 200),
              matchedPattern: pattern.source,
              severity: 'high',
              description: 'Suspicious command in PowerShell history'
            });
            break;
          }
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
 * Run all deleted file scans
 */
function scanAllDeletedFiles() {
  const results = {
    scannedAt: new Date().toISOString(),
    sources: [],
    totalDetections: 0,
    overallStatus: 'clean'
  };

  // Run all scanners
  const recycleBin = scanRecycleBin();
  const prefetch = scanPrefetch();
  const recentFiles = scanRecentFiles();
  const commandHistory = scanCommandHistory();

  results.sources.push(recycleBin, prefetch, recentFiles, commandHistory);

  // Try USN journal (requires admin)
  const usnJournal = scanUSNJournal();
  results.sources.push(usnJournal);

  // Count total detections
  for (const source of results.sources) {
    if (source.detections) {
      results.totalDetections += source.detections.length;
    }
  }

  if (results.totalDetections > 0) {
    results.overallStatus = 'detected';
  }

  return results;
}

module.exports = {
  scanRecycleBin,
  scanUSNJournal,
  scanPrefetch,
  scanRecentFiles,
  scanCommandHistory,
  scanAllDeletedFiles,
  SUSPICIOUS_PATTERNS
};
