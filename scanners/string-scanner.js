/**
 * String Scanner Module
 * Deep scans binary files for cheat-related strings
 * Detects injectors, DLLs, EXEs, and hidden tools
 */

const fs = require('fs');
const path = require('path');
const { scanStringForKeywords } = require('./mod-scanner');

/**
 * Additional binary-specific patterns for string scanning
 */
const BINARY_PATTERNS = [
  // DLL injection patterns
  { pattern: 'LoadLibraryA', severity: 'high', description: 'DLL loading function' },
  { pattern: 'LoadLibraryW', severity: 'high', description: 'DLL loading function (Unicode)' },
  { pattern: 'LoadLibraryExA', severity: 'high', description: 'Extended DLL loading' },
  { pattern: 'LoadLibraryExW', severity: 'high', description: 'Extended DLL loading (Unicode)' },
  { pattern: 'CreateRemoteThread', severity: 'critical', description: 'Remote thread injection' },
  { pattern: 'CreateRemoteThreadEx', severity: 'critical', description: 'Remote thread injection (extended)' },
  { pattern: 'WriteProcessMemory', severity: 'critical', description: 'Process memory write' },
  { pattern: 'ReadProcessMemory', severity: 'high', description: 'Process memory read' },
  { pattern: 'NtWriteVirtualMemory', severity: 'critical', description: 'NT virtual memory write' },
  { pattern: 'NtReadVirtualMemory', severity: 'high', description: 'NT virtual memory read' },
  { pattern: 'VirtualAllocEx', severity: 'high', description: 'Remote virtual memory allocation' },
  { pattern: 'VirtualProtectEx', severity: 'high', description: 'Remote memory protection change' },
  { pattern: 'OpenProcess', severity: 'medium', description: 'Process handle opening' },
  { pattern: 'NtOpenProcess', severity: 'high', description: 'NT process opening' },
  
  // Hook-related
  { pattern: 'SetWindowsHookEx', severity: 'high', description: 'Windows hook installation' },
  { pattern: 'UnhookWindowsHookEx', severity: 'medium', description: 'Windows hook removal' },
  { pattern: 'GetProcAddress', severity: 'medium', description: 'Dynamic function resolution' },
  
  // Anti-debug / Anti-detection
  { pattern: 'IsDebuggerPresent', severity: 'medium', description: 'Debugger detection' },
  { pattern: 'NtQueryInformationProcess', severity: 'high', description: 'Process info query (anti-debug)' },
  { pattern: 'CheckRemoteDebuggerPresent', severity: 'high', description: 'Remote debugger check' },
  
  // Cheat-specific strings
  { pattern: '198macro', severity: 'critical', description: '198Macro reference' },
  { pattern: 'zenithmacro', severity: 'critical', description: 'ZenithMacro reference' },
  { pattern: 'crystalspkmacro', severity: 'critical', description: 'CrystalSpKMacro reference' },
  { pattern: 'autocrystal', severity: 'critical', description: 'AutoCrystal reference' },
  { pattern: 'aimassist', severity: 'critical', description: 'AimAssist reference' },
  { pattern: 'triggerbot', severity: 'critical', description: 'Triggerbot reference' },
  { pattern: 'killaura', severity: 'critical', description: 'KillAura reference' }
];

/**
 * Extract readable strings from a binary file
 */
function extractStringsFromFile(filePath, minLength = 4) {
  const strings = [];

  try {
    const stats = fs.statSync(filePath);
    // Limit to 100MB
    if (stats.size > 100 * 1024 * 1024) {
      return { strings: [], error: 'File too large (>100MB)' };
    }

    const buffer = fs.readFileSync(filePath);
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

    // Also extract wide strings (UTF-16LE)
    current = '';
    for (let i = 0; i < buffer.length - 1; i += 2) {
      const charCode = buffer[i] | (buffer[i + 1] << 8);
      if (charCode >= 32 && charCode < 127) {
        current += String.fromCharCode(charCode);
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
  } catch (err) {
    return { strings: [], error: err.message };
  }

  return { strings };
}

/**
 * Scan a binary file for suspicious strings
 */
function scanBinaryFile(filePath) {
  const results = {
    file: path.basename(filePath),
    path: filePath,
    size: 0,
    detections: [],
    stringsFound: 0,
    status: 'clean'
  };

  try {
    const stats = fs.statSync(filePath);
    results.size = stats.size;

    const { strings, error } = extractStringsFromFile(filePath);
    if (error) {
      results.status = 'error';
      results.error = error;
      return results;
    }

    results.stringsFound = strings.length;
    const allText = strings.join(' ');

    // Check binary patterns
    for (const pattern of BINARY_PATTERNS) {
      const patternLower = pattern.pattern.toLowerCase();
      if (allText.toLowerCase().includes(patternLower)) {
        results.detections.push({
          pattern: pattern.pattern,
          description: pattern.description,
          severity: pattern.severity
        });
      }
    }

    // Also check cheat keywords
    const keywordMatches = scanStringForKeywords(allText);
    for (const match of keywordMatches) {
      results.detections.push({
        pattern: match.keyword,
        description: `Cheat keyword: ${match.category}`,
        severity: match.severity
      });
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
 * Scan a directory for suspicious binaries
 */
function scanDirectory(dirPath, recursive = true) {
  const results = {
    directory: dirPath,
    totalFiles: 0,
    scannedFiles: 0,
    detectedFiles: 0,
    files: []
  };

  const suspiciousExtensions = ['.dll', '.exe', '.ahk', '.bat', '.cmd', '.ps1', '.vbs', '.js'];

  function walkDir(dir) {
    try {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        try {
          const stats = fs.statSync(fullPath);
          if (stats.isDirectory() && recursive) {
            walkDir(fullPath);
          } else if (stats.isFile()) {
            results.totalFiles++;
            const ext = path.extname(item).toLowerCase();
            if (suspiciousExtensions.includes(ext)) {
              const scanResult = scanBinaryFile(fullPath);
              results.files.push(scanResult);
              results.scannedFiles++;
              if (scanResult.status === 'detected') {
                results.detectedFiles++;
              }
            }
          }
        } catch (err) {
          // Skip inaccessible files
        }
      }
    } catch (err) {
      // Skip inaccessible directories
    }
  }

  walkDir(dirPath);
  return results;
}

module.exports = {
  scanBinaryFile,
  scanDirectory,
  extractStringsFromFile,
  BINARY_PATTERNS
};
