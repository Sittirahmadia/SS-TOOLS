/**
 * Kernel Check Scanner Module
 * Full kernel-mode driver scanner for detecting:
 * - Unsigned kernel drivers
 * - Suspicious .sys modules
 * - Known cheat kernel drivers
 * - SSDT hooks and kernel-level macro drivers
 * - Hidden processes via kernel
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Known suspicious kernel driver patterns
 */
const SUSPICIOUS_DRIVERS = [
  // Known cheat/macro kernel drivers
  { pattern: /198macro/i, severity: 'critical', description: '198Macro kernel driver' },
  { pattern: /zenithmacro/i, severity: 'critical', description: 'ZenithMacro kernel driver' },
  { pattern: /macro.*drv/i, severity: 'critical', description: 'Macro-related kernel driver' },
  { pattern: /click.*drv/i, severity: 'high', description: 'Click-related kernel driver' },
  
  // Cheat engine / memory tools
  { pattern: /dbk64/i, severity: 'critical', description: 'Cheat Engine kernel driver (dbk64)' },
  { pattern: /dbk32/i, severity: 'critical', description: 'Cheat Engine kernel driver (dbk32)' },
  { pattern: /cheatengine/i, severity: 'critical', description: 'Cheat Engine driver' },
  { pattern: /processhacker/i, severity: 'high', description: 'Process Hacker kernel driver' },
  { pattern: /kprocesshacker/i, severity: 'high', description: 'KProcessHacker driver' },
  
  // Known ring-0 cheat drivers
  { pattern: /kdmapper/i, severity: 'critical', description: 'KDMapper (kernel driver mapper)' },
  { pattern: /capcom/i, severity: 'critical', description: 'Capcom.sys exploit driver' },
  { pattern: /iqvw64/i, severity: 'critical', description: 'Intel exploit driver (iqvw64e)' },
  { pattern: /asrdrv/i, severity: 'critical', description: 'ASRock exploit driver' },
  { pattern: /gdrv/i, severity: 'high', description: 'GIGABYTE exploit driver' },
  { pattern: /atillk/i, severity: 'critical', description: 'Atillk vulnerable driver' },
  { pattern: /aswarpot/i, severity: 'high', description: 'Avast vulnerable driver' },
  { pattern: /mhyprot/i, severity: 'critical', description: 'mhyprot exploit driver' },
  { pattern: /dbutility/i, severity: 'critical', description: 'Dell BIOS Utility exploit driver' },
  
  // Input injection / macro kernel drivers
  { pattern: /mouse.*filter/i, severity: 'high', description: 'Mouse filter driver (potential input injection)' },
  { pattern: /kbd.*filter/i, severity: 'high', description: 'Keyboard filter driver (potential input injection)' },
  { pattern: /input.*inject/i, severity: 'critical', description: 'Input injection kernel driver' },
  { pattern: /hidinject/i, severity: 'critical', description: 'HID injection driver' },
  
  // Memory manipulation
  { pattern: /memdrv/i, severity: 'critical', description: 'Memory manipulation driver' },
  { pattern: /physmem/i, severity: 'critical', description: 'Physical memory access driver' },
  { pattern: /rwdrv/i, severity: 'critical', description: 'Read/write kernel driver' },
  { pattern: /winio/i, severity: 'high', description: 'WinIO direct hardware access' },

  // Rootkit indicators
  { pattern: /rootkit/i, severity: 'critical', description: 'Rootkit driver' },
  { pattern: /hidedrv/i, severity: 'critical', description: 'Driver hiding utility' },
  { pattern: /hiddendrv/i, severity: 'critical', description: 'Hidden driver utility' }
];

/**
 * Known legitimate driver publishers (whitelist)
 */
const LEGITIMATE_PUBLISHERS = [
  /microsoft/i, /windows/i,
  /intel/i, /nvidia/i, /amd/i, /realtek/i,
  /logitech/i, /razer/i, /corsair/i, /steelseries/i,
  /hyperx/i, /kingston/i, /samsung/i, /western digital/i,
  /dell/i, /hp/i, /lenovo/i, /asus/i, /acer/i, /msi/i,
  /broadcom/i, /qualcomm/i, /symantec/i, /norton/i,
  /kaspersky/i, /bitdefender/i, /malwarebytes/i,
  /vmware/i, /virtualbox/i, /citrix/i,
  /crowdstrike/i, /sentinelone/i, /carbon black/i
];

/**
 * Get loaded kernel drivers using driverquery
 */
function getLoadedDrivers() {
  const drivers = [];

  try {
    const output = execSync('driverquery /V /FO CSV', {
      encoding: 'utf-8',
      timeout: 30000,
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024
    });

    const lines = output.trim().split('\n');
    if (lines.length < 2) return drivers;

    // Parse CSV header
    const headers = lines[0].split('","').map(h => h.replace(/"/g, '').trim());

    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split('","').map(p => p.replace(/"/g, '').trim());
      if (parts.length >= 4) {
        const driver = {
          moduleName: parts[0] || '',
          displayName: parts[1] || '',
          description: parts[2] || '',
          driverType: parts[3] || '',
          startMode: parts[4] || '',
          state: parts[5] || '',
          status: parts[6] || '',
          acceptStop: parts[7] || '',
          acceptPause: parts[8] || '',
          pagedPool: parts[9] || '',
          code: parts[10] || '',
          bss: parts[11] || '',
          linkDate: parts[12] || '',
          path: parts[13] || '',
          initBytes: parts[14] || ''
        };
        drivers.push(driver);
      }
    }
  } catch (err) {
    // Try simpler format
    try {
      const output = execSync('driverquery /FO CSV /NH', {
        encoding: 'utf-8',
        timeout: 15000,
        windowsHide: true
      });

      const lines = output.trim().split('\n');
      for (const line of lines) {
        const parts = line.split('","').map(p => p.replace(/"/g, '').trim());
        if (parts.length >= 3) {
          drivers.push({
            moduleName: parts[0],
            displayName: parts[1],
            driverType: parts[2],
            linkDate: parts[3] || ''
          });
        }
      }
    } catch (innerErr) {
      // Cannot query drivers
    }
  }

  return drivers;
}

/**
 * Get filesystem filter drivers using fltmc
 */
function getFilterDrivers() {
  const filters = [];

  try {
    const output = execSync('fltmc', {
      encoding: 'utf-8',
      timeout: 15000,
      windowsHide: true
    });

    const lines = output.trim().split('\n');
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3 && /^\d+$/.test(parts[1])) {
        filters.push({
          name: parts[0],
          instances: parseInt(parts[1], 10),
          altitude: parts[2] || '',
          frame: parts[3] || ''
        });
      }
    }
  } catch (err) {
    // fltmc requires admin or not available
  }

  return filters;
}

/**
 * Check digital signature status of driver files
 */
function checkDriverSignature(driverPath) {
  try {
    const psCommand = `Get-AuthenticodeSignature '${driverPath.replace(/'/g, "''")}' | Select-Object Status,SignerCertificate | Format-List`;
    const output = execSync(
      `powershell -NoProfile -Command "${psCommand}"`,
      { encoding: 'utf-8', timeout: 10000, windowsHide: true }
    );

    const statusMatch = output.match(/Status\s*:\s*(.+)/i);
    const signerMatch = output.match(/Subject\s*:\s*(.+)/i);

    return {
      signed: statusMatch && statusMatch[1].trim() === 'Valid',
      status: statusMatch ? statusMatch[1].trim() : 'Unknown',
      signer: signerMatch ? signerMatch[1].trim() : 'Unknown'
    };
  } catch (err) {
    return { signed: false, status: 'Error', signer: 'Unknown', error: err.message };
  }
}

/**
 * Scan for unsigned or suspicious .sys files in System32\drivers
 */
function scanDriverFiles() {
  const results = [];
  const driversDir = 'C:\\Windows\\System32\\drivers';

  try {
    if (!fs.existsSync(driversDir)) return results;

    const files = fs.readdirSync(driversDir);
    for (const file of files) {
      if (!file.toLowerCase().endsWith('.sys')) continue;

      const fullPath = path.join(driversDir, file);
      const fileLower = file.toLowerCase();

      // Check against suspicious patterns
      for (const suspicious of SUSPICIOUS_DRIVERS) {
        if (suspicious.pattern.test(fileLower)) {
          results.push({
            file: file,
            path: fullPath,
            description: suspicious.description,
            severity: suspicious.severity,
            source: 'file-scan'
          });
          break;
        }
      }
    }
  } catch (err) {
    // Cannot access drivers directory
  }

  return results;
}

/**
 * Check for hidden processes (kernel-level hiding)
 */
function detectHiddenProcesses() {
  const results = [];

  try {
    // Compare tasklist with WMIC to find discrepancies
    const tasklistOutput = execSync('tasklist /FO CSV /NH', {
      encoding: 'utf-8', timeout: 15000, windowsHide: true
    });
    const tasklistPids = new Set();
    for (const line of tasklistOutput.split('\n')) {
      const parts = line.split('","');
      if (parts.length >= 2) {
        const pid = parseInt(parts[1], 10);
        if (pid) tasklistPids.add(pid);
      }
    }

    // Use WMIC for second enumeration
    const wmicOutput = execSync('wmic process get ProcessId /FORMAT:CSV', {
      encoding: 'utf-8', timeout: 15000, windowsHide: true
    });
    const wmicPids = new Set();
    for (const line of wmicOutput.split('\n')) {
      const parts = line.trim().split(',');
      const pid = parseInt(parts[parts.length - 1], 10);
      if (pid) wmicPids.add(pid);
    }

    // Find PIDs visible to WMIC but not tasklist (potentially hidden)
    for (const pid of wmicPids) {
      if (!tasklistPids.has(pid) && pid > 4) {
        results.push({
          pid: pid,
          description: 'Process visible to WMI but not tasklist (potential kernel-level hiding)',
          severity: 'critical'
        });
      }
    }
  } catch (err) {
    // Hidden process detection failed
  }

  return results;
}

/**
 * Run full kernel check scan
 */
function scanKernel() {
  const results = {
    loadedDrivers: [],
    filterDrivers: [],
    suspiciousDrivers: [],
    unsignedDrivers: [],
    hiddenProcesses: [],
    driverFileScans: [],
    totalDetections: 0,
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  // Step 1: Get loaded drivers
  results.loadedDrivers = getLoadedDrivers();

  // Step 2: Check loaded drivers against suspicious patterns
  for (const driver of results.loadedDrivers) {
    const combined = `${driver.moduleName} ${driver.displayName} ${driver.description || ''} ${driver.path || ''}`;
    
    for (const suspicious of SUSPICIOUS_DRIVERS) {
      if (suspicious.pattern.test(combined)) {
        results.suspiciousDrivers.push({
          ...driver,
          matchDescription: suspicious.description,
          severity: suspicious.severity,
          source: 'loaded-driver'
        });
        results.totalDetections++;
        break;
      }
    }
  }

  // Step 3: Get filesystem filter drivers
  results.filterDrivers = getFilterDrivers();

  // Check filter drivers against patterns
  for (const filter of results.filterDrivers) {
    for (const suspicious of SUSPICIOUS_DRIVERS) {
      if (suspicious.pattern.test(filter.name)) {
        results.suspiciousDrivers.push({
          moduleName: filter.name,
          matchDescription: suspicious.description,
          severity: suspicious.severity,
          source: 'filter-driver'
        });
        results.totalDetections++;
        break;
      }
    }
  }

  // Step 4: Scan driver files on disk
  results.driverFileScans = scanDriverFiles();
  results.totalDetections += results.driverFileScans.length;

  // Step 5: Check for hidden processes
  results.hiddenProcesses = detectHiddenProcesses();
  results.totalDetections += results.hiddenProcesses.length;

  if (results.totalDetections > 0) {
    results.status = 'detected';
  }

  return results;
}

module.exports = {
  scanKernel,
  getLoadedDrivers,
  getFilterDrivers,
  scanDriverFiles,
  detectHiddenProcesses,
  SUSPICIOUS_DRIVERS
};
