/**
 * Process Scanner Module
 * Scans running processes and task manager for hidden cheat tools
 */

const { execSync, exec } = require('child_process');
const path = require('path');

/**
 * Suspicious process names and patterns
 */
const SUSPICIOUS_PROCESSES = [
  // Known macro tools
  { name: '198macro', severity: 'critical', description: '198Macro detected' },
  { name: 'zenithmacro', severity: 'critical', description: 'ZenithMacro detected' },
  { name: 'crystalspkmacro', severity: 'critical', description: 'CrystalSpKMacro detected' },
  
  // Generic injection/cheat tools
  { name: 'injector', severity: 'critical', description: 'Injector process detected' },
  { name: 'dll_inject', severity: 'critical', description: 'DLL Injector detected' },
  { name: 'cheatengine', severity: 'critical', description: 'Cheat Engine detected' },
  { name: 'cheat engine', severity: 'critical', description: 'Cheat Engine detected' },
  { name: 'processhacker', severity: 'high', description: 'Process Hacker detected' },
  
  // AutoHotkey
  { name: 'autohotkey', severity: 'high', description: 'AutoHotkey detected' },
  { name: 'ahk', severity: 'medium', description: 'Possible AutoHotkey script' },
  
  // Known cheat clients
  { name: 'wurst', severity: 'critical', description: 'Wurst client process' },
  { name: 'impact', severity: 'high', description: 'Possible Impact client process' },
  { name: 'meteor', severity: 'high', description: 'Possible Meteor client process' },
  { name: 'aristois', severity: 'critical', description: 'Aristois process' },
  { name: 'rusherhack', severity: 'critical', description: 'RusherHack process' },
  { name: 'futureclient', severity: 'critical', description: 'FutureClient process' },
  
  // Macro/Clicker tools
  { name: 'autoclicker', severity: 'high', description: 'AutoClicker detected' },
  { name: 'op auto clicker', severity: 'high', description: 'OP Auto Clicker detected' },
  { name: 'gs auto clicker', severity: 'high', description: 'GS Auto Clicker detected' },
  { name: 'murgee', severity: 'high', description: 'Murgee Auto Clicker detected' },
  { name: 'fastclicker', severity: 'high', description: 'Fast Clicker detected' },
  { name: 'clickmate', severity: 'high', description: 'ClickMate detected' },
  
  // Memory tools
  { name: 'x64dbg', severity: 'high', description: 'x64dbg debugger detected' },
  { name: 'x32dbg', severity: 'high', description: 'x32dbg debugger detected' },
  { name: 'ollydbg', severity: 'high', description: 'OllyDbg detected' },
  { name: 'ida64', severity: 'high', description: 'IDA Pro detected' },
  { name: 'ida32', severity: 'high', description: 'IDA Pro detected' }
];

/**
 * Get running processes on Windows
 */
function getRunningProcesses() {
  try {
    const output = execSync('tasklist /FO CSV /NH', { 
      encoding: 'utf-8',
      timeout: 15000,
      windowsHide: true
    });

    const processes = [];
    const lines = output.split('\n');

    for (const line of lines) {
      const parts = line.split('","');
      if (parts.length >= 5) {
        const name = parts[0].replace(/"/g, '').trim();
        const pid = parseInt(parts[1], 10);
        const memory = parts[4] ? parts[4].replace(/"/g, '').replace(/[, K]/g, '').trim() : '0';

        if (name && pid) {
          processes.push({
            name: name,
            pid: pid,
            memory: memory
          });
        }
      }
    }

    return processes;
  } catch (err) {
    return [];
  }
}

/**
 * Get processes with their command lines (needs elevated access)
 */
function getProcessesWithCommandLine() {
  try {
    const output = execSync(
      'wmic process get ProcessId,Name,CommandLine,ExecutablePath /FORMAT:CSV',
      { encoding: 'utf-8', timeout: 30000, windowsHide: true }
    );

    const processes = [];
    const lines = output.split('\n').slice(1); // Skip header

    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length >= 4) {
        processes.push({
          commandLine: parts[1] || '',
          executablePath: parts[2] || '',
          name: parts[3] || '',
          pid: parseInt(parts[4], 10) || 0
        });
      }
    }

    return processes;
  } catch (err) {
    // Fall back to basic tasklist
    return getRunningProcesses();
  }
}

/**
 * Scan running processes for suspicious activity
 */
function scanProcesses() {
  const results = {
    totalProcesses: 0,
    detections: [],
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  try {
    const processes = getProcessesWithCommandLine();
    results.totalProcesses = processes.length;

    for (const proc of processes) {
      const procNameLower = (proc.name || '').toLowerCase();
      const cmdLineLower = (proc.commandLine || '').toLowerCase();
      const exePathLower = (proc.executablePath || '').toLowerCase();

      for (const suspicious of SUSPICIOUS_PROCESSES) {
        const searchName = suspicious.name.toLowerCase();

        if (procNameLower.includes(searchName) || 
            cmdLineLower.includes(searchName) || 
            exePathLower.includes(searchName)) {
          results.detections.push({
            processName: proc.name,
            pid: proc.pid,
            commandLine: proc.commandLine || 'N/A',
            executablePath: proc.executablePath || 'N/A',
            match: suspicious.name,
            description: suspicious.description,
            severity: suspicious.severity
          });
        }
      }

      // Check for hidden/suspicious DLLs loaded
      if (procNameLower.includes('javaw') || procNameLower.includes('java.exe')) {
        // Java process — check if command line has suspicious arguments
        if (cmdLineLower.includes('-javaagent') || cmdLineLower.includes('-agentlib') ||
            cmdLineLower.includes('-agentpath')) {
          results.detections.push({
            processName: proc.name,
            pid: proc.pid,
            commandLine: proc.commandLine || 'N/A',
            description: 'Java agent injection detected (potential cheat injector)',
            severity: 'critical'
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
 * Scan for suspicious Windows services
 */
function scanServices() {
  const results = {
    detections: [],
    status: 'clean'
  };

  try {
    const output = execSync('sc query state= all', {
      encoding: 'utf-8',
      timeout: 15000,
      windowsHide: true
    });

    const serviceBlocks = output.split('\n\n');
    for (const block of serviceBlocks) {
      const nameLower = block.toLowerCase();
      for (const suspicious of SUSPICIOUS_PROCESSES) {
        if (nameLower.includes(suspicious.name.toLowerCase())) {
          results.detections.push({
            service: block.trim().split('\n')[0],
            match: suspicious.name,
            description: `Suspicious service: ${suspicious.description}`,
            severity: suspicious.severity
          });
        }
      }
    }

    if (results.detections.length > 0) {
      results.status = 'detected';
    }
  } catch (err) {
    // Services scan not available
  }

  return results;
}

module.exports = {
  scanProcesses,
  scanServices,
  getRunningProcesses,
  SUSPICIOUS_PROCESSES
};
