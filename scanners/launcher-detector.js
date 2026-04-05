/**
 * Launcher Detector Module
 * Detects installed Minecraft launchers and their data directories
 */

const fs = require('fs');
const path = require('path');
const launcherPaths = require('../cheat-signatures/file-patterns.json').launcher_paths;

/**
 * Resolve environment variables in a path string
 */
function resolveEnvPath(pathStr) {
  return pathStr.replace(/%([^%]+)%/g, (_, envVar) => {
    return process.env[envVar] || '';
  });
}

/**
 * Detect all installed Minecraft launchers
 */
function detectLaunchers() {
  const detected = [];

  for (const [launcherId, launcher] of Object.entries(launcherPaths)) {
    for (const basePath of launcher.base_paths) {
      const resolvedPath = resolveEnvPath(basePath);

      if (resolvedPath && fs.existsSync(resolvedPath)) {
        const launcherInfo = {
          id: launcherId,
          name: launcher.name,
          path: resolvedPath,
          versionIsolation: launcher.version_isolation,
          versions: [],
          modsLocations: [],
          logsLocations: []
        };

        // Detect versions/instances/profiles
        if (launcher.version_isolation) {
          const versionsDir = path.join(resolvedPath, launcher.versions_relative.split('/')[0]);
          if (fs.existsSync(versionsDir)) {
            try {
              const items = fs.readdirSync(versionsDir);
              for (const item of items) {
                const itemPath = path.join(versionsDir, item);
                if (fs.statSync(itemPath).isDirectory()) {
                  launcherInfo.versions.push({
                    name: item,
                    path: itemPath
                  });

                  // Build mods path
                  const modsRelative = launcher.mods_relative
                    .replace('{version}', item)
                    .replace('{instance}', item)
                    .replace('{profile}', item);
                  const modsPath = path.join(resolvedPath, modsRelative);
                  if (fs.existsSync(modsPath)) {
                    launcherInfo.modsLocations.push({
                      version: item,
                      path: modsPath
                    });
                  }

                  // Build logs path
                  const logsRelative = launcher.logs_relative
                    .replace('{version}', item)
                    .replace('{instance}', item)
                    .replace('{profile}', item);
                  const logsPath = path.join(resolvedPath, logsRelative);
                  if (fs.existsSync(logsPath)) {
                    launcherInfo.logsLocations.push({
                      version: item,
                      path: logsPath
                    });
                  }
                }
              }
            } catch (err) {
              // Skip
            }
          }
        } else {
          // Non-isolated launcher
          const modsPath = path.join(resolvedPath, launcher.mods_relative);
          if (fs.existsSync(modsPath)) {
            launcherInfo.modsLocations.push({
              version: 'default',
              path: modsPath
            });
          }

          const logsPath = path.join(resolvedPath, launcher.logs_relative);
          if (fs.existsSync(logsPath)) {
            launcherInfo.logsLocations.push({
              version: 'default',
              path: logsPath
            });
          }
        }

        detected.push(launcherInfo);
        break; // Found this launcher, move to next
      }
    }
  }

  return detected;
}

/**
 * Get all mods folders across all detected launchers
 */
function getAllModsFolders() {
  const launchers = detectLaunchers();
  const modsFolders = [];

  for (const launcher of launchers) {
    for (const modsLoc of launcher.modsLocations) {
      modsFolders.push({
        launcher: launcher.name,
        launcherId: launcher.id,
        version: modsLoc.version,
        path: modsLoc.path
      });
    }
  }

  return modsFolders;
}

/**
 * Get all logs folders across all detected launchers
 */
function getAllLogsFolders() {
  const launchers = detectLaunchers();
  const logsFolders = [];

  for (const launcher of launchers) {
    for (const logsLoc of launcher.logsLocations) {
      logsFolders.push({
        launcher: launcher.name,
        launcherId: launcher.id,
        version: logsLoc.version,
        path: logsLoc.path
      });
    }
  }

  return logsFolders;
}

module.exports = {
  detectLaunchers,
  getAllModsFolders,
  getAllLogsFolders,
  resolveEnvPath
};
