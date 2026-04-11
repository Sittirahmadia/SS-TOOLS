/**
 * Browser Scanner Module
 * Scans Chrome, Edge, Firefox, Brave for:
 * - Download history containing cheat/macro files
 * - Extensions related to Minecraft cheats
 * - Bookmarks and cache containing cheat websites
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Known cheat-related websites and download patterns
 */
const SUSPICIOUS_URLS = [
  // Cheat client sites
  /wurst\.?client/i, /wurstclient\.net/i,
  /meteorclient\.com/i, /meteor-client/i,
  /impactclient\.net/i, /impact\.?client/i,
  /aristois\.net/i,
  /rusherhack\.com/i, /rusher\.?hack/i,
  /futureclient\.net/i, /future\.?client/i,
  /thunderhack/i, /bleach\.?hack/i,
  /gamesense\.pub/i,
  /lambda\.?client/i, /lambdaclient/i,
  /inertiaclient/i,
  /crystalclient/i,

  // Macro / auto-clicker sites
  /198macro/i, /zenith\.?macro/i,
  /crystalspk\.?macro/i,
  /auto\.?clicker/i,
  /op-?auto-?clicker/i,
  /gs-?auto-?clicker/i,
  /murgee.*clicker/i,
  /fast\.?clicker/i,

  // General cheat distribution
  /minecraft.*cheat/i, /minecraft.*hack/i,
  /mc.*hack.*client/i,
  /minecraft.*inject/i,
  /hacked\.?client/i,
  /cheat.*download/i,
  /macro.*minecraft/i,
  /minecraft.*macro/i,

  // Specific cheat hosting
  /github\.com.*cheat.*client/i,
  /github\.com.*hack.*client/i,
  /mediafire\.com.*cheat/i,
  /mega\.nz.*cheat/i
];

/**
 * Suspicious file download name patterns
 */
const SUSPICIOUS_DOWNLOAD_NAMES = [
  /198macro/i, /zenithmacro/i, /crystalspkmacro/i,
  /autoclicker/i, /auto[_\-\s]clicker/i,
  /wurst/i, /meteor.*client/i, /impact.*client/i,
  /aristois/i, /rusherhack/i, /futureclient/i,
  /thunderhack/i, /bleachhack/i, /gamesense/i,
  /hack.*client/i, /cheat.*client/i,
  /inject(?:or)?\.(?:exe|dll|jar)/i,
  /macro.*tool/i, /click.*bot/i,
  /killaura/i, /aimassist/i, /triggerbot/i,
  /\.ahk$/i
];

/**
 * Suspicious browser extension patterns
 */
const SUSPICIOUS_EXTENSIONS = [
  /auto.*click/i, /click.*auto/i,
  /macro.*record/i, /mouse.*record/i,
  /click.*repeat/i, /rapid.*click/i,
  /minecraft.*cheat/i, /hack.*assist/i
];

/**
 * Browser definitions with profile and history paths
 */
const BROWSERS = {
  chrome: {
    name: 'Google Chrome',
    profileBase: '%LOCALAPPDATA%\\Google\\Chrome\\User Data',
    historyFile: 'History',
    bookmarksFile: 'Bookmarks',
    extensionsDir: 'Extensions',
    profilePattern: /^(Default|Profile \d+)$/
  },
  edge: {
    name: 'Microsoft Edge',
    profileBase: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data',
    historyFile: 'History',
    bookmarksFile: 'Bookmarks',
    extensionsDir: 'Extensions',
    profilePattern: /^(Default|Profile \d+)$/
  },
  firefox: {
    name: 'Mozilla Firefox',
    profileBase: '%APPDATA%\\Mozilla\\Firefox\\Profiles',
    historyFile: 'places.sqlite',
    bookmarksFile: null, // bookmarks are in places.sqlite
    extensionsDir: 'extensions',
    profilePattern: /^[a-z0-9]+\..+$/
  },
  brave: {
    name: 'Brave Browser',
    profileBase: '%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data',
    historyFile: 'History',
    bookmarksFile: 'Bookmarks',
    extensionsDir: 'Extensions',
    profilePattern: /^(Default|Profile \d+)$/
  }
};

/**
 * Resolve environment variables
 */
function resolveEnvPath(pathStr) {
  return pathStr.replace(/%([^%]+)%/g, (_, envVar) => {
    return process.env[envVar] || '';
  });
}

/**
 * Query Chrome/Edge/Brave history using PowerShell + SQLite
 * (copies the locked DB file first)
 */
function queryChromeHistory(historyDbPath) {
  const results = [];

  try {
    if (!fs.existsSync(historyDbPath)) return results;

    // Copy the locked database to a temp location
    const tempDir = process.env.TEMP || process.env.TMP || 'C:\\Windows\\Temp';
    const tempDb = path.join(tempDir, `sstools_history_${Date.now()}.db`);

    try {
      fs.copyFileSync(historyDbPath, tempDb);
    } catch (err) {
      return results;
    }

    // Use PowerShell to read SQLite (Chrome history)
    // We'll extract URLs and filenames from download history using text parsing
    const psCommand = `
      try {
        Add-Type -Path "$env:LOCALAPPDATA\\Google\\Chrome\\Application\\*\\chrome_elf.dll" -ErrorAction SilentlyContinue
      } catch {}
      $bytes = [System.IO.File]::ReadAllBytes('${tempDb.replace(/\\/g, '\\\\')}')
      $text = [System.Text.Encoding]::UTF8.GetString($bytes)
      $urlPattern = 'https?://[^\\x00-\\x1f\\x7f-\\xff]{5,500}'
      $matches = [regex]::Matches($text, $urlPattern)
      foreach ($m in $matches) {
        Write-Output $m.Value
      }
    `;

    try {
      const output = execSync(
        `powershell -NoProfile -Command "${psCommand.replace(/\n/g, ' ').replace(/"/g, '\\"')}"`,
        { encoding: 'utf-8', timeout: 30000, windowsHide: true, maxBuffer: 10 * 1024 * 1024 }
      );

      const urls = output.trim().split('\n').filter(u => u.trim());
      for (const url of urls) {
        for (const pattern of SUSPICIOUS_URLS) {
          if (pattern.test(url)) {
            results.push({
              type: 'url',
              value: url.trim().substring(0, 300),
              matchedPattern: pattern.source,
              severity: 'high'
            });
            break;
          }
        }
      }
    } catch (err) {
      // PowerShell extraction failed, try raw binary string extraction
      try {
        const buffer = fs.readFileSync(tempDb);
        const text = extractStringsFromBuffer(buffer);
        
        for (const pattern of SUSPICIOUS_URLS) {
          if (pattern.test(text)) {
            const match = text.match(pattern);
            results.push({
              type: 'url-binary',
              value: match ? match[0].substring(0, 200) : pattern.source,
              matchedPattern: pattern.source,
              severity: 'high'
            });
          }
        }

        for (const pattern of SUSPICIOUS_DOWNLOAD_NAMES) {
          if (pattern.test(text)) {
            const match = text.match(pattern);
            results.push({
              type: 'download-binary',
              value: match ? match[0].substring(0, 200) : pattern.source,
              matchedPattern: pattern.source,
              severity: 'critical'
            });
          }
        }
      } catch (innerErr) {
        // Cannot read the file
      }
    }

    // Cleanup temp file
    try { fs.unlinkSync(tempDb); } catch (e) { /* ignore */ }
  } catch (err) {
    // History scan failed
  }

  return results;
}

/**
 * Extract readable strings from a binary buffer
 */
function extractStringsFromBuffer(buffer) {
  const strings = [];
  let current = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 32 && byte < 127) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 6) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 6) {
    strings.push(current);
  }

  return strings.join(' ');
}

/**
 * Scan Chrome/Edge/Brave bookmarks
 */
function scanBookmarks(bookmarksPath) {
  const results = [];

  try {
    if (!fs.existsSync(bookmarksPath)) return results;

    const content = fs.readFileSync(bookmarksPath, 'utf-8');
    
    for (const pattern of SUSPICIOUS_URLS) {
      if (pattern.test(content)) {
        const match = content.match(pattern);
        results.push({
          type: 'bookmark',
          value: match ? match[0].substring(0, 200) : pattern.source,
          matchedPattern: pattern.source,
          severity: 'high'
        });
      }
    }
  } catch (err) {
    // Cannot read bookmarks
  }

  return results;
}

/**
 * Scan browser extensions directory for suspicious extensions
 */
function scanExtensions(extensionsDir) {
  const results = [];

  try {
    if (!fs.existsSync(extensionsDir)) return results;

    const extensions = fs.readdirSync(extensionsDir);
    for (const extId of extensions) {
      const extPath = path.join(extensionsDir, extId);
      try {
        const stats = fs.statSync(extPath);
        if (!stats.isDirectory()) continue;

        // Look for manifest.json in version subdirectories
        const versions = fs.readdirSync(extPath);
        for (const version of versions) {
          const manifestPath = path.join(extPath, version, 'manifest.json');
          if (fs.existsSync(manifestPath)) {
            try {
              const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
              const extName = manifest.name || '';
              const extDesc = manifest.description || '';
              const combined = `${extName} ${extDesc}`;

              for (const pattern of SUSPICIOUS_EXTENSIONS) {
                if (pattern.test(combined)) {
                  results.push({
                    type: 'extension',
                    extensionId: extId,
                    name: extName.substring(0, 100),
                    description: extDesc.substring(0, 200),
                    matchedPattern: pattern.source,
                    severity: 'high'
                  });
                  break;
                }
              }
            } catch (e) {
              // Invalid manifest
            }
          }
        }
      } catch (err) {
        // Skip
      }
    }
  } catch (err) {
    // Cannot scan extensions
  }

  return results;
}

/**
 * Scan all browsers for cheat-related activity
 */
function scanBrowsers() {
  const results = {
    browsers: [],
    totalDetections: 0,
    scannedAt: new Date().toISOString(),
    status: 'clean'
  };

  for (const [browserId, browser] of Object.entries(BROWSERS)) {
    const browserResult = {
      id: browserId,
      name: browser.name,
      installed: false,
      profiles: [],
      detections: [],
      totalDetections: 0
    };

    const basePath = resolveEnvPath(browser.profileBase);
    if (!basePath || !fs.existsSync(basePath)) {
      results.browsers.push(browserResult);
      continue;
    }

    browserResult.installed = true;

    try {
      const items = fs.readdirSync(basePath);
      const profiles = items.filter(item => {
        try {
          return fs.statSync(path.join(basePath, item)).isDirectory() &&
                 browser.profilePattern.test(item);
        } catch (e) {
          return false;
        }
      });

      for (const profile of profiles) {
        const profilePath = path.join(basePath, profile);
        const profileResult = {
          name: profile,
          historyDetections: [],
          bookmarkDetections: [],
          extensionDetections: []
        };

        // Scan history
        const historyPath = path.join(profilePath, browser.historyFile);
        profileResult.historyDetections = queryChromeHistory(historyPath);

        // Scan bookmarks
        if (browser.bookmarksFile) {
          const bookmarksPath = path.join(profilePath, browser.bookmarksFile);
          profileResult.bookmarkDetections = scanBookmarks(bookmarksPath);
        }

        // Scan extensions
        const extDir = path.join(profilePath, browser.extensionsDir);
        profileResult.extensionDetections = scanExtensions(extDir);

        const profileDetections = profileResult.historyDetections.length +
                                   profileResult.bookmarkDetections.length +
                                   profileResult.extensionDetections.length;

        if (profileDetections > 0) {
          browserResult.profiles.push(profileResult);
          browserResult.detections.push(...profileResult.historyDetections);
          browserResult.detections.push(...profileResult.bookmarkDetections);
          browserResult.detections.push(...profileResult.extensionDetections);
          browserResult.totalDetections += profileDetections;
        }
      }
    } catch (err) {
      browserResult.error = err.message;
    }

    results.browsers.push(browserResult);
    results.totalDetections += browserResult.totalDetections;
  }

  if (results.totalDetections > 0) {
    results.status = 'detected';
  }

  return results;
}

module.exports = {
  scanBrowsers,
  queryChromeHistory,
  scanBookmarks,
  scanExtensions,
  BROWSERS,
  SUSPICIOUS_URLS,
  SUSPICIOUS_DOWNLOAD_NAMES
};
