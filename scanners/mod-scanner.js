/**
 * Mod Scanner Module
 * Scans Minecraft mod files (.jar, .zip) for cheat-related keywords
 */

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const keywords = require('../cheat-signatures/keywords.json');

const MAX_UPLOAD_SIZE = 500 * 1024 * 1024; // 500MB

/**
 * Build a flat list of all keywords from all categories
 */
function getAllKeywords() {
  const allKeywords = [];
  for (const [categoryId, category] of Object.entries(keywords.categories)) {
    for (const keyword of category.keywords) {
      allKeywords.push({
        keyword: keyword,
        category: categoryId,
        categoryName: category.name,
        severity: category.severity
      });
    }
  }
  return allKeywords;
}

/**
 * Scan a single mod file (jar/zip) for cheat keywords
 */
function scanModFile(filePath) {
  const results = {
    file: path.basename(filePath),
    path: filePath,
    size: 0,
    detections: [],
    scannedEntries: 0,
    status: 'clean'
  };

  try {
    const stats = fs.statSync(filePath);
    results.size = stats.size;

    if (stats.size > MAX_UPLOAD_SIZE) {
      results.status = 'skipped';
      results.error = 'File exceeds 500MB limit';
      return results;
    }

    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.jar' && ext !== '.zip' && ext !== '.litemod') {
      // For non-archive files, scan filename only
      const filenameDetections = scanStringForKeywords(path.basename(filePath));
      if (filenameDetections.length > 0) {
        results.detections.push({
          location: 'filename',
          matches: filenameDetections
        });
        results.status = 'detected';
      }
      return results;
    }

    // Open as ZIP archive
    const zip = new AdmZip(filePath);
    const entries = zip.getEntries();
    results.scannedEntries = entries.length;

    // Scan each entry in the archive
    for (const entry of entries) {
      const entryName = entry.entryName;

      // Scan entry path/name for keywords
      const nameDetections = scanStringForKeywords(entryName);
      if (nameDetections.length > 0) {
        results.detections.push({
          location: `entry:${entryName}`,
          type: 'filename',
          matches: nameDetections
        });
      }

      // For .class files, scan the bytecode strings
      if (entryName.endsWith('.class') || entryName.endsWith('.json') || 
          entryName.endsWith('.txt') || entryName.endsWith('.cfg') ||
          entryName.endsWith('.properties') || entryName.endsWith('.mcmeta') ||
          entryName.endsWith('.toml') || entryName.endsWith('.yml') ||
          entryName.endsWith('.yaml') || entryName.endsWith('.xml')) {
        try {
          const content = entry.getData();
          if (content && content.length < 10 * 1024 * 1024) { // Skip files > 10MB
            const text = extractStringsFromBuffer(content);
            const contentDetections = scanStringForKeywords(text);
            if (contentDetections.length > 0) {
              results.detections.push({
                location: `entry:${entryName}`,
                type: 'content',
                matches: contentDetections
              });
            }
          }
        } catch (err) {
          // Skip unreadable entries
        }
      }

      // Scan fabric.mod.json / mods.toml for mod metadata
      if (entryName === 'fabric.mod.json' || entryName === 'META-INF/mods.toml' ||
          entryName === 'mcmod.info' || entryName === 'quilt.mod.json') {
        try {
          const content = entry.getData().toString('utf-8');
          const metaDetections = scanStringForKeywords(content);
          if (metaDetections.length > 0) {
            results.detections.push({
              location: `metadata:${entryName}`,
              type: 'metadata',
              matches: metaDetections
            });
          }
        } catch (err) {
          // Skip
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
      if (current.length >= 4) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 4) {
    strings.push(current);
  }

  return strings.join(' ');
}

/**
 * Scan a string for cheat keywords
 */
function scanStringForKeywords(text) {
  const allKeywords = getAllKeywords();
  const matches = [];
  const textLower = text.toLowerCase();

  for (const entry of allKeywords) {
    const keywordLower = entry.keyword.toLowerCase();
    if (textLower.includes(keywordLower)) {
      // Verify case-sensitive match for short keywords to reduce false positives
      if (entry.keyword.length <= 4) {
        if (!text.includes(entry.keyword)) continue;
      }

      // Additional false-positive prevention
      if (isFalsePositive(entry.keyword, text)) continue;

      matches.push({
        keyword: entry.keyword,
        category: entry.categoryName,
        severity: entry.severity
      });
    }
  }

  // Deduplicate
  const seen = new Set();
  return matches.filter(m => {
    const key = `${m.keyword}:${m.category}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Check if a keyword match is a false positive
 */
function isFalsePositive(keyword, context) {
  const falsePositiveRules = {
    'Speed': (ctx) => {
      // "Speed" alone is too generic — only flag if near cheat-related words
      const cheatContext = ['hack', 'cheat', 'module', 'toggle', 'enable', 'setting', 'bypass'];
      const nearby = ctx.toLowerCase();
      return !cheatContext.some(w => nearby.includes(w));
    },
    'Fly': (ctx) => {
      // "Fly" is common in legitimate mods (Elytra, butterfly, etc.)
      const ctxLower = ctx.toLowerCase();
      if (ctxLower.includes('butterfly') || ctxLower.includes('elytra') || 
          ctxLower.includes('firefly') || ctxLower.includes('flywheel')) {
        return true;
      }
      return false;
    },
    'Flight': (ctx) => {
      const ctxLower = ctx.toLowerCase();
      if (ctxLower.includes('elytra') || ctxLower.includes('creative')) {
        return true;
      }
      return false;
    },
    'Timer': (ctx) => {
      // Timer is common in normal code
      const ctxLower = ctx.toLowerCase();
      if (ctxLower.includes('countdown') || ctxLower.includes('scheduler') || 
          ctxLower.includes('timeout') || ctxLower.includes('interval')) {
        return true;
      }
      return false;
    },
    'ESP': (ctx) => {
      // ESP can be false positive in encoding contexts
      const ctxLower = ctx.toLowerCase();
      if (ctxLower.includes('espresso') || ctxLower.includes('especially')) {
        return true;
      }
      return false;
    },
    'Search': (ctx) => {
      // Search is too generic
      return true;
    },
    'Step': (ctx) => {
      // Step is too generic
      const ctxLower = ctx.toLowerCase();
      if (!ctxLower.includes('stephack') && !ctxLower.includes('step hack') &&
          !ctxLower.includes('module') && !ctxLower.includes('cheat')) {
        return true;
      }
      return false;
    },
    'Tower': (ctx) => {
      const ctxLower = ctx.toLowerCase();
      if (!ctxLower.includes('scaffold') && !ctxLower.includes('module') &&
          !ctxLower.includes('cheat') && !ctxLower.includes('hack')) {
        return true;
      }
      return false;
    },
    'Reach': (ctx) => {
      const ctxLower = ctx.toLowerCase();
      if (!ctxLower.includes('module') && !ctxLower.includes('cheat') &&
          !ctxLower.includes('hack') && !ctxLower.includes('combat')) {
        return true;
      }
      return false;
    }
  };

  if (falsePositiveRules[keyword]) {
    return falsePositiveRules[keyword](context);
  }

  return false;
}

/**
 * Scan an entire mods folder
 */
function scanModsFolder(folderPath) {
  const results = {
    folder: folderPath,
    totalFiles: 0,
    scannedFiles: 0,
    detectedFiles: 0,
    cleanFiles: 0,
    errorFiles: 0,
    files: [],
    totalSize: 0
  };

  if (!fs.existsSync(folderPath)) {
    results.error = 'Folder does not exist';
    return results;
  }

  const files = fs.readdirSync(folderPath);
  const modExtensions = ['.jar', '.zip', '.litemod', '.disabled'];

  for (const file of files) {
    const filePath = path.join(folderPath, file);
    const ext = path.extname(file).toLowerCase();

    try {
      const stats = fs.statSync(filePath);
      if (stats.isDirectory()) continue;

      results.totalFiles++;
      results.totalSize += stats.size;

      if (results.totalSize > MAX_UPLOAD_SIZE) {
        results.error = 'Total folder size exceeds 500MB limit';
        break;
      }

      if (modExtensions.includes(ext)) {
        const fileResult = scanModFile(filePath);
        results.files.push(fileResult);
        results.scannedFiles++;

        if (fileResult.status === 'detected') {
          results.detectedFiles++;
        } else if (fileResult.status === 'clean') {
          results.cleanFiles++;
        } else if (fileResult.status === 'error') {
          results.errorFiles++;
        }
      }
    } catch (err) {
      results.errorFiles++;
    }
  }

  return results;
}

module.exports = {
  scanModFile,
  scanModsFolder,
  scanStringForKeywords,
  getAllKeywords,
  MAX_UPLOAD_SIZE
};
