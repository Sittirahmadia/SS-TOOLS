/**
 * Keyword Engine Module
 * Advanced matching engine used by all scanners:
 * - Exact match
 * - Regex pattern matching
 * - Wildcard matching (glob-style)
 * - Fuzzy matching with configurable threshold
 * - Levenshtein distance for typo/obfuscation detection
 * - Multi-layer detection scoring
 *
 * Loads keywords from cheat-signatures/keywords.json
 * and provides a unified API for all scanner modules.
 */

const path = require('path');
const fs = require('fs');

// Load keyword database
let keywordDB = null;

function loadKeywordDatabase() {
  if (keywordDB) return keywordDB;

  const dbPath = path.join(__dirname, '..', 'cheat-signatures', 'keywords.json');
  try {
    const raw = fs.readFileSync(dbPath, 'utf-8');
    keywordDB = JSON.parse(raw);
  } catch (err) {
    keywordDB = { categories: {}, regex_patterns: {} };
  }
  return keywordDB;
}

/**
 * Get all keywords as a flat array with metadata
 */
function getAllKeywords() {
  const db = loadKeywordDatabase();
  const results = [];

  for (const [categoryId, category] of Object.entries(db.categories || {})) {
    for (const keyword of (category.keywords || [])) {
      results.push({
        keyword,
        category: categoryId,
        categoryName: category.name,
        severity: category.severity
      });
    }
  }

  return results;
}

/**
 * Get all regex patterns from the database
 */
function getRegexPatterns() {
  const db = loadKeywordDatabase();
  const patterns = [];

  for (const [name, patternStr] of Object.entries(db.regex_patterns || {})) {
    try {
      patterns.push({
        name,
        regex: new RegExp(patternStr, 'gi'),
        pattern: patternStr
      });
    } catch (err) {
      // Invalid regex, skip
    }
  }

  return patterns;
}

// ============================================================
// Matching Algorithms
// ============================================================

/**
 * Compute Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  const la = a.length;
  const lb = b.length;

  if (la === 0) return lb;
  if (lb === 0) return la;

  // Use single-row optimization for memory efficiency
  let prev = new Array(lb + 1);
  let curr = new Array(lb + 1);

  for (let j = 0; j <= lb; j++) prev[j] = j;

  for (let i = 1; i <= la; i++) {
    curr[0] = i;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[lb];
}

/**
 * Normalized Levenshtein similarity (0.0 to 1.0)
 */
function levenshteinSimilarity(a, b) {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1.0;
  return 1.0 - levenshteinDistance(a.toLowerCase(), b.toLowerCase()) / maxLen;
}

/**
 * Wildcard/glob pattern matching
 * Supports * (any chars) and ? (single char)
 */
function wildcardMatch(text, pattern) {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex specials
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  try {
    return new RegExp(`^${regexStr}$`, 'i').test(text);
  } catch (err) {
    return false;
  }
}

/**
 * Fuzzy substring match -- checks if keyword is approximately present in text
 * Uses sliding window with Levenshtein distance
 */
function fuzzyContains(text, keyword, threshold = 0.8) {
  const textLower = text.toLowerCase();
  const keyLower = keyword.toLowerCase();

  // Exact substring check first (fast path)
  if (textLower.includes(keyLower)) return { match: true, score: 1.0, type: 'exact' };

  // Skip fuzzy for very short keywords (too many false positives)
  if (keyLower.length < 5) return { match: false, score: 0, type: 'none' };

  // Sliding window fuzzy match
  const windowSize = keyLower.length;
  let bestScore = 0;
  let bestMatch = '';

  for (let i = 0; i <= textLower.length - windowSize; i++) {
    const window = textLower.substring(i, i + windowSize);
    const similarity = levenshteinSimilarity(window, keyLower);

    if (similarity > bestScore) {
      bestScore = similarity;
      bestMatch = text.substring(i, i + windowSize);
    }
  }

  // Also check slightly larger windows for insertions
  for (let extra = 1; extra <= 2; extra++) {
    const ws = windowSize + extra;
    if (ws > textLower.length) break;

    for (let i = 0; i <= textLower.length - ws; i++) {
      const window = textLower.substring(i, i + ws);
      const similarity = levenshteinSimilarity(window, keyLower);

      if (similarity > bestScore) {
        bestScore = similarity;
        bestMatch = text.substring(i, i + ws);
      }
    }
  }

  return {
    match: bestScore >= threshold,
    score: bestScore,
    type: bestScore >= threshold ? 'fuzzy' : 'none',
    bestMatch
  };
}

/**
 * Check if a keyword match is a false positive based on context
 */
function isFalsePositive(keyword, context) {
  const fpRules = {
    'Speed': (ctx) => {
      const cheatCtx = ['hack', 'cheat', 'module', 'toggle', 'enable', 'setting', 'bypass'];
      return !cheatCtx.some(w => ctx.toLowerCase().includes(w));
    },
    'Fly': (ctx) => {
      const l = ctx.toLowerCase();
      return l.includes('butterfly') || l.includes('elytra') || l.includes('firefly') || l.includes('flywheel');
    },
    'Flight': (ctx) => {
      const l = ctx.toLowerCase();
      return l.includes('elytra') || l.includes('creative');
    },
    'Timer': (ctx) => {
      const l = ctx.toLowerCase();
      return l.includes('countdown') || l.includes('scheduler') || l.includes('timeout') || l.includes('interval');
    },
    'ESP': (ctx) => {
      const l = ctx.toLowerCase();
      return l.includes('espresso') || l.includes('especially') || l.includes('response');
    },
    'Search': () => true,
    'Step': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('stephack') && !l.includes('step hack') && !l.includes('module') && !l.includes('cheat');
    },
    'Tower': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('scaffold') && !l.includes('module') && !l.includes('cheat') && !l.includes('hack');
    },
    'Reach': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('module') && !l.includes('cheat') && !l.includes('hack') && !l.includes('combat');
    },
    'Impact': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat') && !l.includes('hack') && !l.includes('module');
    },
    'Crystal': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('aura') && !l.includes('pvp') && !l.includes('place') && !l.includes('break') && !l.includes('macro');
    },
    'Future': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat') && !l.includes('hack');
    },
    'Lambda': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat') && !l.includes('hack');
    },
    'Meteor': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat') && !l.includes('development');
    },
    'Rise': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat');
    },
    'Moon': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('client') && !l.includes('cheat');
    },
    'Zoom': () => true,
    'Radar': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('cheat') && !l.includes('hack') && !l.includes('module');
    },
    'Compass': () => true,
    'Coordinates': () => true,
    'Waypoints': () => true
  };

  return fpRules[keyword] ? fpRules[keyword](context) : false;
}

// ============================================================
// Unified Scan API
// ============================================================

/**
 * Scan text using all matching methods
 * Returns array of detection results
 *
 * Options:
 *   exact: true     -- Exact substring matching (default: true)
 *   regex: true     -- Regex pattern matching (default: true)
 *   fuzzy: true     -- Fuzzy/Levenshtein matching (default: false)
 *   fuzzyThreshold: 0.8  -- Fuzzy match threshold (default: 0.8)
 *   wildcards: []   -- Additional wildcard patterns to check
 *   checkFP: true   -- Run false positive checks (default: true)
 *   categories: []  -- Limit to specific categories (default: all)
 *   minSeverity: '' -- Minimum severity filter
 */
function scanText(text, options = {}) {
  const opts = {
    exact: true,
    regex: true,
    fuzzy: false,
    fuzzyThreshold: 0.8,
    wildcards: [],
    checkFP: true,
    categories: [],
    minSeverity: '',
    ...options
  };

  const detections = [];
  const seen = new Set();
  const textLower = text.toLowerCase();
  const allKeywords = getAllKeywords();

  // Filter by category if specified
  const keywords = opts.categories.length > 0
    ? allKeywords.filter(k => opts.categories.includes(k.category))
    : allKeywords;

  // Filter by severity
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const minSev = severityOrder[opts.minSeverity] || 0;

  // 1. Exact keyword matching
  if (opts.exact) {
    for (const entry of keywords) {
      if ((severityOrder[entry.severity] || 0) < minSev) continue;

      const keyLower = entry.keyword.toLowerCase();

      if (textLower.includes(keyLower)) {
        // Case-sensitive check for short keywords
        if (entry.keyword.length <= 4 && !text.includes(entry.keyword)) continue;

        // False positive check
        if (opts.checkFP && isFalsePositive(entry.keyword, text)) continue;

        const key = `exact:${entry.keyword}:${entry.category}`;
        if (!seen.has(key)) {
          seen.add(key);
          detections.push({
            keyword: entry.keyword,
            category: entry.categoryName,
            categoryId: entry.category,
            severity: entry.severity,
            matchType: 'exact',
            score: 1.0
          });
        }
      }
    }
  }

  // 2. Regex pattern matching
  if (opts.regex) {
    const regexPatterns = getRegexPatterns();
    for (const { name, regex } of regexPatterns) {
      regex.lastIndex = 0;
      const matches = text.match(regex);
      if (matches) {
        for (const match of matches.slice(0, 10)) {
          const key = `regex:${name}:${match}`;
          if (!seen.has(key)) {
            seen.add(key);
            detections.push({
              keyword: match,
              category: `Regex: ${name}`,
              categoryId: 'regex',
              severity: 'high',
              matchType: 'regex',
              patternName: name,
              score: 0.9
            });
          }
        }
      }
    }
  }

  // 3. Fuzzy matching (Levenshtein)
  if (opts.fuzzy) {
    // Only check critical/high severity keywords for fuzzy to limit false positives
    const fuzzyKeywords = keywords.filter(k =>
      k.severity === 'critical' && k.keyword.length >= 6
    );

    for (const entry of fuzzyKeywords) {
      if ((severityOrder[entry.severity] || 0) < minSev) continue;

      const key = `exact:${entry.keyword}:${entry.category}`;
      if (seen.has(key)) continue; // Already found via exact match

      const result = fuzzyContains(text, entry.keyword, opts.fuzzyThreshold);
      if (result.match && result.type === 'fuzzy') {
        const fkey = `fuzzy:${entry.keyword}:${entry.category}`;
        if (!seen.has(fkey)) {
          seen.add(fkey);
          detections.push({
            keyword: entry.keyword,
            category: entry.categoryName,
            categoryId: entry.category,
            severity: entry.severity,
            matchType: 'fuzzy',
            score: result.score,
            fuzzyMatch: result.bestMatch
          });
        }
      }
    }
  }

  // 4. Wildcard matching
  if (opts.wildcards && opts.wildcards.length > 0) {
    for (const pattern of opts.wildcards) {
      if (wildcardMatch(text, pattern)) {
        const key = `wildcard:${pattern}`;
        if (!seen.has(key)) {
          seen.add(key);
          detections.push({
            keyword: pattern,
            category: 'Wildcard Match',
            categoryId: 'wildcard',
            severity: 'high',
            matchType: 'wildcard',
            score: 0.85
          });
        }
      }
    }
  }

  // Sort by severity then score
  detections.sort((a, b) => {
    const sevDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    return b.score - a.score;
  });

  return detections;
}

/**
 * Quick check if text contains any cheat-related keyword
 * Returns boolean -- faster than full scanText
 */
function quickCheck(text) {
  const textLower = text.toLowerCase();
  const allKeywords = getAllKeywords();

  for (const entry of allKeywords) {
    if (entry.severity !== 'critical') continue;
    if (textLower.includes(entry.keyword.toLowerCase())) {
      if (entry.keyword.length <= 4 && !text.includes(entry.keyword)) continue;
      if (!isFalsePositive(entry.keyword, text)) return true;
    }
  }

  return false;
}

/**
 * Multi-layer detection scoring
 * Combines results from multiple detection methods into a confidence score
 */
function multiLayerScore(layers) {
  // layers = { hash: bool, signature: detections[], behavior: detections[], memory: detections[], bytecode: detections[] }
  let score = 0;
  let maxSeverity = 'low';
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

  // Hash match is definitive
  if (layers.hash) {
    score += 50;
    maxSeverity = 'critical';
  }

  // Signature matches
  if (layers.signature && layers.signature.length > 0) {
    const critCount = layers.signature.filter(d => d.severity === 'critical').length;
    const highCount = layers.signature.filter(d => d.severity === 'high').length;
    score += Math.min(30, critCount * 10 + highCount * 5);

    for (const d of layers.signature) {
      if ((severityOrder[d.severity] || 0) > (severityOrder[maxSeverity] || 0)) {
        maxSeverity = d.severity;
      }
    }
  }

  // Behavior analysis
  if (layers.behavior && layers.behavior.length > 0) {
    score += Math.min(15, layers.behavior.length * 5);
    for (const d of layers.behavior) {
      if ((severityOrder[d.severity] || 0) > (severityOrder[maxSeverity] || 0)) {
        maxSeverity = d.severity;
      }
    }
  }

  // Memory scan
  if (layers.memory && layers.memory.length > 0) {
    score += Math.min(20, layers.memory.length * 8);
    for (const d of layers.memory) {
      if ((severityOrder[d.severity] || 0) > (severityOrder[maxSeverity] || 0)) {
        maxSeverity = d.severity;
      }
    }
  }

  // Bytecode analysis
  if (layers.bytecode && layers.bytecode.length > 0) {
    score += Math.min(25, layers.bytecode.length * 7);
    for (const d of layers.bytecode) {
      if ((severityOrder[d.severity] || 0) > (severityOrder[maxSeverity] || 0)) {
        maxSeverity = d.severity;
      }
    }
  }

  return {
    score: Math.min(100, score),
    confidence: score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low',
    severity: maxSeverity,
    isDetected: score >= 30
  };
}

/**
 * Invalidate cached keyword database (for hot-reload)
 */
function reloadDatabase() {
  keywordDB = null;
  return loadKeywordDatabase();
}

module.exports = {
  // Core API
  scanText,
  quickCheck,
  getAllKeywords,
  getRegexPatterns,
  loadKeywordDatabase,
  reloadDatabase,

  // Matching functions
  levenshteinDistance,
  levenshteinSimilarity,
  wildcardMatch,
  fuzzyContains,
  isFalsePositive,

  // Multi-layer detection
  multiLayerScore
};
