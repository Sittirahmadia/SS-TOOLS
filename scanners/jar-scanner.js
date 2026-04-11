/**
 * JAR Scanner / Decompiler Module
 * Deep scans Minecraft .jar files:
 * - Extracts and analyzes all .class files via bytecode inspection
 * - Detects known cheat signatures, injected hooks, modified vanilla classes
 * - Identifies obfuscated cheat methods, illegal packet manipulation
 * - Auto-click logic, kill-aura patterns, velocity manipulation
 * - Scans JVM arguments and Fabric/Forge mod metadata
 */

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const keywords = require('../cheat-signatures/keywords.json');

/**
 * Java bytecode constants for .class file parsing
 */
const JAVA_CLASS_MAGIC = 0xCAFEBABE;

/**
 * Vanilla Minecraft classes that are commonly modified by cheats
 */
const VANILLA_CLASSES = [
  'net/minecraft/client/Minecraft',
  'net/minecraft/client/entity/EntityPlayerSP',
  'net/minecraft/entity/EntityLivingBase',
  'net/minecraft/entity/Entity',
  'net/minecraft/entity/player/EntityPlayer',
  'net/minecraft/world/World',
  'net/minecraft/client/renderer/EntityRenderer',
  'net/minecraft/network/play/client',
  'net/minecraft/client/multiplayer/PlayerControllerMP',
  'net/minecraft/client/gui/GuiIngame',
  'net/minecraft/client/settings/KeyBinding',
  // Modern (1.17+) mappings
  'net/minecraft/class_310',  // Minecraft (intermediary)
  'net/minecraft/class_746',  // ClientPlayerEntity
  'net/minecraft/class_1309', // LivingEntity
  'net/minecraft/class_1297', // Entity
  'net/minecraft/class_1657', // PlayerEntity
  'net/minecraft/class_1937', // World
];

/**
 * Suspicious Java class/package patterns indicating cheats
 */
const CHEAT_CLASS_PATTERNS = [
  // Known cheat client packages
  { pattern: /^net\/wurstclient/i, severity: 'critical', description: 'Wurst client class' },
  { pattern: /^meteordevelopment/i, severity: 'critical', description: 'Meteor client class' },
  { pattern: /^mathax/i, severity: 'critical', description: 'MatHax client class' },
  { pattern: /^anticope/i, severity: 'critical', description: 'Anticope addon' },
  { pattern: /^dev\/lars/i, severity: 'critical', description: 'Possible Aristois class' },
  { pattern: /^org\/rusherhack/i, severity: 'critical', description: 'RusherHack class' },
  { pattern: /^me\/earth2me/i, severity: 'critical', description: 'Possible cheat client' },
  { pattern: /^thunderhack/i, severity: 'critical', description: 'ThunderHack class' },
  { pattern: /^bleach/i, severity: 'high', description: 'Possible BleachHack class' },
  { pattern: /^gamesense/i, severity: 'critical', description: 'GameSense class' },
  { pattern: /^lambda/i, severity: 'high', description: 'Possible Lambda client class' },
  { pattern: /^future/i, severity: 'high', description: 'Possible Future client class' },
  { pattern: /^inertia/i, severity: 'high', description: 'Possible Inertia client class' },
  
  // Generic cheat patterns
  { pattern: /(?:^|\/)(?:hack|cheat|exploit|inject)\//i, severity: 'critical', description: 'Cheat-related package' },
  { pattern: /(?:^|\/)module\/(?:combat|movement|player|render|world|exploit)/i, severity: 'critical', description: 'Cheat module structure' },
  { pattern: /(?:^|\/)modules?\/(?:killaura|aimassist|triggerbot|autocrystal|reach|velocity|fly|speed|noclip|xray)/i, severity: 'critical', description: 'Named cheat module class' },
  { pattern: /(?:^|\/)hud\/(?:arraylist|watermark|tabgui)/i, severity: 'high', description: 'Cheat client HUD class' },
  { pattern: /(?:^|\/)gui\/(?:clickgui|hudeditor)/i, severity: 'high', description: 'Cheat client GUI class' },
  { pattern: /(?:^|\/)mixin\/.*(?:Entity|Player|World|Render|Network|Packet)/i, severity: 'high', description: 'Suspicious mixin targeting vanilla classes' }
];

/**
 * Bytecode-level cheat patterns (string constants in .class files)
 */
const BYTECODE_CHEAT_STRINGS = [
  // Module names
  { pattern: /killaura/i, severity: 'critical', description: 'KillAura module reference' },
  { pattern: /aimassist/i, severity: 'critical', description: 'AimAssist module reference' },
  { pattern: /triggerbot/i, severity: 'critical', description: 'Triggerbot module reference' },
  { pattern: /autocrystal/i, severity: 'critical', description: 'AutoCrystal module reference' },
  { pattern: /crystalaura/i, severity: 'critical', description: 'CrystalAura module reference' },
  { pattern: /velocity/i, severity: 'high', description: 'Velocity manipulation reference' },
  { pattern: /antikb|antiknockback|nokb/i, severity: 'critical', description: 'AntiKB/NoKnockback reference' },
  { pattern: /nofall/i, severity: 'high', description: 'NoFall reference' },
  { pattern: /scaffold/i, severity: 'high', description: 'Scaffold reference' },
  { pattern: /autototem/i, severity: 'high', description: 'AutoTotem reference' },
  { pattern: /baritone/i, severity: 'medium', description: 'Baritone pathfinder (often used with cheats)' },
  
  // Packet manipulation
  { pattern: /packetfly/i, severity: 'critical', description: 'PacketFly reference' },
  { pattern: /packetcancel/i, severity: 'critical', description: 'Packet cancellation reference' },
  { pattern: /packetmod/i, severity: 'critical', description: 'Packet modification reference' },
  { pattern: /(?:send|receive)packet.*(?:cancel|modify|inject)/i, severity: 'critical', description: 'Packet manipulation code' },
  { pattern: /C00PacketPlayer|CPacketPlayer/i, severity: 'high', description: 'Direct player packet access' },
  
  // Auto-click / combat logic
  { pattern: /(?:auto|rapid).*click/i, severity: 'critical', description: 'Auto/rapid click logic' },
  { pattern: /cps.*(?:random|range|min|max)/i, severity: 'critical', description: 'CPS manipulation' },
  { pattern: /clickdelay.*(?:random|jitter)/i, severity: 'critical', description: 'Click delay randomization (anti-detection)' },
  
  // Render/ESP
  { pattern: /wallhack/i, severity: 'critical', description: 'Wallhack reference' },
  { pattern: /(?:player|entity|chest|storage)esp/i, severity: 'critical', description: 'ESP reference' },
  { pattern: /tracers?(?:line|render)/i, severity: 'high', description: 'Tracer/line rendering (ESP)' },
  { pattern: /nametag.*(?:render|custom|health)/i, severity: 'high', description: 'Custom nametag rendering' },
  { pattern: /xray/i, severity: 'high', description: 'X-Ray reference' },
  { pattern: /fullbright|gammabright/i, severity: 'medium', description: 'Fullbright reference' },
  
  // Obfuscated cheat patterns (common obfuscator outputs)
  { pattern: /\$\$\$(?:module|hack|cheat)/i, severity: 'critical', description: 'Obfuscated cheat reference' },
  { pattern: /(?:enable|disable|toggle)module/i, severity: 'high', description: 'Module toggle logic' },
  { pattern: /modulemanager|hackmanager|cheatmanager/i, severity: 'critical', description: 'Cheat module manager' },
  { pattern: /eventbus.*(?:register|subscribe)/i, severity: 'medium', description: 'Event bus (common in cheat clients)' }
];

/**
 * Whitelist patterns for legitimate mods to reduce false positives
 */
const LEGITIMATE_MOD_PATTERNS = [
  /^net\/fabricmc/i,        // Fabric loader
  /^net\/minecraftforge/i,  // Forge
  /^org\/quiltmc/i,         // Quilt
  /^net\/optifine/i,        // OptiFine
  /^com\/mojang/i,          // Mojang
  /^me\/jellysquid/i,       // Sodium/Lithium/Phosphor
  /^cafe\/rab/i,            // Sodium extra
  /^net\/coderbot/i,        // WorldEdit
  /^com\/sk89q/i,           // WorldEdit
  /^net\/labymod/i,         // LabyMod
  /^de\/florianmichael/i,   // ViaFabricPlus
  /^com\/viaversion/i,      // ViaVersion
  /^net\/raphimc/i,         // ViaFabricPlus
];

/**
 * Parse a Java .class file and extract useful information
 */
function parseClassFile(buffer) {
  const result = {
    isValid: false,
    version: null,
    className: null,
    superClass: null,
    interfaces: [],
    strings: [],
    methods: [],
    fields: []
  };

  try {
    if (buffer.length < 10) return result;

    // Check magic number
    const magic = buffer.readUInt32BE(0);
    if (magic !== JAVA_CLASS_MAGIC) return result;
    result.isValid = true;

    // Version
    const minorVersion = buffer.readUInt16BE(4);
    const majorVersion = buffer.readUInt16BE(6);
    result.version = `${majorVersion}.${minorVersion}`;

    // Extract string constants from constant pool
    // We'll do a simplified extraction of UTF-8 strings
    const strings = extractUTF8Constants(buffer);
    result.strings = strings;

    // Try to identify class name from constants
    for (const str of strings) {
      if (str.includes('/') && !str.includes(' ') && !str.startsWith('(') && str.length > 5) {
        if (!result.className) {
          result.className = str;
        }
      }
    }
  } catch (err) {
    // Parsing error
  }

  return result;
}

/**
 * Extract UTF-8 string constants from a .class file constant pool
 */
function extractUTF8Constants(buffer) {
  const strings = [];

  try {
    if (buffer.length < 10) return strings;

    const constantPoolCount = buffer.readUInt16BE(8);
    let offset = 10;

    for (let i = 1; i < constantPoolCount && offset < buffer.length - 2; i++) {
      const tag = buffer[offset];
      offset++;

      switch (tag) {
        case 1: // UTF-8
          if (offset + 2 > buffer.length) return strings;
          const length = buffer.readUInt16BE(offset);
          offset += 2;
          if (offset + length > buffer.length) return strings;
          const str = buffer.slice(offset, offset + length).toString('utf-8');
          if (str.length >= 3 && str.length <= 500) {
            strings.push(str);
          }
          offset += length;
          break;
        case 3: // Integer
        case 4: // Float
          offset += 4;
          break;
        case 5: // Long
        case 6: // Double
          offset += 8;
          i++; // Longs and doubles take two entries
          break;
        case 7: // Class
        case 8: // String
        case 16: // MethodType
        case 19: // Module
        case 20: // Package
          offset += 2;
          break;
        case 9:  // Fieldref
        case 10: // Methodref
        case 11: // InterfaceMethodref
        case 12: // NameAndType
        case 17: // Dynamic
        case 18: // InvokeDynamic
          offset += 4;
          break;
        case 15: // MethodHandle
          offset += 3;
          break;
        default:
          // Unknown tag, try to continue
          return strings;
      }
    }
  } catch (err) {
    // Parsing error, return what we have
  }

  return strings;
}

/**
 * Deep scan a .class file for cheat indicators
 */
function scanClassFile(entryName, buffer) {
  const results = {
    entry: entryName,
    detections: [],
    classInfo: null
  };

  // Parse the class file
  const classInfo = parseClassFile(buffer);
  results.classInfo = {
    isValid: classInfo.isValid,
    version: classInfo.version,
    className: classInfo.className,
    stringCount: classInfo.strings.length
  };

  if (!classInfo.isValid) return results;

  // Check class path against cheat patterns
  for (const pattern of CHEAT_CLASS_PATTERNS) {
    if (pattern.pattern.test(entryName)) {
      // Check against whitelist
      const isLegit = LEGITIMATE_MOD_PATTERNS.some(wp => wp.test(entryName));
      if (!isLegit) {
        results.detections.push({
          type: 'class-pattern',
          description: pattern.description,
          severity: pattern.severity,
          match: entryName
        });
      }
    }
  }

  // Check if it's modifying a vanilla class (mixin injection)
  for (const vanillaClass of VANILLA_CLASSES) {
    for (const str of classInfo.strings) {
      if (str.includes(vanillaClass)) {
        // Only flag if the jar itself isn't from a known legitimate mod
        const isLegit = LEGITIMATE_MOD_PATTERNS.some(wp => wp.test(entryName));
        if (!isLegit) {
          results.detections.push({
            type: 'vanilla-class-reference',
            description: `References vanilla class: ${vanillaClass}`,
            severity: 'medium',
            match: str.substring(0, 100)
          });
        }
        break;
      }
    }
  }

  // Scan string constants for cheat indicators
  const allStrings = classInfo.strings.join(' ');
  for (const pattern of BYTECODE_CHEAT_STRINGS) {
    if (pattern.pattern.test(allStrings)) {
      const match = allStrings.match(pattern.pattern);
      results.detections.push({
        type: 'bytecode-string',
        description: pattern.description,
        severity: pattern.severity,
        match: match ? match[0].substring(0, 80) : ''
      });
    }
  }

  return results;
}

/**
 * Deep scan a complete .jar file
 */
function deepScanJar(filePath) {
  const results = {
    file: path.basename(filePath),
    path: filePath,
    size: 0,
    totalEntries: 0,
    classFilesScanned: 0,
    detections: [],
    modMetadata: null,
    isFabric: false,
    isForge: false,
    isQuilt: false,
    suspiciousClassCount: 0,
    vanillaClassModifications: 0,
    status: 'clean'
  };

  try {
    const stats = fs.statSync(filePath);
    results.size = stats.size;

    if (stats.size > 500 * 1024 * 1024) {
      results.status = 'skipped';
      results.error = 'File exceeds 500MB limit';
      return results;
    }

    const zip = new AdmZip(filePath);
    const entries = zip.getEntries();
    results.totalEntries = entries.length;

    for (const entry of entries) {
      const entryName = entry.entryName;

      // Detect mod loader type
      if (entryName === 'fabric.mod.json') results.isFabric = true;
      if (entryName === 'META-INF/mods.toml') results.isForge = true;
      if (entryName === 'quilt.mod.json') results.isQuilt = true;

      // Parse mod metadata
      if (entryName === 'fabric.mod.json' || entryName === 'quilt.mod.json') {
        try {
          const content = entry.getData().toString('utf-8');
          results.modMetadata = JSON.parse(content);
        } catch (e) { /* Invalid JSON */ }
      }

      if (entryName === 'META-INF/mods.toml' || entryName === 'mcmod.info') {
        try {
          results.modMetadata = { raw: entry.getData().toString('utf-8').substring(0, 2000) };
        } catch (e) { /* Cannot read */ }
      }

      // Deep scan .class files
      if (entryName.endsWith('.class')) {
        try {
          const data = entry.getData();
          if (data && data.length < 10 * 1024 * 1024) {
            const classResult = scanClassFile(entryName, data);
            results.classFilesScanned++;

            if (classResult.detections.length > 0) {
              results.suspiciousClassCount++;
              
              for (const detection of classResult.detections) {
                if (detection.type === 'vanilla-class-reference') {
                  results.vanillaClassModifications++;
                }
                results.detections.push({
                  ...detection,
                  location: entryName
                });
              }
            }
          }
        } catch (err) {
          // Skip unreadable class files
        }
      }

      // Scan text-based files for cheat keywords
      if (entryName.endsWith('.json') || entryName.endsWith('.txt') ||
          entryName.endsWith('.cfg') || entryName.endsWith('.properties') ||
          entryName.endsWith('.toml') || entryName.endsWith('.yml') ||
          entryName.endsWith('.yaml') || entryName.endsWith('.xml') ||
          entryName.endsWith('.mcmeta')) {
        try {
          const content = entry.getData().toString('utf-8');
          const textDetections = scanTextContent(entryName, content);
          results.detections.push(...textDetections);
        } catch (err) {
          // Skip
        }
      }

      // Check entry names for suspicious patterns
      const nameDetections = scanEntryName(entryName);
      results.detections.push(...nameDetections);
    }

    // Deduplicate detections
    results.detections = deduplicateDetections(results.detections);

    if (results.detections.length > 0) {
      // Filter out low-confidence detections to reduce false positives
      const highConfidence = results.detections.filter(d => 
        d.severity === 'critical' || 
        (d.severity === 'high' && d.type !== 'vanilla-class-reference')
      );

      if (highConfidence.length > 0) {
        results.status = 'detected';
      } else if (results.detections.length >= 3) {
        // Multiple medium-severity detections together raise confidence
        results.status = 'detected';
      } else {
        results.status = 'suspicious';
      }
    }
  } catch (err) {
    results.status = 'error';
    results.error = err.message;
  }

  return results;
}

/**
 * Scan text content for cheat-related keywords
 */
function scanTextContent(entryName, content) {
  const detections = [];
  const contentLower = content.toLowerCase();

  const allKeywords = getAllKeywords();
  for (const entry of allKeywords) {
    const keywordLower = entry.keyword.toLowerCase();
    if (contentLower.includes(keywordLower)) {
      if (entry.keyword.length <= 4 && !content.includes(entry.keyword)) continue;
      if (isFalsePositive(entry.keyword, content)) continue;

      detections.push({
        type: 'text-keyword',
        description: `Cheat keyword "${entry.keyword}" (${entry.categoryName})`,
        severity: entry.severity,
        location: entryName,
        match: entry.keyword
      });
    }
  }

  return detections;
}

/**
 * Scan entry name for suspicious patterns
 */
function scanEntryName(entryName) {
  const detections = [];

  for (const pattern of CHEAT_CLASS_PATTERNS) {
    if (pattern.pattern.test(entryName)) {
      const isLegit = LEGITIMATE_MOD_PATTERNS.some(wp => wp.test(entryName));
      if (!isLegit) {
        detections.push({
          type: 'entry-name',
          description: pattern.description,
          severity: pattern.severity,
          location: entryName,
          match: entryName
        });
      }
    }
  }

  return detections;
}

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
 * False positive check (reuse logic from mod-scanner)
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
      return l.includes('countdown') || l.includes('scheduler') || l.includes('timeout');
    },
    'ESP': (ctx) => {
      const l = ctx.toLowerCase();
      return l.includes('espresso') || l.includes('especially');
    },
    'Search': () => true,
    'Step': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('stephack') && !l.includes('step hack') && !l.includes('module') && !l.includes('cheat');
    },
    'Tower': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('scaffold') && !l.includes('module') && !l.includes('cheat');
    },
    'Reach': (ctx) => {
      const l = ctx.toLowerCase();
      return !l.includes('module') && !l.includes('cheat') && !l.includes('hack') && !l.includes('combat');
    }
  };

  return fpRules[keyword] ? fpRules[keyword](context) : false;
}

/**
 * Deduplicate detections
 */
function deduplicateDetections(detections) {
  const seen = new Set();
  return detections.filter(d => {
    const key = `${d.type}:${d.description}:${d.location || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Recursively scan the entire .minecraft directory for all .jar files
 */
function deepScanMinecraftDirectory(mcDir) {
  const results = {
    directory: mcDir,
    totalJars: 0,
    scannedJars: 0,
    detectedJars: 0,
    suspiciousJars: 0,
    jars: [],
    scannedAt: new Date().toISOString()
  };

  const scanDirs = ['mods', 'versions', 'libraries', 'shaderpacks', 'resourcepacks', 'coremods'];

  for (const subDir of scanDirs) {
    const fullDir = path.join(mcDir, subDir);
    if (!fs.existsSync(fullDir)) continue;

    const jars = findJarFiles(fullDir);
    for (const jarPath of jars) {
      results.totalJars++;

      try {
        const scanResult = deepScanJar(jarPath);
        results.scannedJars++;
        results.jars.push(scanResult);

        if (scanResult.status === 'detected') {
          results.detectedJars++;
        } else if (scanResult.status === 'suspicious') {
          results.suspiciousJars++;
        }
      } catch (err) {
        results.jars.push({
          file: path.basename(jarPath),
          path: jarPath,
          status: 'error',
          error: err.message
        });
      }
    }
  }

  return results;
}

/**
 * Find all .jar files recursively in a directory
 */
function findJarFiles(dir, maxDepth = 5, currentDepth = 0) {
  const jars = [];

  if (currentDepth > maxDepth) return jars;

  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      try {
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory()) {
          jars.push(...findJarFiles(fullPath, maxDepth, currentDepth + 1));
        } else if (stats.isFile() && item.toLowerCase().endsWith('.jar')) {
          jars.push(fullPath);
        }
      } catch (err) {
        // Skip inaccessible
      }
    }
  } catch (err) {
    // Skip inaccessible
  }

  return jars;
}

module.exports = {
  deepScanJar,
  deepScanMinecraftDirectory,
  scanClassFile,
  parseClassFile,
  findJarFiles,
  CHEAT_CLASS_PATTERNS,
  BYTECODE_CHEAT_STRINGS,
  VANILLA_CLASSES
};
