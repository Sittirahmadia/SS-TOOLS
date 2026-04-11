# SS-TOOLS v2.0 -- Minecraft SS AntiCheat Scanner

A comprehensive Windows desktop application for detecting cheats, macros, and suspicious software during Minecraft screenshare (SS) inspections.

## Features

### Core Scanners

| Scanner | Description |
|---------|-------------|
| **Mod Scanner** | Scans .jar/.zip mod files for cheat keywords in class files, configs, and metadata |
| **JAR Deep Scanner** | Bytecode-level analysis of .class files -- detects obfuscated cheats, packet manipulation, kill-aura patterns, vanilla class modifications |
| **Log Scanner** | Detects cheat client signatures, module toggles, and suspicious mod loading in Minecraft logs |
| **Process Scanner** | Enumerates running processes for known cheat tools, macro software, injectors, and debuggers |
| **DLL Scanner** | Full loaded-DLL enumeration per process with name matching, SHA-256 hashing, and binary string analysis |
| **Mouse Software Scanner** | Detects Logitech, Razer, Bloody, Redragon, Corsair, SteelSeries, Glorious, ROCCAT -- scans macro profiles for auto-click and PvP macros |
| **Browser Scanner** | Scans Chrome, Edge, Firefox, Brave download history, extensions, and bookmarks for cheat-related activity |
| **Kernel Driver Scanner** | Full kernel-mode driver scan using driverquery and fltmc -- detects Cheat Engine drivers, exploit drivers, hidden processes |
| **Deleted File Scanner** | Scans Recycle Bin, NTFS USN Journal, Windows Prefetch, Recent Files, and PowerShell history |
| **String Scanner** | Deep binary string extraction and analysis of executables and DLLs |

### Detection Techniques

- **Multi-layer detection**: keyword matching + bytecode analysis + hash verification + memory string scanning
- **Java bytecode parsing**: Reads .class constant pools to identify cheat class patterns, even when obfuscated
- **Smart whitelisting**: Legitimate gaming software (Logitech G HUB, Razer Synapse, Corsair iCUE, SteelSeries GG) is recognized -- only suspicious macro configurations are flagged
- **False positive prevention**: Context-aware keyword matching with per-keyword rules to minimize false flags
- **Vanilla class modification detection**: Identifies when mods modify core Minecraft classes (Entity, Player, World)

### GUI

- Modern dark-themed dashboard with real-time 3D Minecraft block visualization
- One-click "Full System SS Scan" button
- Real-time progress tracking with animated scan ring
- Threat severity graph (critical/high/medium/low breakdown)
- Individual scanner tabs for targeted scans
- System tray support -- minimize to tray
- HTML/JSON/TXT report export

## Requirements

- **Windows 10/11** (64-bit)
- **Administrator privileges** recommended for full scanning (kernel drivers, USN Journal, Prefetch)
- **Node.js 18+** (for development)

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm start

# Build Windows installer
npm run build:installer

# Build portable executable
npm run build:portable
```

## Project Structure

```
SS-TOOLS/
  electron/
    main.js          # Electron main process + IPC handlers
    preload.js       # Context bridge for renderer
  renderer/
    index.html       # Main UI layout
    app.js           # Application logic + scanner integrations
    styles.css       # Dark theme CSS
    three-viz.js     # 3D Minecraft block visualization engine
  scanners/
    mod-scanner.js        # Mod file keyword scanner
    jar-scanner.js        # JAR deep bytecode scanner
    log-scanner.js        # Minecraft log analyzer
    process-scanner.js    # Running process detector
    dll-scanner.js        # Loaded DLL enumerator
    mouse-scanner.js      # Gaming mouse software scanner
    browser-scanner.js    # Browser history/extension scanner
    kernel-scanner.js     # Kernel driver scanner
    deleted-file-scanner.js  # Deleted file forensics
    string-scanner.js     # Binary string analyzer
    launcher-detector.js  # Minecraft launcher detector
    report-generator.js   # HTML/TXT report generator
    index.js              # Scanner module exports
  cheat-signatures/
    keywords.json         # Cheat keyword database
    file-patterns.json    # File patterns + launcher paths
  assets/
    icon.ico              # Application icon
```

## Supported Launchers

Vanilla Minecraft, Zalith, Mojo, Modrinth, CurseForge, Prism Launcher, MultiMC, Lunar Client, Badlion Client, Feather Client

## Detected Threats

- **Cheat Clients**: Wurst, Meteor, Impact, Aristois, RusherHack, Future, ThunderHack, BleachHack, GameSense, Lambda, Inertia
- **Macro Tools**: 198Macro, ZenithMacro, CrystalSpKMacro, AutoHotkey, OP Auto Clicker, GS Auto Clicker
- **Cheat Modules**: KillAura, AimAssist, Triggerbot, AutoCrystal, Velocity/AntiKB, NoFall, Scaffold, ESP, X-Ray, Fly, Speed
- **Injection Tools**: Cheat Engine, Process Hacker, x64dbg, DLL injectors
- **Kernel Exploits**: KDMapper, Capcom.sys, mhyprot, dbk64 (Cheat Engine driver)
- **Mouse Macros**: Bloody hardware macros, rapid-click profiles, jitter-click macros, PvP combo macros

## License

MIT
