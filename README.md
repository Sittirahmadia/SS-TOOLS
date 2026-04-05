# SS-TOOLS

Minecraft Cheat Detection Scanner for PC — an Electron desktop application + web version.

SS-TOOLS scans Minecraft launcher data, mods, logs, running processes, and deleted files to detect cheats, macro tools, and injectors.

## Features

- **Mod Scanner**: Scans .jar/.zip mod files for cheat keywords in class files, configs, and metadata
- **Log Scanner**: Detects cheat client signatures and module toggle patterns in Minecraft logs
- **Process Scanner**: Scans running processes and task manager for hidden cheat tools (198macro, zenithmacro, injectors, AutoHotkey)
- **Deleted File Scanner**: Finds previously deleted cheat files via Recycle Bin, NTFS journal, Prefetch, Recent Files, and command history
- **String/Binary Scanner**: Deep scans .exe, .dll, .ahk files for injection patterns and cheat strings
- **Launcher Detection**: Auto-detects installed launchers (Zalith, Mojo, Modrinth, Vanilla, CurseForge, Prism, MultiMC, Lunar, Badlion, Feather)
- **Full Auto Scan**: One-click scan of all detected launchers
- **Web Version**: Upload-based scanning with drag & drop (no install needed)
- **Export Reports**: Save scan results as JSON or text

## Supported Launchers

| Launcher | Version Isolation | Status |
|----------|------------------|--------|
| Zalith Launcher | Yes (must enable) | Supported |
| Mojo Launcher | Yes (always on, called "instance") | Supported |
| Modrinth Launcher | Yes (profiles) | Supported |
| Minecraft (Vanilla) | No | Supported |
| CurseForge | Yes (instances) | Supported |
| Prism Launcher | Yes (instances) | Supported |
| MultiMC | Yes (instances) | Supported |
| Lunar Client | Yes (per-version) | Supported |
| Badlion Client | No | Supported |
| Feather Client | No | Supported |

## Cheat Detection

Detects cheats for Minecraft **1.21 — 1.21.11**, including:

- **Crystal PvP**: AutoCrystal, CrystalAura, AnchorMacro, BedAura, CevBreak, AutoCity, HoleFill, PistonCrystal
- **Sword PvP**: KillAura, AimAssist, Triggerbot, AutoClicker, Reach, Velocity, AntiKB, Criticals, BackTrack
- **Movement**: SpeedHack, FlyHack, NoFall, NoSlow, Phase, NoClip, PacketFly, Scaffold
- **Visual**: ESP, Tracers, Xray, FreeCam, Chams, Fullbright
- **Utility**: AutoTotem, FastBreak, Nuker, Baritone, ChestStealer, Timer
- **Known Clients**: Wurst, Impact, Meteor, Aristois, RusherHack, Lambda, Future, ThunderHack, BleachHack, GameSense, Konas, and more
- **Macro Tools**: 198macro, ZenithMacro, CrystalSpKMacro, injectors, DLL injection
- **Anti-Detection**: Anti-screenshare bypass tools

Max folder upload: **500MB**

## Building

### Prerequisites

- [Node.js](https://nodejs.org/) v20+
- Windows OS (for full scanning features)

### Install & Run (Development)

```bash
npm install
npm start
```

### Build .exe

```bash
# Build both installer and portable
npm run build

# Build portable only
npm run build:portable

# Build installer only
npm run build:installer
```

Built files will be in the `dist/` folder.

### Automated Builds

This repo includes a GitHub Actions workflow that automatically builds `.exe` files on every push and on releases. Download built artifacts from the **Actions** tab.

## Web Version

Open `renderer/web.html` in a browser for the web-based scanner. The web version supports:

- Mod file upload scanning (.jar, .zip, .litemod)
- Binary/string scanning (.exe, .dll, .ahk)
- Log file scanning (.log, .txt)

Note: Process scanning and deleted file scanning require the desktop app.

## Project Structure

```
SS-TOOLS/
├── electron/              # Electron main process
│   ├── main.js            # App entry point
│   └── preload.js         # Preload script (IPC bridge)
├── scanners/              # Scanner modules
│   ├── mod-scanner.js     # Mod file scanner
│   ├── log-scanner.js     # Log file scanner
│   ├── process-scanner.js # Process/task manager scanner
│   ├── deleted-file-scanner.js  # Deleted file scanner
│   ├── launcher-detector.js     # Launcher detection
│   ├── string-scanner.js  # Binary string scanner
│   └── index.js           # Module exports
├── renderer/              # Frontend UI
│   ├── index.html         # Desktop app UI
│   ├── web.html           # Web version UI
│   ├── styles.css         # Shared styles
│   ├── app.js             # Desktop app logic
│   └── web-scanner.js     # Web scanner logic
├── cheat-signatures/      # Detection databases
│   ├── keywords.json      # Cheat keyword database
│   └── file-patterns.json # File patterns & launcher paths
├── assets/                # Icons and images
└── package.json
```

## Credits

Built by **Sittirahmadia**
