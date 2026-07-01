Plugin Phantom
[ Nessus-style logic without the scanner ]
---
```texts
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║          ██████   ██       ██   ██   █████   ███████  ██   ██        ║
║          ██   ██  ██       ██   ██  ██          ██    ███  ██        ║
║          ██████   ██       ██   ██  ██  ███     ██    ██ █ ██        ║
║          ██       ██       ██   ██  ██   ██     ██    ██  ███        ║
║          ██       ███████   █████    █████   ███████  ██   ██        ║
║                                                                      ║
║     ██████   ██   ██    ███    ██   ██  ███████   █████   ██   ██    ║
║     ██   ██  ██   ██   ██ ██   ███  ██     ██    ██   ██  ███ ███    ║
║     ██████   ███████  ██   ██  ██ █ ██     ██    ██   ██  ██ █ ██    ║
║     ██       ██   ██  ███████  ██  ███     ██    ██   ██  ██   ██    ║
║     ██       ██   ██  ██   ██  ██   ██     ██     █████   ██   ██    ║
║                                                                      ║
║           · the plugin's logic, with no scanner attached ·           ║
║                                                                      ║
╟──────────────────────────────────────────────────────────────────────╢
║          [ fetch ] -> [ parse ] -> [ compare ] -> [ haunt ]          ║
╚══════════════════════════════════════════════════════════════════════╝
```
This script reconstructs the core version-based detection logic commonly used in Nessus plugins: request an endpoint, parse a version string, compare it to a known fixed version, and report if it’s vulnerable. Nessus plugins typically add additional fingerprinting and edge-case handling.

Four moves, no feed:

- Query a target endpoint (`/Version`)
- Extract an installed build version
- Compare it to a **Stable baseline** (NASL: embedded baseline like a real plugin feed)
- In PowerShell, optionally scrape the vendor page to discover the current **Stable** version dynamically
- Report if the installed build is older than Stable
