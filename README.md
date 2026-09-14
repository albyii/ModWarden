# 🛡️ ModWarden

[![ModWarden](https://img.shields.io/badge/ModWarden-PowerShell-blue)](https://github.com/albyii/ModWarden)

**Professional Minecraft mod forensic analyzer — built entirely in PowerShell.**

ModWarden analyzes Minecraft mod `.jar` files for known cheat/client identifiers, combat and movement modules, automation, suspicious code and packaging, obfuscation, download provenance, injection indicators, and other evidence that may help identify unauthorized modifications.

> **A signature match is evidence for review, not mathematical proof of cheating.** ModWarden uses multiple indicators to produce a moderation assumption while keeping the public result simple.

## ⚡ Quick Start

[![Quick Start](https://img.shields.io/badge/Quick%20Start-Run%20ModWarden-success)](https://github.com/albyii/ModWarden#-quick-start)

Run ModWarden with a single command:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/albyii/ModWarden/main/ModWarden.ps1')"
```

Or download/clone the repository and run:

```powershell
.\ModWarden.ps1
```

ModWarden can automatically discover common Minecraft and launcher mod locations.

You can also choose a custom path from the interactive CMD interface.

## 🔎 What ModWarden Checks

[![Analysis](https://img.shields.io/badge/Analysis-Minecraft%20Mods-informational)](https://github.com/albyii/ModWarden#-what-modwarden-checks)

ModWarden contains a large signature database covering:

- **Known cheat/client identifiers** — known Minecraft cheat and client names, identifiers, namespaces and components.
- **Combat modules** — AutoCrystal, KillAura, AimAssist, Aimbot, TriggerBot, Reach, Hitbox, Velocity, Criticals, AutoTotem, AutoArmor, AutoWeapon, AutoPotion, BedAura, AnchorAura, MaceSwap and more.
- **Movement modules** — Speed, Fly, NoFall, Jesus, Step, LongJump, HighJump, Spider, Glide, Phase, NoClip, Blink, Timer, NoSlow, InventoryMove, AirJump, BunnyHop and more.
- **World & render modules** — XRay, ESP, Tracers, BlockESP, CaveESP, Freecam, FullBright, StorageESP, EntityRadar and related tools.
- **Automation** — AutoClicker, AutoEat, FastEat, AutoFish, ChestStealer, InventoryStealer, AutoMine, AutoRegear, AutoCraft, AutoSmelt, AutoTool, AutoRespawn, AutoXP, FastPlace, Scaffold, AutoBridge and more.
- **Component signatures** — suspicious classes, packages, methods and strings associated with cheat functionality.
- **Obfuscation indicators** — known obfuscators, protectors, unusual Unicode and suspicious packaging.
- **Security indicators** — `Runtime.exec`, `ProcessBuilder`, remote downloads, HTTP POST behavior, loaders and potentially malicious functionality.
- **Archive structure** — nested JARs, suspicious files and unusual mod packaging.
- **Download provenance** — source metadata such as Modrinth, CurseForge, GitHub, Discord, MediaFire, Mega and Google Drive indicators.
- **Modrinth verification** — JAR hashes can be checked against Modrinth version-file information when applicable.
- **JVM injection indicators** — running Java processes are checked for indicators such as `-javaagent`, `-agentpath` and JDWP.

ModWarden combines these indicators to distinguish stronger evidence from weaker or more ambiguous findings.

## 📋 Scan Menu

[![CMD](https://img.shields.io/badge/Interface-CMD%20Only-111827)](https://github.com/albyii/ModWarden)

ModWarden uses a normal interactive CMD/PowerShell menu — no custom GUI required.

```text
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  [1]  MINECRAFT SCAN                                                     │
  │  [2]  FULL PC SCAN                                                       │
  │  [3]  CUSTOM PATH                                                        │
  │  [4]  EXIT                                                               │
  └──────────────────────────────────────────────────────────────────────────┘
```

### Scan Modes

- **MINECRAFT SCAN** — checks detected Minecraft and launcher mod locations.
- **FULL PC SCAN** — searches relevant Minecraft/launcher locations across the PC.
- **CUSTOM PATH** — scans a folder or path selected by the user.
- **EXIT** — closes ModWarden.

## 🧾 Example

[![Example](https://img.shields.io/badge/Example-Results-blueviolet)](https://github.com/albyii/ModWarden#-example)

A clean result can look like:

```text
============================================================
  MODWARDEN
============================================================

  SCAN COMPLETE
  ----------------------------------------------------------

  CHEATING: NO

  DETECTED CHEATS
  ----------------------------------------------------------
  None

  SCAN MODE       MINECRAFT SCAN
  JAR FILES       14
  SCAN TIME       2.41s
```

A detection result can look like:

```text
============================================================
  MODWARDEN
============================================================

  SCAN COMPLETE
  ----------------------------------------------------------

  CHEATING: YES

  DETECTED CHEATS
  ----------------------------------------------------------

  [01] AutoAnchor
  [02] AutoCrystal
  [03] Mace Swap
  [04] Silent Aim
  [05] TriggerBot

  SCAN MODE       MINECRAFT SCAN
  JAR FILES       18
  SCAN TIME       3.17s
```

Each detected cheat is shown **once**, even if multiple files or signatures point to the same cheat.

The public report intentionally does **not** display a numeric risk score.

## 📁 Project Structure

[![Project](https://img.shields.io/badge/Project-Single%20File-orange)](https://github.com/albyii/ModWarden#-project-structure)

```text
ModWarden/
├── ModWarden.ps1
├── README.md
└── .gitignore
```

The signature database is currently contained within `ModWarden.ps1` so the project can be distributed as a simple one-file forensic tool.

## 🧠 Signature Database

[![Signatures](https://img.shields.io/badge/Database-Signatures-purple)](https://github.com/albyii/ModWarden#-signature-database)

ModWarden uses structured signatures covering:

- Known clients
- Cheat/module identifiers
- Component and package signatures
- Class and string indicators
- Obfuscators
- Suspicious code behavior
- Archive/package indicators
- Download/source provenance
- JVM injection indicators

The scanner combines multiple findings rather than relying on one generic string.

Internal scoring is used by the detection logic to distinguish stronger evidence from weaker findings. This score is **not displayed in the final moderation report**.

## 🔐 Safety

[![Safety](https://img.shields.io/badge/Safety-Defensive%20Forensics-success)](https://github.com/albyii/ModWarden#-safety)

ModWarden is a **defensive forensic analysis tool**.

It:

- does not execute Minecraft mods or JAR files;
- does not load or run code from scanned JARs;
- does not modify scanned JAR files;
- analyzes archive contents and metadata statically;
- does not attempt to bypass anti-cheat systems;
- does not modify the player's Minecraft installation;
- reports suspicious indicators for manual investigation.

> ModWarden analyzes static evidence. It does not prove what a player did in-game.

## ⚠️ Important

[![Important](https://img.shields.io/badge/Important-Review%20Before%20Moderation-yellow)](https://github.com/albyii/ModWarden#%EF%B8%8F-important)

No static JAR scanner can guarantee perfect detection or zero false positives.

Minecraft mods can be:

- obfuscated;
- renamed;
- repackaged;
- modified;
- custom-built;
- intentionally designed to hide their identifiers.

A ModWarden result should therefore be combined with available server logs, staff observations, replay evidence, anti-cheat evidence and other relevant information before taking moderation action.

**Do not automatically punish a player solely because of a single signature match.**

## 🚀 One-Command Launch

[![Launch](https://img.shields.io/badge/Launch-One%20Command-brightgreen)](https://github.com/albyii/ModWarden#-one-command-launch)

For staff or moderators who simply want to run the scanner:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/albyii/ModWarden/main/ModWarden.ps1' | iex"
```

> This downloads and executes the current `main` version. For maximum security, inspect or clone the repository instead of blindly executing remote code.

## 👤 Contact

[![Contact](https://img.shields.io/badge/Contact-albyii-blue)](https://github.com/albyii)

**MODWARDEN — by albyi_**

**Contributor — WindowsFolder**

**Discord:** `albyi_i`

**GitHub:** `albyii`

Found a questionable detection or false positive?

Open an issue on the GitHub repository with the relevant evidence so the signature can be reviewed.

## 📄 License

[![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/albyii/ModWarden)

MIT
