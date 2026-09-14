# 🛡️ ModWarden

**Professional Minecraft mod & client forensic analyzer — built entirely in PowerShell.**

ModWarden statically inspects Minecraft `.jar` files for known client identifiers, cheat modules/features, suspicious namespaces, obfuscation indicators, archive artifacts and security-related indicators.

> **CHEATING: YES / NO** is ModWarden's final moderation assumption. A static signature result is evidence for review, not mathematical proof of a player's behavior.

## ⚡ Quick Start

Run ModWarden directly from GitHub:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/albyii/ModWarden/main/ModWarden.ps1')"
```

Or download/clone the repository and run:

```powershell
.\ModWarden.ps1
```

### Scan Modes

From the normal CMD menu you can choose:

```text
[1] MINECRAFT SCAN
[2] FULL PC SCAN
[3] CUSTOM PATH
[4] EXIT
```

**Minecraft Scan** can locate common `.minecraft`, CurseForge, Modrinth and PrismLauncher mod directories.

**Full PC Scan** searches known Minecraft/launcher locations and relevant folders on other drives.

**Custom Path** lets you enter any directory containing Minecraft `.jar` files.

## 🔎 What ModWarden Checks

* **Client signatures** — known Minecraft clients and utility clients.
* **Component signatures** — AutoCrystal, AutoAnchor, AutoTotem, Silent Aim, TriggerBot, FakeLag, Mace Swap and many others.
* **Package / namespace evidence** — suspicious or known client namespaces.
* **Archive structure** — JAR entry names, nested JARs and metadata.
* **Class strings** — printable strings embedded in `.class` and relevant metadata files.
* **Obfuscation indicators** — suspicious class naming and known obfuscators.
* **Security indicators** — runtime execution, HTTP activity, possible POST/exfiltration indicators and other artifacts are surfaced for investigation.
* **Download source** — Windows Zone.Identifier metadata can classify sources such as Modrinth, CurseForge, GitHub, Discord, MediaFire, Mega and Google Drive.
* **Modrinth verification** — JAR hashes can be checked against Modrinth's version-file API.
* **JVM injection indicators** — running Java processes are checked for flags such as `-javaagent`, `-agentpath` and JDWP.
* **Robust scanning** — unreadable or corrupt JARs are reported instead of terminating the complete scan.

## 🧾 Example

A completed scan is intentionally kept simple:

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                              SCAN COMPLETE                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

  CHEATING: YES

  DETECTED CHEATS

  [01] AutoAnchor
  [02] AutoCrystal
  [03] Mace Swap
  [04] Silent Aim
  [05] TriggerBot

  ──────────────────────────────────────────────────────────────────────────────

  SCAN
  ├─ MODE            MINECRAFT
  ├─ TARGET          C:\Users\User\AppData\Roaming\.minecraft\mods
  ├─ FILES ANALYZED  12
  ├─ JAR FILES       12
  └─ SCAN TIME       1.84s
```

If no cheat signatures are identified:

```text
  CHEATING: NO

  DETECTED CHEATS

  None
```

Detected cheat names are deduplicated so the same detection is not printed repeatedly.

## 📁 Project Structure

```text
ModWarden/
├── ModWarden.ps1
├── README.md
└── .gitignore
```

ModWarden currently keeps its signature database directly inside `ModWarden.ps1`, so there is no required external `data/signatures.json` file.

## 🧠 Signature Database

The scanner uses built-in signature collections for:

* cheat/client names;
* module and feature identifiers;
* suspicious package paths;
* class strings;
* obfuscators;
* security-related indicators.

Signatures are combined and deduplicated before scanning. Specific identifiers are preferred over broad everyday words to help reduce unnecessary false positives.

## 🔐 Safety

ModWarden is a **defensive forensic scanner**.

It:

* does not modify scanned JARs;
* does not execute code from scanned JARs;
* does not collect credentials or tokens;
* does not attempt to bypass anti-cheat systems;
* reports suspicious security indicators for manual investigation.

## ⚠️ Important

No static signature scanner can guarantee perfect detection or zero false positives.

A `CHEATING: YES` result means ModWarden found enough configured evidence to make that moderation assumption. It should still be combined with available server/staff evidence and reviewed before a final moderation action.

Security-related detections are not automatically proof of cheating and should be investigated separately.

## 👤 Contact

**MODWARDEN - by albyi_**

Contributor - WindowsFolder

**Discord:** `albyi_i`

Unsure about a detection? **Contact me on Discord for review.**

**GitHub:** `albyii`

## 📄 License

MIT
