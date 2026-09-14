# 🛡️ ModWarden

**Professional Minecraft mod & client forensic analyzer — built entirely in PowerShell.**

ModWarden statically inspects Minecraft `.jar` files for known client identifiers, modules/features, suspicious namespaces, obfuscation indicators and security-related artifacts.

> **51+ / 100 = CHEATER** is ModWarden's configured verdict threshold. A static signature result is evidence for review, not a mathematical proof of a player's behavior.

## ⚡ Quick Start

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/albyii/ModWarden/main/ModWarden.ps1')"
```

Or download/clone the repository and run:

```powershell
.\ModWarden.ps1
```

Custom mods directory:

```powershell
.\ModWarden.ps1 -ModsPath "C:\path	o\.minecraft\mods"
```

Machine-readable output:

```powershell
.\ModWarden.ps1 -JsonOutput
```

## 🔎 What ModWarden Checks

- **Client signatures** — known Minecraft clients and utility clients.
- **Component signatures** — AutoCrystal, AutoAnchor, AutoTotem, SilentAim, TriggerBot, FakeLag, MaceSwap and many others.
- **Package/namespace evidence** — suspicious or known client namespaces.
- **Archive structure** — JAR entry names and metadata.
- **Class strings** — printable strings embedded in `.class` files.
- **Obfuscation indicators** — known protection/obfuscation names.
- **Security indicators** — credential/token/backdoor-related strings are surfaced as security evidence and are not automatically treated as cheat proof.
- **Robust scanning** — unreadable JARs are reported instead of terminating the complete scan.

## 📊 Risk Scoring

| Score | ModWarden result |
|---:|---|
| 0–20 | LOW |
| 21–40 | LOW RISK |
| 41–50 | SUSPICIOUS |
| **51–70** | **CHEATER** |
| 71–85 | HIGH CONFIDENCE CHEATER |
| 86–100 | VERY HIGH CONFIDENCE CHEATER |

The score is based on configured evidence weights and corroboration bonuses. Generic indicators are deliberately kept low-weight to reduce false positives.

## 🧾 Example

```text
  RISK ASSESSMENT

                         87 / 100
                 ███████████████████████████████████░░░
                   VERY HIGH CONFIDENCE

  DETECTIONS

  [01] DOOMSDAY CLIENT                    +35
       ├─ CATEGORY              CLIENTS
       ├─ MOD                   example.jar
       └─ EVIDENCE              doomsday

  [02] AUTOCRYSTAL                       +16
       ├─ CATEGORY              COMPONENTS
       ├─ MOD                   example.jar
       └─ EVIDENCE              autoCrystal

  VERDICT

                         CHEATER
             ModWarden threshold: 51+ = CHEATER.
```

## 📁 Project Structure

```text
ModWarden/
├── ModWarden.ps1
├── data/
│   └── signatures.json
├── README.md
└── .gitignore
```

## 🧠 Signature Database

`data/signatures.json` is intentionally external so signatures can be updated without rewriting the scanner.

Each entry contains a name, patterns, weight and explanation. Add new variants carefully and prefer specific identifiers over broad everyday words.

## 🔐 Safety

ModWarden is a **defensive forensic scanner**.

It:
- does not modify scanned JARs;
- does not execute code from scanned JARs;
- does not collect credentials or tokens;
- does not attempt to bypass anti-cheat systems;
- reports suspicious security indicators for manual investigation.

## ⚠️ Important

No static signature scanner can guarantee perfect detection or zero false positives. A ModWarden result should be combined with the available server/staff evidence and reviewed before a final moderation action.

## 👤 Contact

**MODWARDEN - by albyi_**

Contributor - WindowsFolder

**Discord:** `albyi_i`

Unsure about a detection? **Contact me on Discord for review.**

**GitHub:** `albyii`

## 📄 License

MIT
