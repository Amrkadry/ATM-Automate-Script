# Amr's ATM Automate Script

**Author:** Amr Kadry  
**Target:** NCR Personas ATMs (Windows Embedded / IoT)

## Overview

PowerShell-based ATM penetration testing automation script for authorized security assessments of NCR Personas ATMs. Runs 10 phases of enumeration and testing, outputs all findings to a timestamped text log and exports Radmin registry hashes to a `.reg` file.

## Requirements

- Local Administrator access on the ATM
- PowerShell 5.1+ (pre-installed on Windows Embedded)
- Run from the ATM itself (not remote)

## Usage

```powershell
.\Amrs-ATM-Automate-Script.ps1
```

Output is written to `Amrs Output\` in the same directory as the script.

## Phases

| # | Phase | What It Does |
|---|-------|-------------|
| 1 | System Information | OS version, NCR software detection, installed packages |
| 2 | User Enumeration | Local users, Administrators group, service accounts |
| 3 | sstauto Assessment | sstauto existence, group membership, auto-logon config |
| 4 | UAC Misconfiguration | UAC registry values, AlwaysInstallElevated, bypass binaries |
| 5 | Credential Hunting | Auto-logon passwords, stored creds, config file secrets |
| 6 | eJournal & Camera | Journal/surveillance file permissions, unmasked card data |
| 7 | Radmin Hashes | Registry extraction, TLV parsing, .reg export |
| 8 | XFS Registry | Service providers, logical services, configuration |
| 9 | XFS API (P/Invoke) | Direct msxfs.dll calls — CDM status, caps, cash units |
| 10 | Security Posture | Solidcore, PS language mode, RDP, firewall, open ports |

## Output

```
Amrs Output/
├── ATM-Pentest-Results_2026-09-06_14-30-00.txt   # Full verbose log
└── Radmin-Hashes_2026-09-06_14-30-00.reg          # Radmin registry export
```

Findings are tagged by severity: `[CRITICAL]`, `[WARNING]`, `[SUCCESS]`, `[INFO]`, `[VERBOSE]`.

## Disclaimer

For authorized penetration testing only. Unauthorized use against ATMs is a criminal offense. Always operate under a signed scope-of-work with explicit permission from the ATM owner.
