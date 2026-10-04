# Amr's ATM Assessment

Offline, single-file PowerShell collector for **authorised** security assessments of
Windows-based ATMs — NCR Personas / APTRA in particular, but most checks apply to any
XFS terminal (Diebold, Wincor, KAL).

You copy one `.ps1` onto the terminal, run it, and walk away with a verbose log, a
machine-readable findings file, and the evidence you need to write the report.

**Read-only by design.** The script never dispenses cash, never writes to an XFS device,
and never changes system configuration.

```powershell
.\Amrs-ATM-Assessment.ps1
```

---

## What it looks at

Fifteen phases, each isolated so one failing check cannot abort the run.

| # | Phase | Why it matters on an ATM |
|---|-------|--------------------------|
| 1 | Host context & software inventory | OS support status, patch currency, NCR/APTRA footprint, ATM application process identity, third-party remote-access agents |
| 2 | Local users & administrators | Blank-password flags, excessive local admins, built-in Administrator state |
| 3 | ATM service accounts & auto-logon | The `sstauto` family, group membership, cleartext `DefaultPassword` |
| 4 | UAC / elevation | `EnableLUA`, `AlwaysInstallElevated`, remote token filtering |
| 5 | Credential hunting | Registry, config files, Credential Manager, Wi-Fi PSKs, provisioning leftovers |
| 6 | eJournal & camera archives | Luhn-validated PAN and track-2 detection, archive ACLs, exposing SMB shares |
| 7 | Radmin hash extraction | Radmin 2.x MD5 **and** 3.x SRP verifier, hashcat-ready, full blobs preserved |
| 8 | XFS registry & SP integrity | Service-provider DLL bitness, signature and ACL; XFS tracing left enabled |
| 9 | XFS API direct interaction | `WFSOpen` from a non-ATM process, live cassette inventory, optional safe lock proof |
| 10 | Whitelisting & endpoint security | Solidcore mode and **updater list**, AppLocker enforcement, WDAC, PowerShell posture |
| 11 | **Kiosk / lockdown breakout posture** | Shell replacement, keyboard filter coverage, accessibility backdoors, safe-mode reachability, AutoPlay, browser surfaces |
| 12 | Local privilege escalation | Unquoted paths, weak service and task binary ACLs, writable PATH, WDigest, hive backups |
| 13 | Disk encryption & boot integrity | BitLocker, TPM, Secure Boot, hibernation — the offline-attack chain |
| 14 | Removable media & device control | USB storage policy, device-install restrictions, co-driver download, attached HID inventory |
| 15 | Network exposure | Listening services, firewall, RDP/NLA, SMB signing, named pipes, egress segmentation |

### The two findings that carry an ATM report

Everything else supports these:

- **Phase 9** proves an arbitrary local process can reach the cash dispenser through the
  XFS Manager and read live cassette currency and note counts. CEN XFS performs no caller
  authentication, so this is the precondition every cash-out malware family depends on.
- **Phases 8 and 13** close the loop: a writable service-provider DLL, or an unencrypted
  disk in a top box opened with a common key, is a persistent implant in the device layer.

---

## Usage

```powershell
# Full assessment, secrets masked
.\Amrs-ATM-Assessment.ps1

# Radmin + XFS only, in 32-bit PowerShell so msxfs.dll actually loads
.\Amrs-ATM-Assessment.ps1 -Phases 7,8,9 -Relaunch32

# What a kiosk-level attacker sees, no admin needed
.\Amrs-ATM-Assessment.ps1 -AllowNonAdmin -Phases 11,12

# In-service terminal: never touch the device layer, skip the slow disk walks
.\Amrs-ATM-Assessment.ps1 -SkipXfsApi -Fast
```

### Parameters

| Parameter | Effect |
|-----------|--------|
| `-OutputDir <path>` | Results location. Defaults to `.\Amrs Output`, falling back to `%TEMP%` if that is read-only (e.g. a write-protected USB stick) |
| `-Phases 1,2,9` | Run a subset. Default is all fifteen |
| `-NoRedact` | Write PANs and secrets **unmasked**. Off by default |
| `-Fast` | Skip the deep recursive filesystem scans in phases 5 and 6 |
| `-SkipXfsApi` | Registry-only XFS assessment; no `Add-Type`, no device calls |
| `-ProveCdmLock` | Safe impact proof: `WFSLock` the dispenser, log, `WFSUnlock`. Asks for a typed confirmation unless `-Force` |
| `-Relaunch32` | Re-execute under 32-bit PowerShell for XFS compatibility |
| `-AllowNonAdmin` | Run unelevated to assess the low-privilege view |
| `-MaxScanSeconds` / `-MaxScanFiles` | Budgets for the filesystem walks (default 180s / 20000 files) |

### Requirements

- PowerShell 2.0 or later. WMI fallbacks are in place for WES7 / POSReady images where
  `Get-LocalUser`, `Get-NetTCPConnection` and friends do not exist.
- Local Administrator for full coverage. `-AllowNonAdmin` is supported and useful.
- Run **on** the terminal, not remotely.

---

## Output

```
Amrs Output/Run_2026-10-04_12-37-07/
├── ATM-Assessment.log      # full verbose log, UTF-8
├── findings.json           # structured findings for the report pipeline
├── findings.csv            # same, spreadsheet-friendly
├── Radmin-Registry.reg     # registry export
├── Radmin-hashes.txt       # hashcat-ready candidate lines
└── blobs/                  # complete binary evidence, never truncated
```

The run directory ACL is set to the current user and Administrators, with inheritance
broken, because this output can contain credential material.

Exit code reflects the worst severity found: `10` critical, `11` high, `12` medium,
`0` clean, `2` a phase errored. Useful when wrapping the script in fleet tooling.

### Redaction

Masking is **on by default**. PANs are Luhn-validated before being masked to
`123456******3456[PAN-MASKED]`; track 2 is replaced wholesale; recovered passwords are
logged as `<REDACTED len=14 sha1=…>` so the same credential can be correlated across a
fleet without the plaintext ever reaching disk.

This matters: without it the assessment output is itself cardholder data sitting on a
production terminal. Use `-NoRedact` only when you have somewhere safe to put the result.

---

## Kiosk breakout (phase 11)

An ATM is a kiosk, and the fascia is where most real engagements start. Phase 11 assesses
from inside the OS the controls an operator would be probing from the outside, so the two
halves of the test corroborate each other:

| At the fascia | What phase 11 checks |
|---|---|
| `Win+R`, `Win+E`, `Ctrl+Shift+Esc` | Keyboard Filter coverage, `DisableTaskMgr` / `NoRun` / `NoWinKeys`, whether Explorer is the shell |
| Shift ×5 sticky keys, `utilman` at the logon screen | Accessibility hotkey flags, ACLs and IFEO debugger hijacks on `sethc.exe` / `utilman.exe` / `osk.exe` |
| Two hard power cycles → safe mode | `bootstatuspolicy`, `recoveryenabled` |
| USB stick → AutoPlay or repair dialog | `NoDriveTypeAutoRun`, USBSTOR policy, device-install restrictions |
| USB keyboard or emulated mouse-as-keyboard | Device-class allowlisting, attached HID inventory |
| Plug in a consumer mouse → vendor software popup | Driver and device-metadata download policy |
| Links, print and save dialogs, developer tools | Browser and Chromium-embedded runtimes present on the image |

For the attacker-side technique catalogue — the shortcut tables, the Facedancer and
Flipper Zero recipes, URI handlers, the Android notes — use
[**ikarus23/kiosk-mode-breakout**](https://github.com/ikarus23/kiosk-mode-breakout).
This script is the defender-side mirror of that list: it tells you which of those
techniques the terminal is actually exposed to, and gives you the registry evidence to
put in the report. Run both.

ATM-specific additions worth trying at the fascia that are not OS-observable:
the operator-menu key sequence (**Enter → Clear → Cancel → 1 → 2 → 3** reaches the
operator menu on several brands; default master passwords are published in vendor
quick-reference guides), and the service keyboard in the top box.

---

## Notes on accuracy

A few things that trip people up, handled explicitly:

- **XFS is 32-bit.** A 64-bit PowerShell cannot P/Invoke a 32-bit `msxfs.dll`; it fails
  with `BadImageFormatException`. The script reads the PE machine type, tells you, and
  offers `-Relaunch32`.
- **`WFSStartUp` takes a version *range*.** Low word is the lowest acceptable version,
  high word the highest, each as `(minor << 8) | major`. An inverted range fails on a
  conforming manager.
- **The XFS registry `class` value may be a name or a number.** `"CDM"` and `3` both occur;
  assuming one silently skips every dispenser check on terminals using the other.
- **`Add-Type` invokes a compiler**, which application whitelisting usually blocks — and
  which generates an alert. Use `-SkipXfsApi` if you need to stay quiet.
- **`UF_PASSWD_NOTREQD` is not proof of a blank password.** It is reported as such and
  flagged for manual confirmation.

---

## Disclaimer

For authorised penetration testing only. Unauthorised access to an ATM is a criminal
offence in every jurisdiction that has them. Operate under a signed scope of work with
written permission from the ATM owner, and agree a maintenance window before touching
`-ProveCdmLock` on anything in service.

**Author:** Amr Kadry
