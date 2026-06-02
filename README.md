# Windows Persistence Audit Tool

A read-only PowerShell tool for auditing Windows persistence locations.

It is based on the excellent [`persistence-info`](https://persistence-info.github.io/) project and is meant to help with defensive checks, incident response, hardening reviews, and baseline monitoring.

The tool does not create, change, remove, disable, or remediate anything. It only collects evidence, enriches it, scores it, and writes reports.

---

## What this tool does

Windows has many legitimate places where software can register itself to start automatically, load a DLL, hook into a subsystem, or extend system behavior. Attackers can abuse the same places for persistence.

This script walks through those locations and produces a practical audit report.

It collects:

- registry-based persistence entries;
- scheduled tasks;
- Windows services;
- logon/startup locations;
- LSA, Winlogon, Print Monitor, Netsh, AMSI and other extension points;
- COM and shell extension related entries;
- PowerShell profiles;
- Windows Terminal profiles;
- RDP-related startup settings;
- DSC configuration state;
- other persistence locations listed by `persistence-info`.

For file-backed entries, it also tries to enrich the result with:

- SHA256;
- Authenticode signature status;
- signer;
- file owner;
- timestamps;
- company/product metadata;
- original filename;
- file description;
- ZoneId;
- writable-by-non-admin indicator.

---

## Quick start

Run from an elevated PowerShell session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\persistence_audit_tool.ps1 -OutputDirectory C:\Temp\pi-audit
```

The output directory will contain raw results and a triage report.

---

## Output structure

Example output:

```text
C:\Temp\pi-audit\
  persistence-info-audit-<timestamp>.json
  persistence-info-audit-<timestamp>.csv
  persistence-info-audit-errors-<timestamp>.json

  triage-<timestamp>\
    persistence-info-triage-all.csv
    persistence-info-triage-reviewqueue.csv
    persistence-info-triage-dangerous.csv
    persistence-info-triage-summary.csv
    persistence-info-coverage.csv
    persistence-info-triage-highlighted.html

    categories\
      01_AMSI_Providers.csv
      02_Authentication_Packages.csv
      ...
      20_Windows_Services.csv
      21_Windows_Terminal_Profile.csv
```

The most useful file to open first is:

```text
persistence-info-triage-highlighted.html
```

It gives a grouped, collapsible view of the findings.

---

## Reports

### HTML report

The HTML report is built for manual triage.

It includes:

- a summary by mechanism and verdict;
- coverage for all supported persistence mechanisms;
- one collapsible section per persistence mechanism;
- nested risk sections inside each mechanism:
  - Critical
  - High
  - Medium
  - Low

### CSV reports

| File | Purpose |
|---|---|
| `persistence-info-audit-*.csv` | Raw inventory. Useful for archival and diffing. |
| `persistence-info-audit-*.json` | JSON version of the raw inventory. |
| `persistence-info-triage-all.csv` | All findings with scoring, enrichment, and explanations. |
| `persistence-info-triage-reviewqueue.csv` | Findings that should be reviewed first: Medium, High, Critical. |
| `persistence-info-triage-dangerous.csv` | Compatibility alias for the review queue. |
| `persistence-info-triage-summary.csv` | Count by mechanism and verdict. |
| `persistence-info-coverage.csv` | Shows which persistence-info mechanisms are implemented and observed. |
| `categories\*.csv` | One CSV per persistence mechanism. |

---

## Risk scoring

The scoring is rule-based and intentionally explainable.

Each finding gets:

- `Score`
- `Verdict`
- `Reasons`
- `RecommendedAction`

Verdicts:

| Verdict | Meaning |
|---|---|
| `Critical` | Review immediately. Usually multiple strong suspicious signals. |
| `High` | Prioritize. Often a suspicious path, signer, script host, or sensitive mechanism. |
| `Medium` | Worth checking, but not necessarily malicious. |
| `Low` | Usually baseline/inventory unless it changes later. |

The script also tries to reduce noise from expected Microsoft components. Signed Microsoft files in expected system locations are usually downgraded unless other suspicious indicators are present.

Expected system locations include:

```text
C:\Windows\System32
C:\Windows\SysWOW64
C:\Windows\WinSxS
C:\ProgramData\Microsoft\Windows Defender
```

---

## Supported persistence mechanisms

The script implements read-only checks for the Windows persistence mechanisms listed by `persistence-info`, including:

- `.chm helper DLL`
- `.NET Startup Hooks`
- `AeDebug`
- `AMSI Providers`
- `Authentication Packages`
- `Autodial DLL`
- `Boot Verification Program`
- `Code Signing DLL`
- `Credential Manager DLL`
- `Desired State Configuration`
- `Disk Cleanup Handler`
- `Explorer tools`
- `File Extension Hijacking`
- `Filter Handlers for Windows Search`
- `GPO Client-side Extension`
- `hhctrl.ocx`
- `HKCU cmd.exe AutoRun`
- `HKCU Load`
- `HKCU Run and RunOnce registry keys`
- `IFilter`
- `Image File Execution Options key`
- `Keyboard Shortcut`
- `LSA Extension`
- `Monitoring Silent Process Exit`
- `MPNotify`
- `Natural Language Development Platform 6 DLLs`
- `Netsh extension DLL`
- `Password Filter`
- `PowerShell Profiles`
- `Print Monitor`
- `RDP WDS Startup Programs`
- `Recycle Bin COM Extension Handler`
- `Screen Saver`
- `ServerLevelPluginDll`
- `Startup Folder`
- `Task Scheduler`
- `TelemetryController`
- `TS Initial Program`
- `User Init Mpr Logon Script`
- `WER Debugger`
- `Windows Platform Binary Table`
- `Windows Services`
- `Windows Terminal Profile`
- `Winlogon Notification Package`

---



## Limitations

This tool is a local, read-only persistence audit helper. It is useful for inventory, triage, and baseline comparison, but it is not a full compromise assessment.

Known limitations:

- It checks only the local Windows host.
- Offline user hives are not mounted automatically, so persistence in unloaded `NTUSER.DAT` files may be missed.
- Firmware, UEFI/WPBT, bootkits, and pre-boot persistence are only checked best-effort or not fully visible from Windows userland.
- Kernel-mode rootkits or API hooking can hide registry keys, files, services, tasks, or other artifacts from normal Windows APIs.
- WMI permanent event subscriptions are not comprehensively covered unless implemented as a separate check.
- Application-specific persistence is not fully covered: browser extensions, Office add-ins/macros, Outlook rules, IDE plugins, package manager hooks, etc.
- Deleted or historical artifacts are not recovered. The script does not parse USN Journal, Amcache, ShimCache, Prefetch, SRUM, or registry transaction logs.
- Scoring is heuristic. `Medium`, `High`, or `Critical` means “review first,” not “confirmed malicious.”
- `Low` means lower priority, not guaranteed safe.
- The script does not remediate anything. It does not delete, disable, quarantine, or modify persistence entries.

---

## Safety

The script only performs read-only actions:

- reads registry keys and values;
- reads scheduled task definitions;
- reads service configuration;
- reads profile/config files;
- checks file metadata;
- checks signatures;
- calculates SHA256;
- writes reports.

It does not modify the system.

---

## Disclaimer

This project is intended for defensive security work and Windows configuration auditing.

Use the results as investigation input, not as a final verdict. Always validate findings against your environment, installed software, baseline, and telemetry.
