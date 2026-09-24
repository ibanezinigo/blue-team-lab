# Unit42 — SOC / DFIR Investigation

## Overview

This investigation analyzes a Sysmon event log from a Windows endpoint and reconstructs the execution of a suspicious installer named:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

The investigation identified:

- delivery through Dropbox using Firefox;
- interactive user execution from `explorer.exe`;
- MSI-based installation through `msiexec.exe`;
- privileged Windows Installer activity running as `NT AUTHORITY\SYSTEM`;
- deployment of several files into `C:\Games`;
- staging of multiple UltraVNC-related components;
- widespread creation-time manipulation consistent with timestomping;
- outbound DNS and TCP activity;
- cleanup of staging artifacts after installation.

The available telemetry supports the presence of remote-access functionality, but it does **not** prove that a remote-access session occurred or that a persistence mechanism was successfully created.

---

## Evidence

Primary evidence:

```text
Microsoft-Windows-Sysmon-Operational.evtx
```

Tools used:

```text
EvtxECmd
Timeline Explorer
PowerShell / Get-WinEvent
```

---

## Investigation Structure

- [01 — Initial Analysis](01-initial-analysis.md)
- [02 — Process and Installation Analysis](02-process-and-installation.md)
- [03 — Network and Persistence Assessment](03-network-and-persistence.md)
- [04 — File Activity and Timestomping](04-file-activity-and-timestomping.md)
- [05 — Timeline and Indicators](05-timeline-and-iocs.md)
- [06 — Detection and Response](06-detection-and-response.md)
- [07 — Lessons Learned](07-lessons-learned.md)

---

## High-Level Attack Chain

```text
Firefox
  |
  |  downloads executable from Dropbox
  v
Preventivo24.02.14.exe.exe
  ^
  |
explorer.exe
  |
  +--> Preventivo24.02.14.exe.exe
          |
          +--> stages MSI and additional artifacts
          |
          +--> msiexec.exe /i main1.msi
                  |
                  +--> Windows Installer
                          |
                          +--> msiexec.exe [SYSTEM]
                                  |
                                  +--> C:\Games\
                                      ├── on.cmd
                                      ├── c.cmd
                                      ├── cmmc.cmd
                                      ├── once.cmd
                                      ├── viewer.exe
                                      └── taskhost.exe
```

---

## Key Conclusion

The evidence supports the following sequence:

```text
Dropbox delivery
→ user execution
→ MSI installation
→ SYSTEM-level deployment
→ timestomping
→ remote-access-related components
→ staging cleanup
```

The following were **not confirmed** in the supplied Sysmon telemetry:

```text
persistent VNC service
scheduled-task persistence
actual VNC session
remote operator activity
credential dumping
process injection
malicious root certificate installation
confirmed C2
```

The investigation therefore remains evidence-driven and avoids treating Sysmon `RuleName` ATT&CK labels as proof of attacker behavior.
