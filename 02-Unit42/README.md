# Unit42 — SOC / DFIR Investigation

## Overview

This investigation analyzes a Windows Sysmon log and reconstructs the execution of:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

The investigation identified:

- delivery through Dropbox using Firefox;
- interactive execution from an `explorer.exe` context;
- MSI-based installation through `msiexec.exe`;
- privileged Windows Installer activity running as `NT AUTHORITY\SYSTEM`;
- deployment of multiple files into `C:\Games`;
- WinVNC / UltraVNC-related remote-access components;
- modification of creation timestamps across staged artifacts;
- outbound DNS and TCP activity;
- cleanup of staging artifacts after installation.

VirusTotal enrichment strongly corroborates that the initial payload is WinVNC/UltraVNC-based and that the file deployed as `C:\Games\taskhost.exe` is the same binary VirusTotal identifies as `WinVNC.exe`.

The supplied telemetry does **not** prove that the deployed VNC component executed, established persistence, or accepted a remote session.

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
VirusTotal (external enrichment)
```

---

## Investigation Structure

- [01 — Initial Analysis](01-initial-analysis.md)
- [02 — Process and Installation Analysis](02-process-and-installation.md)
- [03 — Network and Persistence Assessment](03-network-and-persistence.md)
- [04 — File Activity and Timestamp Analysis](04-file-activity-and-timestamps.md)
- [05 — Threat Intelligence Enrichment](05-threat-intelligence-enrichment.md)
- [06 — Timeline and Indicators](06-timeline-and-iocs.md)
- [07 — Detection and Response](07-detection-and-response.md)
- [08 — Lessons Learned](08-lessons-learned.md)

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
          +--> stages main1.msi and additional files
          |
          +--> msiexec.exe /i main1.msi
                  |
                  +--> Windows Installer activity
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
                                          |
                                          +--> hash externally identified as WinVNC.exe
```

---

## Key Conclusion

The evidence supports:

```text
Dropbox delivery
→ user execution
→ MSI installation
→ SYSTEM-level deployment
→ timestamp modification
→ WinVNC / UltraVNC-related payload
→ staging cleanup
```

Not confirmed in the supplied telemetry:

```text
persistent VNC service
scheduled-task persistence
execution of C:\Games\taskhost.exe
actual VNC session
remote operator activity
credential dumping
process injection
malicious root certificate installation
confirmed C2
```

This report deliberately separates observed evidence, analyst inference, external enrichment, and unconfirmed hypotheses.
