# 04 — File Activity and Timestamp Analysis

## Staging Directory

The suspicious installer staged files under:

```text
C:\Users\CyberJunkie\AppData\Roaming\
Photo and Fax Vn\Photo and vn 1.1.2\
install\F97891C\
```

A significant portion of the payload was staged under:

```text
WindowsVolume\Games\
```

## Confirmed File Creation

Examples of files created in staging include:

```text
c.cmd
cmmc.cmd
on.cmd
once.cmd
taskhost.exe
viewer.exe
```

The SYSTEM-level Windows Installer process later created:

```text
C:\Games\on.cmd
C:\Games\c.cmd
C:\Games\cmmc.cmd
C:\Games\viewer.exe
C:\Games\once.cmd
C:\Games\taskhost.exe
```

## Creation-Time Modification

Sysmon Event ID 2 showed creation-time changes affecting artifacts including:

```text
main1.msi
powercfg.msi
c.cmd
cmmc.cmd
on.cmd
once.cmd
cmd.txt
UltraVNC.ini
taskhost.exe
viewer.exe
ddengine.dll
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
~.pdf
```

Example:

```text
taskhost.exe

PreviousCreationTimeUTC:
2024-02-14 03:41:58.404

CreationTimeUTC:
2024-01-10 18:12:26.513
```

### Confirmed Finding

The installer changed the filesystem creation timestamps of multiple staged artifacts to dates earlier than the incident.

That fact is directly supported by Sysmon.

## Why This Is Not Automatically Anti-Forensic Timestomping

Initially, the repeated Event ID 2 activity was consistent with MITRE ATT&CK T1070.006 `Timestomp`.

VirusTotal enrichment of `main1.msi` adds an important caveat.

Sysmon observed:

```text
PreviousCreationTimeUTC:
2024-02-14 03:41:57.545

CreationTimeUTC:
2024-01-14 08:14:23.713
```

VirusTotal independently reports the same SHA256 with:

```text
Creation Time:
2024-01-14 08:14:24 UTC
```

The near-exact match suggests that, at least for `main1.msi`, the installer may have restored or preserved an original packaged timestamp after extraction.

Therefore:

```text
CONFIRMED:
creation timestamps were modified

CONFIRMED:
older timestamps were assigned

POSSIBLE:
installer timestamp preservation/restoration

POSSIBLE:
anti-forensic timestomping

NOT DETERMINABLE:
attacker intent from Sysmon alone
```



## Staging Cleanup

After installation, the suspicious executable deleted multiple staging artifacts, including:

```text
main1.msi
~.pdf
c.cmd
cmmc.cmd
on.cmd
once.cmd
powercfg.msi
taskhost.exe
viewer.exe
ddengine.dll
vnchooks.dll
UVncVirtualDisplay.dll
```

The deletion event for `once.cmd` contained:

```text
Archived:
false - shredded file with pattern 0x74697865
```

## Staging vs Final Copy

Example:

```text
Staging:
...\F97891C\WindowsVolume\Games\taskhost.exe

Final:
C:\Games\taskhost.exe
```

The staging copy was later deleted.

That does **not** prove that the final `C:\Games\taskhost.exe` was deleted.

## Summary

```text
download
→ staging
→ creation-time modification
→ privileged deployment to C:\Games
→ staging cleanup
```
