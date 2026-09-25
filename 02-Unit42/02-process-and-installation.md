# 02 — Process and Installation Analysis

## Primary Process

```text
Image:
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

PID:
10672

ProcessGUID:
817bddf3-3684-65cc-2d02-000000001900
```

## MSI Staging

The executable staged:

```text
C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\main1.msi
```

## Named Pipe

```text
\ToServerAdvinst_Extract_C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

This is consistent with installer extraction activity.

## Windows Installer Execution

The suspicious executable launched:

```text
"C:\Windows\system32\msiexec.exe" /i
"C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\
Photo and vn 1.1.2\install\F97891C\main1.msi"
```

Installer properties included:

```text
AI_SETUPEXEPATH=C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
SETUPEXEDIR=C:\Users\CyberJunkie\Downloads\
EXE_CMD_LINE="/exenoupdates /forcecleanup /wintime 1707880560"
```

The user-context `msiexec.exe` had `Preventivo24.02.14.exe.exe` as its direct parent.

## Privileged Windows Installer Activity

A separate process ran as:

```text
Image:
C:\Windows\System32\msiexec.exe

PID:
10220

User:
NT AUTHORITY\SYSTEM

IntegrityLevel:
System

Parent:
C:\Windows\System32\services.exe

CommandLine:
C:\Windows\system32\msiexec.exe /V
```

The evidence directly shows:

```text
Preventivo → user-context msiexec /i main1.msi
```

and separately:

```text
services.exe → SYSTEM msiexec /V
```

These are correlated as part of the same installation flow, but Sysmon does not show a direct ProcessGUID parent-child edge between the two `msiexec` instances.

## SYSTEM-Level Deployment

The SYSTEM `msiexec.exe` created:

```text
C:\Games\on.cmd
C:\Games\c.cmd
C:\Games\cmmc.cmd
C:\Games\viewer.exe
C:\Games\once.cmd
C:\Games\taskhost.exe
```

Payload deployment is confirmed. Post-install execution of these files is not observed in the supplied telemetry.

## WinVNC / UltraVNC Artifacts

The staging area contained:

```text
UltraVNC.ini
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
viewer.exe
taskhost.exe
```

VirusTotal later identified the SHA256 of `taskhost.exe` as `WinVNC.exe`, strongly supporting a WinVNC / UltraVNC remote-access payload.

```text
Payload deployment: CONFIRMED
Remote-access binary identity: STRONGLY CORROBORATED
Post-install execution: NOT OBSERVED
```
