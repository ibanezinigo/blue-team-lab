# 02 — Process and Installation Analysis

## Suspicious Process

Primary process:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

```text
PID:
10672

ProcessGUID:
817bddf3-3684-65cc-2d02-000000001900
```

---

## MSI Staging

The executable staged:

```text
C:\Users\CyberJunkie\AppData\Roaming\
Photo and Fax Vn\Photo and vn 1.1.2\
install\F97891C\main1.msi
```

The creation time of `main1.msi` was then changed from the incident time to an older value.

This becomes important later in the timestomping analysis.

---

## Named Pipe

The executable created:

```text
\ToServerAdvinst_Extract_C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

This is consistent with installer extraction activity.

---

## Windows Installer Execution

The suspicious executable launched:

```text
"C:\Windows\system32\msiexec.exe" /i
"C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\
Photo and vn 1.1.2\install\F97891C\main1.msi"
```

Installer properties included:

```text
AI_SETUPEXEPATH=
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

SETUPEXEDIR=
C:\Users\CyberJunkie\Downloads\

EXE_CMD_LINE=
"/exenoupdates /forcecleanup /wintime 1707880560"
```

---

## Process Relationship

The child `msiexec.exe` showed:

```text
ParentProcess:
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

ParentProcessID:
10672

ParentProcessGUID:
817bddf3-3684-65cc-2d02-000000001900
```

This directly proves the parent-child relationship.

---

## Privileged Windows Installer Activity

A separate instance of Windows Installer appeared as:

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

This instance performed the privileged installation activity.

---

## SYSTEM-Level Deployment

The SYSTEM-level `msiexec.exe` created:

```text
C:\Games\on.cmd
C:\Games\c.cmd
C:\Games\cmmc.cmd
C:\Games\viewer.exe
C:\Games\once.cmd
C:\Games\taskhost.exe
```

### Assessment

This is direct Sysmon FileCreate evidence.

The correct statement is:

> Windows Installer, running as SYSTEM, deployed multiple files into `C:\Games`.

The evidence does **not** show those files being executed afterward.

---

## UltraVNC-Related Artifacts

The staging directory contained artifacts such as:

```text
UltraVNC.ini
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
viewer.exe
```

Other staged components included:

```text
taskhost.exe
ddengine.dll
powercfg.msi
cmd.txt
c.cmd
cmmc.cmd
on.cmd
once.cmd
```

### Assessment

The package contains components strongly associated with UltraVNC-based remote-access functionality.

However, this alone does not prove:

```text
VNC service persistence
VNC execution
remote session
remote operator activity
```

---

## What Was Not Proven

The following were not observed as Process Creation events:

```text
C:\Games\taskhost.exe
C:\Games\viewer.exe
cmd.exe /c C:\Games\...
```

Therefore, execution of the deployed payload components remains unconfirmed in the supplied telemetry.
