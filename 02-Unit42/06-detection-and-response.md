# 06 — Detection and Response

## Detection Opportunities

### 1. Suspicious Double Extensions

Alert on executables in user-writable directories with patterns such as:

```text
*.exe.exe
*.pdf.exe
*.doc.exe
```

Especially under:

```text
Downloads
Desktop
AppData
Temp
```

---

## 2. Explorer Launching Downloaded Executables

High-value pattern:

```text
explorer.exe
    ↓
unsigned executable from Downloads
```

Useful fields:

```text
ParentImage
Image
CommandLine
Hashes
User
IntegrityLevel
```

---

## 3. Suspicious MSI Installation

Detect:

```text
user executable
    ↓
msiexec.exe /i
    ↓
MSI under AppData or another user-writable directory
```

This becomes stronger when followed by SYSTEM-level Windows Installer activity.

---

## 4. Windows Installer Writing to Unusual Locations

Alert when:

```text
msiexec.exe
```

running as:

```text
NT AUTHORITY\SYSTEM
```

creates executable content in unusual directories such as:

```text
C:\Games\
C:\Users\Public\
C:\ProgramData\<unexpected>\
```

---

## 5. Mass Timestomping

A particularly strong behavioral detection:

```text
same ProcessGUID
+
multiple Event ID 2 events
+
many files
+
very short time window
```

Example:

```text
EXE
DLL
CMD
MSI
INF
CAT
```

all receiving older timestamps within milliseconds.

---

## 6. Remote-Access Components

Detection candidates include unusual deployment of:

```text
UltraVNC.ini
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
```

Context is essential because remote-access tools can also be legitimate.

---

## 7. Create → Timestomp → Delete

A useful correlation rule:

```text
FileCreate
→ CreationTimeChanged
→ FileDelete
```

for the same file and ProcessGUID within a short period.

---

# Response Actions

If this occurred in a real environment:

1. Isolate the endpoint.
2. Preserve the original executable and MSI.
3. Collect all files under `C:\Games`.
4. Hash `taskhost.exe`, `viewer.exe`, scripts and DLLs.
5. Inspect the `.cmd` contents.
6. Check Windows Services for references to `C:\Games`.
7. Check Task Scheduler for suspicious tasks.
8. Review Run / RunOnce and other persistence locations.
9. Search EDR, proxy and firewall logs for later activity.
10. Hunt the primary SHA256 across the environment.
11. Hunt the Dropbox URL and filename across browser/proxy/email telemetry.
12. Search other systems for the same hashes and `C:\Games` artifacts.
13. If later evidence confirms interactive remote access or credential theft, rotate potentially exposed credentials.

---

# Suggested Hunting Queries

## Conceptual Sysmon Hunt

Look for:

```text
Image endswith "\msiexec.exe"
AND User = "NT AUTHORITY\SYSTEM"
AND TargetFilename startswith "C:\"
AND TargetFilename NOT startswith "C:\Windows\"
AND TargetFilename NOT startswith "C:\Program Files\"
```

Then prioritize:

```text
.exe
.dll
.cmd
.ps1
.bat
```

---

# Response Priority

The highest-priority findings in this case are:

```text
1. suspicious user-downloaded executable
2. SYSTEM-level installer activity
3. payload deployment into C:\Games
4. mass timestomping
5. remote-access-related components
6. cleanup of staged payloads
```
