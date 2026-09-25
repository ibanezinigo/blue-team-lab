# 07 — Detection and Response

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

### 2. Explorer Launching Downloaded Executables

High-value pattern:

```text
explorer.exe
    ↓
executable from Downloads
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

### 3. Suspicious MSI Installation

Detect:

```text
user executable
    ↓
msiexec.exe /i
    ↓
MSI under AppData or another user-writable directory
```

This becomes stronger when followed by privileged Windows Installer activity.

### 4. Windows Installer Writing Executables to Unusual Locations

High-value behavior:

```text
msiexec.exe
running as NT AUTHORITY\SYSTEM
```

creating executable or script content in unusual directories such as:

```text
C:\Games\
C:\Users\Public\
C:\ProgramData\<unexpected>\
```

### 5. Remote Access Software Under Misleading Filenames

Hunt for known WinVNC / UltraVNC hashes appearing under unusual names.

Example:

```text
WinVNC.exe hash
→ deployed as C:\Games\taskhost.exe
```

This is stronger than detecting the filename alone.

### 6. Burst of Creation-Time Modifications

Useful correlation:

```text
same ProcessGUID
+
multiple Event ID 2 events
+
many files
+
very short time window
```

Do not automatically classify this as anti-forensic timestomping without context.

Useful follow-up questions:

```text
Do assigned timestamps match original packaged timestamps?
Are timestamps arbitrary?
Are files subsequently deleted?
Is the same behavior repeated across unrelated artifacts?
```

### 7. Remote-Access Components

Contextual detection candidates:

```text
UltraVNC.ini
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
WinVNC.exe hashes
```

Remote administration software can be legitimate, so detection should incorporate:

```text
path
parent process
installer source
user context
renaming
persistence mechanism
network behavior
```

### 8. Create → Timestamp Change → Delete

Useful correlation:

```text
FileCreate
→ File Creation Time Changed
→ FileDelete
```

for the same file or process within a short interval.

# Response Actions

If this activity were observed in a real environment:

1. Isolate the affected endpoint.
2. Preserve the original executable and MSI.
3. Collect files remaining under `C:\Games`.
4. Hash `taskhost.exe`, `viewer.exe`, scripts and DLLs.
5. Inspect the `.cmd` files.
6. Check Windows Services for references to `C:\Games`.
7. Check Task Scheduler for suspicious tasks.
8. Review Run / RunOnce and other persistence locations.
9. Review EDR, firewall and proxy telemetry for later WinVNC activity.
10. Hunt the initial payload SHA256 across the environment.
11. Hunt the WinVNC SHA256 deployed as `taskhost.exe`.
12. Hunt the Dropbox URL and suspicious filename in browser/proxy/email telemetry.
13. Search other endpoints for the same `C:\Games` paths and hashes.
14. If later evidence confirms remote access or credential theft, rotate exposed credentials.

# Highest-Priority Findings

```text
1. suspicious downloaded executable
2. interactive execution
3. MSI installation from AppData
4. SYSTEM-level Windows Installer deployment
5. WinVNC binary deployed as taskhost.exe
6. multiple creation-time modifications
7. staging cleanup
```
