# 04 — File Activity and Timestomping

## Staging Directory

The suspicious installer staged files under:

```text
C:\Users\CyberJunkie\AppData\Roaming\
Photo and Fax Vn\Photo and vn 1.1.2\
install\F97891C\
```

A significant portion of the staged payload was located under:

```text
WindowsVolume\Games\
```

---

## Confirmed File Creation

Examples of files created by the suspicious executable in staging:

```text
c.cmd
cmmc.cmd
on.cmd
once.cmd
taskhost.exe
viewer.exe
```

The SYSTEM-level Windows Installer process then created:

```text
C:\Games\on.cmd
C:\Games\c.cmd
C:\Games\cmmc.cmd
C:\Games\viewer.exe
C:\Games\once.cmd
C:\Games\taskhost.exe
```

---

## Timestamp Manipulation

Sysmon Event ID 2 showed creation-time changes affecting:

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

The file was created during the incident and then assigned an older creation timestamp.

### Assessment

This is direct evidence of creation-time manipulation and is consistent with timestomping.

---

## Staging Cleanup

After installation, the suspicious process deleted multiple staging artifacts, including:

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

---

## Notable File Deletion

The deletion event for:

```text
once.cmd
```

contained:

```text
Archived:
false - shredded file with pattern 0x74697865
```

### Assessment

This is stronger than a simple delete event and should be noted as potential anti-forensic cleanup.

---

## Important Distinction

The staging copies and final deployed copies must not be confused.

For example:

```text
Staging:
...\F97891C\WindowsVolume\Games\taskhost.exe

Final location:
C:\Games\taskhost.exe
```

The staging copy was later deleted.

That does **not** prove the final `C:\Games\taskhost.exe` was deleted.

---

## File Activity Summary

```text
download
→ staging
→ timestamp manipulation
→ privileged deployment to C:\Games
→ staging cleanup
```

This sequence is one of the strongest behavioral indicators in the dataset.
