# 01 — Initial Analysis

## Objective

The first phase focused on identifying the suspicious execution chain without assuming prior knowledge of the challenge.

The workflow was:

```text
inventory event types
→ review high-value events
→ inspect Process Creation
→ identify anomalous process
→ pivot by ProcessGUID
```

---

## Relevant Sysmon Event IDs

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 2 | File Creation Time Changed |
| 3 | Network Connection |
| 5 | Process Terminated |
| 7 | Image Loaded |
| 10 | Process Access |
| 11 | File Create |
| 12 | Registry Object Create/Delete |
| 13 | Registry Value Set |
| 15 | FileCreateStreamHash |
| 17 | Named Pipe Created |
| 22 | DNS Query |
| 23 | File Delete |
| 26 | File Delete Detected |

The presence of an Event ID alone was not treated as malicious.

---

## Delivery

Firefox queried Dropbox content infrastructure:

```text
uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
```

Shortly afterward Firefox created:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

The file also received a `Zone.Identifier` stream containing:

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://www.dropbox.com/
HostUrl=https://uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com/...
```

### Assessment

This strongly supports:

```text
Firefox
→ Dropbox
→ downloaded executable
```

The evidence does not identify how the user originally received the Dropbox link.

Therefore, phishing or social engineering should **not** be stated as confirmed.

---

## Suspicious File Metadata

Observed filename:

```text
Preventivo24.02.14.exe.exe
```

Metadata:

```text
FileVersion:      1.1.2
Description:      Photo and vn Installer
Product:          Photo and vn
Company:          Photo and Fax Vn
OriginalFileName: Fattura 2 2024.exe
```

The following mismatches increased investigation priority:

```text
Preventivo24.02.14.exe.exe
Fattura 2 2024.exe
Photo and vn Installer
```

This inconsistency is suspicious but does not, by itself, prove malware.

---

## Primary Hash

```text
SHA256:
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

Additional hashes:

```text
SHA1:
18A24AA0AC052D31FC5B56F5C0187041174FFC61

MD5:
32F35B78A3DC5949CE3C99F2981DEF6B

IMPHASH:
36ACA8EDDDB161C588FCF5AFDC1AD9FA
```

---

## User Execution

At:

```text
2024-02-14 03:41:56.538 UTC
```

Sysmon recorded:

```text
ParentImage:
C:\Windows\explorer.exe

Image:
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

User:
DESKTOP-887GK2L\CyberJunkie

IntegrityLevel:
Medium
```

### Assessment

The parent process and session context are consistent with interactive user execution.

The evidence does not prove the exact GUI action used, so this report avoids stating that the user definitely double-clicked the file.

---

## Initial Pivot

The key ProcessGUID was:

```text
817bddf3-3684-65cc-2d02-000000001900
```

This ProcessGUID was used to correlate:

```text
process creation
file activity
timestamp changes
registry activity
DNS
network connections
file deletion
process termination
```

This was the main pivot that allowed the rest of the investigation to be reconstructed.
