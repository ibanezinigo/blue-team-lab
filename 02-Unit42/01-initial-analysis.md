# 01 — Initial Analysis

## Objective

```text
inventory event types
→ inspect high-value telemetry
→ review Process Creation events
→ identify anomalous process
→ pivot by ProcessGUID
→ investigate backward and forward
```

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

An Event ID or Sysmon `RuleName` was not considered malicious by itself.

## Delivery

Firefox queried Dropbox infrastructure:

```text
uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
```

and created:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

Its `Zone.Identifier` contained:

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://www.dropbox.com/
HostUrl=https://uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com/...
```

This supports:

```text
Firefox → Dropbox → downloaded executable
```

The Sysmon data does not reveal how the Dropbox link was originally delivered, so phishing or social engineering are not claimed as confirmed.

## Suspicious File

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

Metadata:

```text
FileVersion:      1.1.2
Description:      Photo and vn Installer
Product:          Photo and vn
Company:          Photo and Fax Vn
OriginalFileName: Fattura 2 2024.exe
```

Primary hash:

```text
SHA256:
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

## User Execution

At approximately:

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

## Main Pivot

```text
ProcessGUID:
817bddf3-3684-65cc-2d02-000000001900
```

This GUID was used to correlate process, file, registry, DNS, network, deletion and termination activity.
