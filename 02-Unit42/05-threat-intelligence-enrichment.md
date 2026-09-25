# 05 — Threat Intelligence Enrichment

## Methodology

VirusTotal was used as an external enrichment source for selected SHA256 hashes.

> VirusTotal detections, family labels, historical names and sandbox metadata are contextual intelligence. Behavioral conclusions in this investigation remain grounded primarily in the supplied Sysmon telemetry.

Review date:

```text
September 2026
```

## 1. Preventivo24.02.14.exe.exe

### SHA256

```text
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

VirusTotal reported:

```text
46 / 71 detections
```

Popular threat label:

```text
trojan.winvnc/based
```

Threat categories:

```text
trojan
hacktool
pua
```

Family labels:

```text
winvnc
based
ultravnc
```

VirusTotal filename:

```text
Fattura 2 2024.exe
```

This matches the `OriginalFileName` observed in Sysmon metadata.

### Assessment

This strongly corroborates the Sysmon-based conclusion that the initial payload is associated with WinVNC / UltraVNC remote-access functionality.

### Report

https://www.virustotal.com/gui/file/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3

---

## 2. taskhost.exe

### SHA256

```text
3FB38EEFB8DB4D52BE428FACC8A242997AB2AD58A8D08980A7688C9BF0B30454
```

VirusTotal reported:

```text
6 / 70 detections
```

VirusTotal identifies the same hash as:

```text
WinVNC.exe
```

Popular threat label:

```text
hacktool.ultravnc/ktxdfi
```

Threat categories included:

```text
hacktool
pua
trojan
```

Historical names shown by VirusTotal included:

```text
winvnc.exe
WinVNC
WinVNC.exe
_winVNC.exe
winvnc32n.exe
```

### Assessment

The same SHA256 was deployed by the installer under:

```text
C:\Games\taskhost.exe
```

while VirusTotal identifies it as `WinVNC.exe`.

This strongly supports the conclusion that the installer deployed a WinVNC remote-access binary under a different, Windows-like filename. This supports a masquerading assessment, although intent cannot be proven solely from the filename.

### Report

https://www.virustotal.com/gui/file/3fb38eefb8db4d52be428facc8a242997ab2ad58a8d08980a7688c9bf0b30454

---

## 3. viewer.exe

### SHA256

```text
E48AAC5148B261371C714B9E00268809832E4F82D23748E44F5CFBBF20CA3D3F
```

VirusTotal reported:

```text
0 / 72 detections
```

Observed properties:

```text
Name:
viewer.exe

Type:
Win32 EXE

Signed:
yes
```

### Assessment

`viewer.exe` was deployed as part of the same installer flow, but VirusTotal did not identify it as malicious or assign a clear malware family in the reviewed data.

Its exact role remains unconfirmed.

### Report

https://www.virustotal.com/gui/file/e48aac5148b261371c714b9e00268809832e4f82d23748e44f5cfbbf20ca3d3f

---

## 4. VNCHooks.dll

### SHA256

```text
4D12FEBD622266220AA2DD2074972EE82545C144DC599F68866212A29DB9F442
```

VirusTotal reported:

```text
0 / 70 detections
```

Observed properties:

```text
Name:
VNCHooks.dll

Type:
Win32 DLL

Signed:
yes
```

Historical names included:

```text
vnchooks.dll
VNCHooks
VNCHooks.dll
```

### Assessment

This supports the conclusion that the installer bundled legitimate or dual-use VNC components rather than every individual payload component being inherently malicious.

### Report

https://www.virustotal.com/gui/file/4d12febd622266220aa2dd2074972ee82545c144dc599f68866212a29db9f442

---

## 5. main1.msi

### SHA256

```text
B73B46F35142989A10C91AA887F94037271B8EE7148CC3BFB061AE9848ED1FD9
```

VirusTotal reported:

```text
0 / 59 detections
```

Observed properties:

```text
Name:
main1.msi

Type:
Windows Installer

Size:
2.49 MB
```

Metadata included:

```text
Subject:
Photo and vn

Author:
Photo and Fax Vn

Creating Application:
Photo and vn (Evaluation Installer)
```

VirusTotal reported:

```text
Creation Time:
2024-01-14 08:14:24 UTC
```

This closely matches the timestamp assigned to `main1.msi` in Sysmon:

```text
2024-01-14 08:14:23.713 UTC
```

VirusTotal displayed both:

```text
signed
invalid-signature
```

and reported that the certificate chain terminated in a root certificate not trusted by the trust provider.

### Assessment

Despite receiving no antivirus detections, Sysmon directly links `main1.msi` to the suspicious installation flow.

This is a useful example of:

```text
0 detections ≠ benign
```

The timestamp correlation also suggests that some Event ID 2 activity may represent restoration of original packaged timestamps rather than necessarily anti-forensic timestomping.

### Report

https://www.virustotal.com/gui/file/b73b46f35142989a10c91aa887f94037271b8ee7148cc3bfb061ae9848ed1fd9

---

## Enrichment Summary

| Artifact | VT Detection | Key Enrichment |
|---|---:|---|
| `Preventivo24.02.14.exe.exe` | 46/71 | WinVNC / UltraVNC-based malicious installer |
| `taskhost.exe` | 6/70 | Same hash identified as `WinVNC.exe` |
| `viewer.exe` | 0/72 | Signed component; exact role unconfirmed |
| `VNCHooks.dll` | 0/70 | Signed VNC-related component |
| `main1.msi` | 0/59 | MSI used in suspicious install flow; untrusted certificate chain |

## Final Enrichment Assessment

VirusTotal strongly reinforces:

```text
malicious initial installer
        ↓
MSI installation
        ↓
deployment of legitimate / dual-use VNC components
        ↓
WinVNC binary renamed as taskhost.exe
```

It does not prove:

```text
WinVNC execution
persistent service registration
remote session
operator activity
```
