# 06 — Timeline and Indicators

## Timeline

| Time (UTC) | Event | Interpretation |
|---|---|---|
| 03:41:25 | Firefox queries `*.dl.dropboxusercontent.com` | Dropbox delivery activity |
| 03:41:26 | Firefox creates `Preventivo24.02.14.exe.exe` | File downloaded |
| 03:41:30 | `Zone.Identifier` created | Internet-origin metadata |
| 03:41:55 | SmartScreen activity | File evaluated before execution |
| 03:41:56.538 | `explorer.exe` launches `Preventivo24.02.14.exe.exe` | Interactive user execution |
| 03:41:56.955 | `Preventivo` queries `www.example.com` | DNS activity |
| 03:41:57.159 | `Preventivo` connects to `93.184.216.34:80` | Outbound TCP connection |
| 03:41:57.545 | `main1.msi` creation time modified | Timestamp modification |
| 03:41:57.604 | SYSTEM `msiexec.exe /V` starts | Privileged installer activity |
| 03:41:57.905 | `Preventivo` launches `msiexec /i main1.msi` | MSI installation |
| 03:41:58.389–420 | Multiple staged artifacts receive older creation timestamps | Timestamp restoration/manipulation |
| 03:41:58.561–608 | SYSTEM `msiexec` writes files into `C:\Games` | Payload deployment |
| 03:41:58.686 | `taskschd.dll` loaded | Task Scheduler API interaction |
| 03:41:58.733–748 | Staging artifacts deleted | Cleanup |
| 03:41:58.795 | `Preventivo` terminates | End of observed execution |

# Indicators

## Primary Executable

```text
Path:
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe

SHA256:
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

## MSI

```text
main1.msi

SHA256:
B73B46F35142989A10C91AA887F94037271B8EE7148CC3BFB061AE9848ED1FD9
```

## WinVNC Binary Deployed as taskhost.exe

```text
Observed path:
C:\Games\taskhost.exe

SHA256:
3FB38EEFB8DB4D52BE428FACC8A242997AB2AD58A8D08980A7688C9BF0B30454
```

VirusTotal identifies this hash as `WinVNC.exe`.

## viewer.exe

```text
SHA256:
E48AAC5148B261371C714B9E00268809832E4F82D23748E44F5CFBBF20CA3D3F
```

## VNCHooks.dll

```text
SHA256:
4D12FEBD622266220AA2DD2074972EE82545C144DC599F68866212A29DB9F442
```

## ddengine.dll

```text
SHA256:
0D44439A0425DF8ABF338BD1496679A144DD705A51832A05C1A4ED1F76756EBA
```

## UVncVirtualDisplay.dll

```text
SHA256:
FF9D8F7FC2C3F5D0AFAF6F76E87D41FEEABF54FACBE26DC59661A78830F32972
```

## Network Observables

```text
uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
www.example.com
93.184.216.34:80
```

`www.example.com` / `93.184.216.34` are observed network artifacts, not confirmed malicious C2 indicators.

# MITRE ATT&CK Mapping

| Technique | ID | Confidence | Evidence |
|---|---|---:|---|
| User Execution | T1204 | High | Interactive execution from Explorer context |
| Ingress Tool Transfer | T1105 | Medium | Executable downloaded via Firefox from Dropbox |
| Signed Binary Proxy Execution: Msiexec | T1218.007 | High | `msiexec.exe /i main1.msi` |
| File Deletion | T1070.004 | High | Staging artifacts deleted after installation |
| Remote Access Software | T1219 | High | WinVNC / UltraVNC-related payload; `taskhost.exe` hash identified as WinVNC |
| Masquerading | T1036 | Medium | WinVNC binary deployed as `taskhost.exe` |
| Timestomp | T1070.006 | Medium / Context-dependent | Creation times modified, but at least `main1.msi` matches an independently observed original timestamp |
| Scheduled Task/Job | T1053 | Low / Unconfirmed | `taskschd.dll` loaded but no task creation evidence |

# Confirmed vs Unconfirmed

## Confirmed

```text
Dropbox delivery
user execution
MSI installation
SYSTEM installer activity
C:\Games payload deployment
creation-time modification
WinVNC / UltraVNC-related payload
DNS activity
TCP connection
staging cleanup
```

## Strongly Corroborated by External Enrichment

```text
Preventivo is WinVNC / UltraVNC-based
taskhost.exe is the same binary VirusTotal identifies as WinVNC.exe
```

## Not Confirmed

```text
phishing
execution of C:\Games\taskhost.exe
VNC session
remote operator activity
service persistence
scheduled-task persistence
Run / RunOnce persistence
credential dumping
process injection
malicious root certificate
C2
```
