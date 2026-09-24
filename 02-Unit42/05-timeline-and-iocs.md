# 05 — Timeline and Indicators

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
| 03:41:57.545 | `main1.msi` creation time changed | Timestamp manipulation |
| 03:41:57.604 | SYSTEM `msiexec.exe /V` starts | Privileged installer activity |
| 03:41:57.905 | `Preventivo` launches `msiexec /i main1.msi` | MSI installation |
| 03:41:58.389–420 | Multiple staged artifacts timestomped | Anti-forensic timestamp manipulation |
| 03:41:58.561–608 | SYSTEM `msiexec` writes files into `C:\Games` | Payload deployment |
| 03:41:58.686 | `taskschd.dll` loaded | Task Scheduler API interaction |
| 03:41:58.733–748 | Staging artifacts deleted | Cleanup |
| 03:41:58.795 | `Preventivo` terminates | End of observed execution |

---

## Primary Executable

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

```text
SHA256:
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3
```

```text
SHA1:
18A24AA0AC052D31FC5B56F5C0187041174FFC61
```

```text
MD5:
32F35B78A3DC5949CE3C99F2981DEF6B
```

---

## MSI

```text
main1.msi
```

```text
SHA256:
B73B46F35142989A10C91AA887F94037271B8EE7148CC3BFB061AE9848ED1FD9
```

---

## Staged Executables / DLLs

### taskhost.exe

```text
SHA256:
3FB38EEFB8DB4D52BE428FACC8A242997AB2AD58A8D08980A7688C9BF0B30454
```

### viewer.exe

```text
SHA256:
E48AAC5148B261371C714B9E00268809832E4F82D23748E44F5CFBBF20CA3D3F
```

### vnchooks.dll

```text
SHA256:
4D12FEBD622266220AA2DD2074972EE82545C144DC599F68866212A29DB9F442
```

### ddengine.dll

```text
SHA256:
0D44439A0425DF8ABF338BD1496679A144DD705A51832A05C1A4ED1F76756EBA
```

### UVncVirtualDisplay.dll

```text
SHA256:
FF9D8F7FC2C3F5D0AFAF6F76E87D41FEEABF54FACBE26DC59661A78830F32972
```

---

## Network Indicators

Observed DNS:

```text
uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com
www.example.com
```

Observed TCP destination:

```text
93.184.216.34:80
```

### Important

`www.example.com` / `93.184.216.34` should not be treated as a confirmed malicious C2 IOC based on this dataset.

---

## Important Paths

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

```text
C:\Users\CyberJunkie\AppData\Roaming\
Photo and Fax Vn\Photo and vn 1.1.2\
install\F97891C\
```

```text
C:\Games\
```

---

## Confirmed vs Unconfirmed

### Confirmed

```text
Dropbox delivery
user execution
MSI installation
SYSTEM installer activity
C:\Games payload deployment
timestomping
UltraVNC-related components
DNS activity
TCP connection
staging cleanup
```

### Not Confirmed

```text
phishing
VNC execution
remote session
remote operator activity
service persistence
scheduled task persistence
Run/RunOnce persistence
credential dumping
process injection
malicious root certificate
C2
```
