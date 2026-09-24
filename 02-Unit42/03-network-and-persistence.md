# 03 — Network and Persistence Assessment

## DNS Activity

The suspicious process queried:

```text
www.example.com
```

Observed process:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

Resolved address included:

```text
93.184.216.34
```

---

## Network Connection

The same process initiated:

```text
Protocol:
TCP

Source:
172.17.79.132:61177

Destination:
93.184.216.34:80

Initiated:
True
```

### Assessment

Outbound network activity from the suspicious process is confirmed.

However, the available evidence does not justify classifying this destination as command-and-control.

The safest conclusion is:

> The suspicious executable performed outbound DNS and TCP activity.

---

## Persistence Investigation

The investigation looked for evidence of:

```text
Windows services
scheduled tasks
Run / RunOnce
Startup Folder
Winlogon
TaskCache
WMI persistence
```

No confirmed persistence mechanism was identified.

---

## Scheduled Task Indicator

The suspicious executable loaded:

```text
C:\Windows\SysWOW64\taskschd.dll
```

Sysmon labeled the event:

```text
T1053 - Scheduled Task
```

### Important Limitation

Loading `taskschd.dll` does not prove that a task was created.

No supporting evidence was observed for:

```text
schtasks.exe
TaskCache registry changes
task XML creation
task action referencing C:\Games
```

Therefore:

```text
Scheduled Task persistence = NOT CONFIRMED
```

---

## Service Creation Labels

Several Sysmon events carried labels such as:

```text
T1543 - Service Creation
```

However, the associated registry paths were primarily:

```text
HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\...
```

These BAM-related registry entries do not prove that a new Windows service was created.

No evidence was observed resembling:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<malicious service>\
    ImagePath = C:\Games\taskhost.exe
```

Therefore:

```text
Service persistence = NOT CONFIRMED
```

---

## Certificate Store Activity

The installer interacted with:

```text
...\Software\Microsoft\SystemCertificates\CA\Certificates
...\Software\Microsoft\SystemCertificates\Root\Certificates
```

Sysmon mapped these events to:

```text
T1553.004 - Install Root Certificate
```

### Assessment

The registry interaction is real.

However, the supplied events do not identify a specific certificate being added.

Therefore:

```text
Malicious root certificate installation = NOT CONFIRMED
```

---

## Remote Access Assessment

The evidence contains multiple UltraVNC-related artifacts.

The strongest defensible statement is:

> The installer deployed or staged components consistent with UltraVNC-based remote-access functionality.

What remains unconfirmed:

```text
remote-access process execution
listening VNC service
remote session
operator connection
persistent remote-access service
```

---

## Evidence Confidence

| Finding | Confidence |
|---|---:|
| Suspicious process performed DNS | High |
| Suspicious process initiated TCP/80 | High |
| Remote-access-related components present | High |
| VNC session occurred | Not confirmed |
| Scheduled task persistence | Not confirmed |
| Service persistence | Not confirmed |
| Malicious root certificate | Not confirmed |
| C2 communication | Not confirmed |
