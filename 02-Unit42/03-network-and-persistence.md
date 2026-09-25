# 03 — Network and Persistence Assessment

## DNS and Network

The suspicious process queried:

```text
www.example.com
```

and initiated:

```text
Protocol: TCP
Source: 172.17.79.132:61177
Destination: 93.184.216.34:80
Initiated: True
```

Outbound network activity is confirmed, but this evidence does not justify calling the destination command-and-control.

## Persistence Investigation

The investigation looked for:

```text
Windows services
scheduled tasks
Run / RunOnce
Startup Folder
Winlogon
TaskCache
WMI persistence
```

No persistence mechanism was confirmed.

## Scheduled Task Indicator

The process loaded:

```text
C:\Windows\SysWOW64\taskschd.dll
```

This shows Task Scheduler API interaction, not task creation.

No supporting evidence was observed for:

```text
schtasks.exe
TaskCache changes
task XML creation
task action referencing C:\Games
```

Therefore:

```text
Scheduled-task persistence = NOT CONFIRMED
```

## Service Creation Labels

Several Sysmon registry events were labeled `T1543 - Service Creation`, but the target paths were primarily BAM entries:

```text
HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\...
```

BAM activity is not proof of a newly created service.

Therefore:

```text
Service persistence = NOT CONFIRMED
```

## Certificate Store Activity

The installer interacted with:

```text
...\SystemCertificates\CA\Certificates
...\SystemCertificates\Root\Certificates
```

but the events do not identify a specific certificate being added.

Therefore:

```text
Malicious root certificate installation = NOT CONFIRMED
```

## Remote Access Assessment

VirusTotal identifies the hash of the deployed `taskhost.exe` as `WinVNC.exe`.

This strongly supports remote-access capability being present, but does not prove:

```text
taskhost.exe execution
listening VNC service
automatic startup
remote session
operator connection
```

| Finding | Confidence |
|---|---:|
| Suspicious process performed DNS | High |
| Suspicious process initiated TCP/80 | High |
| WinVNC / UltraVNC-related payload present | High |
| Remote-access binary deployed | High |
| VNC process executed | Not observed |
| VNC session occurred | Not confirmed |
| Scheduled-task persistence | Not confirmed |
| Service persistence | Not confirmed |
| C2 communication | Not confirmed |
