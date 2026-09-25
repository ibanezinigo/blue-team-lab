# 08 — Step-by-Step Investigation Walkthrough

## Purpose

This file reproduces the investigation from the beginning so another analyst can follow the same reasoning process without knowing the answer in advance.

The goal is not to jump directly to known indicators. The goal is to show how to move from:

```text
one Sysmon EVTX
```

to:

```text
delivery
→ execution
→ installation
→ privileged deployment
→ remote-access tooling
→ cleanup
```

using repeatable pivots.

---

# 1. Preserve the Original Evidence

Start with the original file:

```text
Microsoft-Windows-Sysmon-Operational.evtx
```

Do not edit or overwrite it.

Create a working directory and keep the original evidence separate from parsed output.

Example:

```text
Unit42/
├── evidence/
│   └── Microsoft-Windows-Sysmon-Operational.evtx
└── parsed/
```

The investigation should always be reproducible from the original EVTX.

---

# 2. Parse the EVTX

One practical option is Eric Zimmerman's `EvtxECmd`.

Example:

```powershell
.\EvtxECmd.exe `
  -f "C:\Users\m.lopez\Desktop\Microsoft-Windows-Sysmon-Operational.evtx" `
  --csv "C:\Users\m.lopez\Desktop\Unit42-output" `
  --csvf "Unit42.csv"
```

Open the resulting CSV with **Timeline Explorer**.

The reason for parsing first is simple:

```text
raw EVTX
→ difficult to correlate manually

CSV + Timeline Explorer
→ sortable
→ searchable
→ easy to pivot by ProcessGUID
→ easy to compare timestamps
```

PowerShell can also be used directly against the EVTX for focused queries.

---

# 3. Inventory the Available Event Types

Do not begin by searching for malware names.

First ask:

```text
What telemetry do I actually have?
```

Using PowerShell:

```powershell
Get-WinEvent -Path $evtx |
Group-Object Id |
Sort-Object Count -Descending |
Select-Object Count, Name
```

In this dataset, important events included:

```text
1  Process Creation
2  File Creation Time Changed
3  Network Connection
5  Process Terminated
7  Image Loaded
10 Process Access
11 File Create
12 Registry Object Create/Delete
13 Registry Value Set
15 FileCreateStreamHash
17 Named Pipe Created
22 DNS Query
23 File Delete
26 File Delete Detected
```

## Why start here?

Because the event distribution tells us where the investigation is likely to be efficient.

There are only a few **Process Creation** events, so Event ID 1 is a high-value starting point.

A dataset with thousands of Event ID 1 events might require a different triage strategy.

---

# 4. Build a Small PowerShell Helper

Sysmon stores useful fields inside EventData.

A helper makes repeated analysis easier:

```powershell
function Get-SysmonEventData {
    param(
        [string]$Path,
        [int]$EventId
    )

    Get-WinEvent -Path $Path -FilterXPath "*[System[(EventID=$EventId)]]" |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}

        foreach ($field in $xml.Event.EventData.Data) {
            $data[$field.Name] = $field.'#text'
        }

        [PSCustomObject]$data
    }
}
```

This lets us inspect only the fields that matter instead of reading the full XML or message body.

---

# 5. Review Process Creation First

Query Event ID 1:

```powershell
Get-SysmonEventData $evtx 1 |
Select-Object UtcTime,
              ProcessGuid,
              ProcessId,
              User,
              Image,
              CommandLine,
              ParentProcessGuid,
              ParentProcessId,
              ParentImage,
              ParentCommandLine,
              Hashes |
Sort-Object UtcTime |
Format-List
```

## What are we looking for?

Prioritize:

```text
executables from Downloads
executables from AppData
temporary directories
double extensions
unexpected parent-child relationships
suspicious command lines
user-writable paths
```

One process immediately stands out:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

with:

```text
ParentImage:
C:\Windows\explorer.exe
```

and user:

```text
DESKTOP-887GK2L\CyberJunkie
```

## First hypothesis

At this point, do **not** conclude malware.

Record:

```text
Observed:
A user-context executable from Downloads was launched from Explorer.

Interesting:
double .exe.exe extension
unexpected metadata
user-writable path
```

This process becomes the first pivot.

---

# 6. Record the ProcessGUID

The suspicious process has:

```text
ProcessGUID:
817bddf3-3684-65cc-2d02-000000001900
```

This is more useful than relying only on PID.

## Why?

A PID can be reused.

A ProcessGUID identifies the specific process instance and lets us correlate:

```text
DNS
network
files
registry
named pipes
deletions
termination
```

across the dataset.

---

# 7. Pivot Backward — Where Did the File Come From?

Once a suspicious process is identified, investigate in both directions.

First move **backward**:

```text
How did this file arrive?
```

Search Timeline Explorer globally for:

```text
Preventivo24.02.14.exe.exe
```

Do not limit the search to Event ID 1.

This reveals earlier events involving the same filename.

Look for:

```text
FileCreate
FileCreateStreamHash
Zone.Identifier
browser activity
DNS activity immediately before creation
```

The investigation shows Firefox creating:

```text
C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe
```

---

# 8. Inspect the Zone.Identifier

The file has a `Zone.Identifier` alternate data stream.

Relevant content:

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://www.dropbox.com/
HostUrl=https://...dl.dropboxusercontent.com/...
```

## Conclusion

This supports:

```text
Firefox
→ Dropbox
→ downloaded executable
```

## What it does NOT prove

It does not tell us how the user received the link.

Therefore do not write:

```text
phishing email delivered the payload
```

unless email evidence exists.

Correct wording:

```text
The executable was downloaded from Dropbox using Firefox.
The original delivery mechanism of the Dropbox link is unknown.
```

---

# 9. Return to the Suspicious Process and Pivot Forward

Now move forward:

```text
What did Preventivo do after execution?
```

Search globally for its ProcessGUID:

```text
817bddf3-3684-65cc-2d02-000000001900
```

In Timeline Explorer, this is one of the most useful filters in the whole investigation.

Sort ascending by timestamp.

Prioritize:

```text
Event ID 11 — File Create
Event ID 2  — Creation Time Changed
Event ID 17 — Named Pipe
Event ID 22 — DNS
Event ID 3  — Network
Event ID 12/13 — Registry
Event ID 23 — File Delete
Event ID 5  — Process Terminated
```

---

# 10. Identify the MSI

The process stages:

```text
...\F97891C\main1.msi
```

and later launches:

```text
msiexec.exe /i ...\main1.msi
```

This gives us a new investigation branch:

```text
Preventivo
→ main1.msi
→ msiexec
```

Every newly discovered child process or artifact becomes a potential pivot.

---

# 11. Follow the Direct Child msiexec.exe

Search for the child ProcessGUID from the Event ID 1 entry.

Confirm:

```text
ParentProcess:
Preventivo24.02.14.exe.exe

Child:
C:\Windows\SysWOW64\msiexec.exe
```

and a command line similar to:

```text
msiexec.exe /i "...main1.msi"
```

This directly proves:

```text
Preventivo launched the MSI installation
```

---

# 12. Identify the Privileged Windows Installer Process

During the same installation window, another `msiexec.exe` instance appears:

```text
User:
NT AUTHORITY\SYSTEM

Parent:
services.exe
```

Search its ProcessGUID globally.

Important process:

```text
PID:
10220

Image:
C:\Windows\System32\msiexec.exe

User:
NT AUTHORITY\SYSTEM
```

## Important precision

Do not invent a direct parent-child relationship if Sysmon does not show one.

The evidence shows:

```text
Preventivo → user-context msiexec /i main1.msi
```

and separately:

```text
services.exe → SYSTEM msiexec /V
```

These are correlated as part of the Windows Installer workflow.

That is different from claiming:

```text
user msiexec → SYSTEM msiexec
```

as a direct Sysmon lineage edge.

---

# 13. Follow SYSTEM msiexec File Activity

With the SYSTEM `msiexec.exe` ProcessGUID selected, inspect Event ID 11.

This reveals the strongest deployment evidence:

```text
C:\Games\on.cmd
C:\Games\c.cmd
C:\Games\cmmc.cmd
C:\Games\viewer.exe
C:\Games\once.cmd
C:\Games\taskhost.exe
```

## Why this is important

We can now move from:

```text
suspicious installer
```

to:

```text
confirmed privileged payload deployment
```

The process writing the final files is running as SYSTEM.

---

# 14. Pivot on the Final Directory

Search globally for:

```text
C:\Games\
```

Do not keep the SYSTEM `msiexec` ProcessGUID filter active.

We want to know whether other processes later interact with the deployed files.

Check for:

```text
Event ID 1  — execution
Event ID 3  — network
Event ID 7  — image load
Event ID 12/13 — registry
Event ID 23 — delete
```

## Result in this dataset

No Process Creation event shows:

```text
C:\Games\taskhost.exe
C:\Games\viewer.exe
```

Correct conclusion:

```text
Their execution was not observed in the supplied telemetry.
```

Incorrect conclusion:

```text
They never executed.
```

The dataset may simply stop before later activity.

---

# 15. Investigate the Staging Files

Return to the original `Preventivo` ProcessGUID.

Look at Event ID 11 and Event ID 2.

You will find files associated with the staged package, including:

```text
UltraVNC.ini
vnchooks.dll
UVncVirtualDisplay.dll
UVncVirtualDisplay.inf
uvncvirtualdisplay.cat
viewer.exe
taskhost.exe
ddengine.dll
c.cmd
cmmc.cmd
on.cmd
once.cmd
```

This is the first major clue that remote-access functionality may be involved.

At this stage, phrase the conclusion carefully:

```text
Observed:
VNC-related filenames/components are present.

Inference:
The package likely contains remote-access functionality.

Not yet proven:
actual VNC execution or remote session.
```

---

# 16. Analyze Creation-Time Changes

Filter Event ID:

```text
2
```

or inspect Event ID 2 rows for the suspicious ProcessGUID.

Many files have their creation times changed to older dates.

Example:

```text
taskhost.exe

PreviousCreationTimeUTC:
2024-02-14 03:41:58.404

CreationTimeUTC:
2024-01-10 18:12:26.513
```

## Initial interpretation

This resembles:

```text
MITRE ATT&CK T1070.006 — Timestomp
```

But do not immediately assign intent.

Record the fact first:

```text
The installer modified creation timestamps.
```

---

# 17. Use External Enrichment to Test the Timestamp Hypothesis

Search the SHA256 of `main1.msi` in VirusTotal:

```text
B73B46F35142989A10C91AA887F94037271B8EE7148CC3BFB061AE9848ED1FD9
```

VirusTotal reports:

```text
Creation Time:
2024-01-14 08:14:24 UTC
```

Sysmon shows the installer assigning:

```text
2024-01-14 08:14:23.713 UTC
```

These almost exactly match.

## Revised interpretation

This suggests that at least some Event ID 2 activity may be:

```text
restoring packaged timestamps after extraction
```

rather than purely:

```text
anti-forensic timestamp falsification
```

Therefore the final report uses:

```text
creation-time modification
```

as the confirmed finding.

`T1070.006` remains context-dependent rather than treated as unquestionably malicious anti-forensics.

---

# 18. Investigate DNS

Query Event ID 22:

```powershell
Get-SysmonEventData $evtx 22 |
Select-Object UtcTime,
              ProcessGuid,
              ProcessId,
              Image,
              QueryName,
              QueryResults |
Sort-Object UtcTime |
Format-List
```

For the suspicious process, observe:

```text
QueryName:
www.example.com
```

with an answer including:

```text
93.184.216.34
```

Correlate using:

```text
same ProcessGUID
close timestamp
same destination
```

---

# 19. Investigate Network Connections

Query Event ID 3:

```powershell
Get-SysmonEventData $evtx 3 |
Select-Object UtcTime,
              ProcessGuid,
              ProcessId,
              Image,
              Protocol,
              SourceIp,
              SourcePort,
              DestinationIp,
              DestinationPort,
              DestinationHostname |
Sort-Object UtcTime |
Format-List
```

Observe:

```text
Image:
Preventivo24.02.14.exe.exe

Protocol:
TCP

Destination:
93.184.216.34:80
```

## Conclusion

Confirmed:

```text
The suspicious executable performed outbound network activity.
```

Not confirmed:

```text
C2
```

Do not promote a network connection to command-and-control without supporting evidence.

---

# 20. Investigate Registry Activity

Review Event IDs:

```text
12
13
```

Look for:

```text
Run
RunOnce
Services
TaskCache
Winlogon
ImagePath
certificate stores
```

In this dataset, several events were automatically labeled:

```text
Service Creation
Install Root Certificate
```

but the actual paths must be inspected.

Example:

```text
HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\...
```

This is BAM activity.

It does **not** prove service creation.

---

# 21. Investigate Scheduled Task Indicators

The process loads:

```text
taskschd.dll
```

Sysmon labels the event:

```text
T1053 — Scheduled Task
```

That is a useful clue, not proof.

Search for:

```text
schtasks.exe
TaskCache
task XML
C:\Games paths in scheduled-task related activity
```

None are observed.

Final conclusion:

```text
Task Scheduler API interaction observed.
Scheduled-task persistence not confirmed.
```

---

# 22. Investigate Cleanup

Return to the original suspicious ProcessGUID.

Review Event ID 23.

The installer deletes staged copies of:

```text
main1.msi
c.cmd
cmmc.cmd
on.cmd
once.cmd
taskhost.exe
viewer.exe
vnchooks.dll
UVncVirtualDisplay.dll
ddengine.dll
```

This shows cleanup of the staging directory after deployment.

## Important distinction

Do not confuse:

```text
staging copy deleted
```

with:

```text
final C:\Games copy deleted
```

They are different paths.

---

# 23. Perform Hash Enrichment

Once the behavior is understood, enrich selected hashes.

Do not begin the investigation with VirusTotal and work backward from vendor labels.

Recommended order:

```text
telemetry first
→ hypothesis
→ external enrichment
→ refine hypothesis
```

The five most useful hashes were:

```text
Preventivo24.02.14.exe.exe
0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3

taskhost.exe
3FB38EEFB8DB4D52BE428FACC8A242997AB2AD58A8D08980A7688C9BF0B30454

viewer.exe
E48AAC5148B261371C714B9E00268809832E4F82D23748E44F5CFBBF20CA3D3F

VNCHooks.dll
4D12FEBD622266220AA2DD2074972EE82545C144DC599F68866212A29DB9F442

main1.msi
B73B46F35142989A10C91AA887F94037271B8EE7148CC3BFB061AE9848ED1FD9
```

---

# 24. Correlate taskhost.exe with WinVNC

VirusTotal identifies the same SHA256 as:

```text
WinVNC.exe
```

while the endpoint receives it as:

```text
C:\Games\taskhost.exe
```

This is a critical enrichment result.

It strengthens:

```text
Remote Access Software
```

and supports a masquerading assessment.

But still distinguish:

```text
binary identity = strongly corroborated
execution = not observed
persistence = not confirmed
remote session = not confirmed
```

---

# 25. Build the Final Timeline

Only after the pivots are complete should the timeline be written.

The sequence becomes:

```text
03:41:25  Firefox queries Dropbox infrastructure
03:41:26  Firefox creates Preventivo24.02.14.exe.exe
03:41:30  Zone.Identifier records Internet/Dropbox origin
03:41:56  Explorer launches Preventivo
03:41:56  Preventivo performs DNS query
03:41:57  Preventivo opens TCP connection
03:41:57  MSI installation begins
03:41:57  privileged Windows Installer activity begins
03:41:58  staged artifacts receive older creation timestamps
03:41:58  SYSTEM msiexec deploys files to C:\Games
03:41:58  staging artifacts are deleted
03:41:58  Preventivo terminates
```

---

# 26. Separate Findings by Confidence

## Confirmed

```text
Dropbox download
interactive execution
MSI installation
SYSTEM-level deployment
creation-time modification
WinVNC-related payload
network activity
staging cleanup
```

## Strongly Corroborated

```text
taskhost.exe is WinVNC.exe
Preventivo is WinVNC / UltraVNC-based
```

## Not Confirmed

```text
phishing
VNC execution
VNC persistence
remote session
operator activity
C2
credential dumping
process injection
malicious root certificate
```

This prevents assumptions from becoming "facts" as the report grows.

---

# 27. Replicable Investigation Flow

The entire workflow can be reused for similar Sysmon investigations:

```text
1. Preserve evidence
2. Parse EVTX
3. Inventory Event IDs
4. Review sparse/high-value Process Creation events
5. Identify anomalous process
6. Record ProcessGUID
7. Pivot backward to delivery
8. Pivot forward by ProcessGUID
9. Follow child processes
10. Follow privileged installer/service processes
11. Review final file deployment
12. Search final paths globally
13. Review staging artifacts
14. Analyze timestamp changes
15. Review DNS
16. Review network
17. Review registry
18. Test persistence hypotheses
19. Review cleanup
20. Enrich selected hashes externally
21. Reassess earlier hypotheses
22. Build timeline
23. Extract IoCs
24. Map MITRE only where evidence supports it
25. Separate confirmed, inferred and unconfirmed findings
```

---

# 28. Core Analytical Principle

The investigation is driven by pivots.

Each answer creates the next question:

```text
What executed?
        ↓
Where did it come from?
        ↓
What did it launch?
        ↓
What did the child process do?
        ↓
What files were deployed?
        ↓
Were those files executed?
        ↓
Did they create persistence?
        ↓
Did they communicate?
        ↓
What did they clean up?
        ↓
What can external intelligence confirm or challenge?
```

The objective is not to recognize the malware immediately.

The objective is to continuously ask:

```text
What evidence supports the next pivot?
```
