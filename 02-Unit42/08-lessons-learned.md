# 08 — Lessons Learned

## 1. Start Broad, Then Pivot

The suspicious filename was not assumed in advance.

The investigation began with:

```text
What telemetry is available?
```

Then:

```text
What processes executed?
```

Only after reviewing the small number of Process Creation events did the suspicious process become the main pivot.

## 2. ProcessGUID Is More Useful Than PID Alone

ProcessGUID allowed correlation across:

```text
Process Creation
FileCreate
CreationTimeChanged
Registry
DNS
Network
FileDelete
Process Termination
```

## 3. Investigate Both Backward and Forward

Backward:

```text
Where did this file come from?
```

led to:

```text
Firefox
→ Dropbox
→ Zone.Identifier
```

Forward:

```text
What did this process do?
```

led to:

```text
MSI
→ msiexec
→ SYSTEM deployment
→ C:\Games
→ WinVNC / UltraVNC components
→ cleanup
```

## 4. RuleName Is a Hint, Not Proof

Sysmon labels included:

```text
Credential Dumping
Process Injection
Service Creation
Install Root Certificate
Scheduled Task
Timestomp
```

Several were not supported by the underlying event details.

The analyst must inspect what happened, not merely what the rule called it.

## 5. Separate Observation From Inference

Observed:

```text
explorer.exe launched Preventivo24.02.14.exe.exe
```

Reasonable inference:

```text
interactive user execution
```

Too strong:

```text
the user definitely double-clicked the file
```

## 6. Remote-Access Capability Is Not the Same as Persistence

VirusTotal enrichment strongly supports:

```text
taskhost.exe == WinVNC.exe by SHA256
```

But this does not automatically mean:

```text
service persistence
scheduled-task persistence
remote session
```

## 7. Zero VirusTotal Detections Does Not Mean Benign

Examples:

```text
main1.msi    → 0/59
viewer.exe   → 0/72
VNCHooks.dll → 0/70
```

Yet `main1.msi` is directly linked by Sysmon to the suspicious install chain.

Context matters more than detection ratio alone.

## 8. External Enrichment Can Change Interpretation

Initially, the repeated creation-time changes looked like straightforward anti-forensic timestomping.

VirusTotal showed that the creation time assigned to `main1.msi` closely matched its independently recorded original creation time.

Therefore the investigation was updated from:

```text
confirmed anti-forensic timestomping
```

to:

```text
confirmed timestamp modification
with uncertain intent
```

New evidence should refine the hypothesis rather than be forced to fit the original conclusion.

## 9. Absence of Evidence Must Be Reported Correctly

No Process Creation event showed:

```text
C:\Games\taskhost.exe
C:\Games\viewer.exe
```

Correct:

> Their execution was not observed in the supplied telemetry.

Incorrect:

> They never executed.

## 10. Reusable Investigation Model

```text
1. Inventory telemetry
2. Identify anomalous process
3. Build process tree
4. Pivot by ProcessGUID
5. Trace delivery backward
6. Trace behavior forward
7. Review filesystem activity
8. Review network activity
9. Review persistence evidence
10. Review cleanup
11. Build timeline
12. Extract indicators
13. Enrich selected hashes externally
14. Map MITRE only when supported
15. Separate confirmed findings from hypotheses
16. Revise conclusions when new evidence appears
```
