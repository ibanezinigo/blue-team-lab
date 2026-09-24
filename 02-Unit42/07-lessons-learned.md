# 07 — Lessons Learned

## 1. Start Broad, Then Pivot

The suspicious filename was not known in advance.

The investigation began with:

```text
What event types do I have?
```

Then:

```text
What processes executed?
```

Only after reviewing the small number of Event ID 1 events did the suspicious process become visible.

---

## 2. ProcessGUID Is More Reliable Than PID Alone

PID reuse can create ambiguity.

ProcessGUID allowed the investigation to follow the same process across:

```text
Process Creation
FileCreate
Timestomp
Registry
DNS
Network
FileDelete
Process Termination
```

---

## 3. Investigate Backward and Forward

Once `Preventivo24.02.14.exe.exe` was identified, the investigation moved in both directions.

Backward:

```text
Where did this file come from?
```

This led to:

```text
Firefox
→ Dropbox
→ Zone.Identifier
```

Forward:

```text
What did this process do?
```

This led to:

```text
MSI
→ msiexec
→ SYSTEM
→ C:\Games
→ UltraVNC-related artifacts
→ cleanup
```

---

## 4. RuleName Is a Hint, Not Proof

Sysmon labels included:

```text
Credential Dumping
Process Injection
Service Creation
Install Root Certificate
Scheduled Task
```

The underlying telemetry did not prove several of those techniques.

The analyst must always inspect:

```text
what actually happened
```

rather than accepting:

```text
what the rule called it
```

---

## 5. Separate Observation From Inference

Example:

### Observed

```text
explorer.exe launched Preventivo24.02.14.exe.exe
```

### Reasonable inference

```text
interactive user execution
```

### Too strong

```text
the user definitely double-clicked the file
```

The third statement cannot be proven from Sysmon alone.

---

## 6. Remote Access Is Not the Same as Persistence

UltraVNC-related artifacts strongly suggest remote-access functionality.

But:

```text
remote-access software present
```

does not automatically mean:

```text
persistent remote-access service confirmed
```

Persistence requires its own evidence.

---

## 7. Absence of Evidence Must Be Reported Correctly

No Event ID 1 showed:

```text
C:\Games\taskhost.exe
C:\Games\viewer.exe
```

The correct statement is:

> Their execution was not observed in the supplied telemetry.

Not:

> They never executed.

The dataset may simply end before later activity occurred.

---

## 8. Final Investigation Model

The workflow used in this case can be reused in future SOC investigations:

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
10. Review cleanup / anti-forensics
11. Build timeline
12. Extract indicators
13. Map MITRE only when evidence supports it
14. Separate confirmed findings from hypotheses
```

This evidence-driven approach produces a stronger investigation than answering isolated challenge questions.
