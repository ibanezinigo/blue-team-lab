# 07 — Lessons Learned

## 1. Do Not Attribute Without Evidence

A successful login from `203.101.190.9` does not automatically make that IP malicious.

Useful confidence levels include:

```text
Confirmed malicious
High-confidence suspicious
Potentially suspicious
Observed / Unknown
Known legitimate
```

## 2. Authentication Is Not the Same as an Interactive Session

```text
auth.log
→ authentication and PAM activity

wtmp
→ interactive login/logout sessions
```

Correlating both sources produces stronger evidence.

## 3. Normalize Timezones

Before correlating:

```text
auth.log
wtmp
SIEM events
endpoint telemetry
network logs
```

timestamps should ideally be converted to a common timezone.

## 4. Follow Identities Across Events

```text
65.2.161.68
     │
     ├── repeated authentication failures
     ├── successful root authentication
     ├── interactive session
     └── later login as cyberjunkie
```

Sequences of related events are more valuable than isolated log lines.

## 5. Separate Evidence From Assumptions

The evidence proves:

```text
PWD=/home/cyberjunkie
curl https://.../linper.sh
```

It does not prove that `/home/cyberjunkie/linper.sh` was written to disk or executed.

A forensic report should distinguish:

```text
Observed fact
        vs
Analyst inference
```

## 6. Make Investigations Reproducible

Commands such as:

```text
grep
awk
sort
uniq
sed
```

allow another analyst to reproduce and validate the analysis.

## 7. Pivot From One Artifact to Another

A useful SOC mindset is:

```text
What happened?
      │
      ▼
Who performed it?
      │
      ▼
From where?
      │
      ▼
What happened before?
      │
      ▼
What happened afterwards?
      │
      ▼
Can another data source confirm it?
```

For Brutus:

```text
SSH failures
      │
      ▼
Successful root login
      │
      ▼
Interactive session
      │
      ▼
User creation
      │
      ▼
Privilege assignment
      │
      ▼
Persistence login
      │
      ▼
Credential access
      │
      ▼
External tool retrieval
```

## Final Takeaway

The main value of the Sherlock is not answering individual questions, but reconstructing the incident as a sequence of evidence-backed events.

```text
auth.log
   +
wtmp
   +
account activity
   +
privileged commands
   +
timeline analysis
```

produces a much stronger investigation than any single artifact alone.
