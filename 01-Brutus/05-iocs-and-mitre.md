05 — Indicators of Compromise and MITRE ATT&CK
Indicators of Compromise
High-Confidence Attacker IP
```text
65.2.161.68
```
Evidence:
Numerous SSH authentication failures
Multiple usernames attempted
Successful authentication as `root`
Later authentication using `cyberjunkie`
Unauthorized Local Account
```text
cyberjunkie
```
Evidence:
Created after compromise
Password assigned
Added to `sudo`
Used from the attacker IP
Used to execute privileged commands
Suspicious URL
```text
https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```
Suspicious Artifact
```text
linper.sh
```
Retrieval is confirmed. Execution is not confirmed.
Sensitive File Accessed
```text
/etc/shadow
```
Observed but Not Confirmed Malicious
```text
203.101.190.9
```
Current classification:
```text
Observed / Unknown
```
MITRE ATT&CK Mapping
Activity	Technique	ID
SSH credential attack	Brute Force	`T1110`
Successful use of root credentials	Valid Accounts	`T1078`
Creation of `cyberjunkie`	Create Account: Local Account	`T1136.001`
Addition to privileged group	Account Manipulation	`T1098`
Access to `/etc/shadow`	OS Credential Dumping	`T1003`
Retrieval using `curl`	Ingress Tool Transfer	`T1105`
> These mappings are analyst classifications based on observed behavior.
Confidence Notes
Finding	Confidence
`65.2.161.68` performed the SSH credential attack	High
`root` credentials were compromised	High
`cyberjunkie` was attacker-created	High
`cyberjunkie` was used for persistence	High
`/etc/shadow` was accessed	High
`linper.sh` was retrieved	High
`linper.sh` was saved to disk	Not confirmed
`linper.sh` was executed	Not confirmed
`203.101.190.9` was malicious	Not confirmed
Lateral movement occurred	Not confirmed
