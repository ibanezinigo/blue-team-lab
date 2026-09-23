🛡️ Brutus — SOC / DFIR Investigation
> Hack The Box Sherlock focused on Linux authentication logs, SSH brute-force activity, persistence and post-compromise analysis.
Overview
This investigation reconstructs a compromise of a Linux server using the evidence provided by the Sherlock.
The analysis focuses on:
SSH brute-force activity
Successful authentication
Session correlation
Persistence
Privilege usage
Credential access
Tool retrieval
Timeline reconstruction
Indicators of Compromise
MITRE ATT&CK mapping
Detection opportunities
Containment and remediation
Evidence
```text
auth.log
wtmp
utmp.py
```
`auth.log` contains authentication, SSH, account-management and `sudo` events.
`wtmp` is a binary database containing interactive login/logout information. The supplied `utmp.py` script is used to parse it.
Investigation Structure
File	Content
01-initial-analysis.md	Initial review, brute-force activity and useful filtering commands
02-access-and-sessions.md	Successful authentication and session analysis
03-persistence-and-post-exploitation.md	Account creation, privilege assignment and post-compromise activity
04-wtmp-and-timeline.md	`wtmp`, timezone handling and full incident timeline
05-iocs-and-mitre.md	IoCs, confidence levels and MITRE ATT&CK mapping
06-detection-and-response.md	Root cause, scope, detections and remediation
07-lessons-learned.md	Investigation methodology and lessons learned
Executive Summary
The evidence strongly indicates that `65.2.161.68` performed an SSH credential attack against the server and successfully authenticated as `root`.
After obtaining privileged access, the attacker:
Established an interactive SSH session.
Created the local user `cyberjunkie`.
Assigned a password to the new account.
Added it to the `sudo` group.
Logged in using `cyberjunkie`.
Accessed `/etc/shadow`.
Retrieved the contents of `linper.sh` using `curl`.
The creation of `cyberjunkie` represents a persistence mechanism.
A previous root login from `203.101.190.9` was observed, but the available evidence is insufficient to attribute it to the attacker.
Attack Flow
```text
SSH authentication failures
            │
            ▼
Multiple usernames attempted
            │
            ▼
Successful root authentication
            │
            ▼
Interactive SSH session
            │
            ▼
Create cyberjunkie
            │
            ▼
Assign password
            │
            ▼
Add cyberjunkie to sudo
            │
            ▼
Login using cyberjunkie
            │
            ▼
Read /etc/shadow
            │
            ▼
Retrieve linper.sh
```
Skills Practiced
`Linux Logs` · `SSH` · `Authentication Analysis` · `Incident Response` · `Timeline Reconstruction` · `Persistence Detection` · `MITRE ATT&CK` · `IOC Analysis` · `DFIR`
Tools Used
```text
grep
awk
sort
uniq
sed
utmp.py
Linux CLI
```
Responsible Disclosure
This repository documents investigation methodology and defensive analysis. No challenge flags or credentials are included.