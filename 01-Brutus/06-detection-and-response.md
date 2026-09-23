06 — Detection, Root Cause and Response
Root Cause
The initial compromise occurred through password-based SSH authentication against the `root` account.
The attacker performed multiple authentication attempts from:
```text
65.2.161.68
```
and eventually obtained successful access as:
```text
root
```
The available evidence does not reveal exactly how the correct password was obtained beyond the observed credential attack.
Allowing direct password authentication to the `root` account significantly increased the impact of the compromise.
Scope
Confirmed affected host
```text
ip-172-31-35-28
```
Confirmed compromised / attacker-controlled accounts
```text
root
cyberjunkie
```
Confirmed post-compromise activity
Creation of a privileged local account
Password assignment
Addition to the `sudo` group
Authentication using the persistence account
Access to `/etc/shadow`
Retrieval of an external shell script
Not confirmed
Execution of `linper.sh`
Lateral movement
Additional persistence mechanisms
Data exfiltration
Malicious activity from `203.101.190.9`
Detection Opportunities
SSH Brute Force
```bash
grep "Failed password" auth.log | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -nr
```
Potential detection logic:
```text
Same source IP
+
Multiple authentication failures
+
Multiple usernames
+
Short time window
```
Failed Authentication Followed by Success
```text
Repeated failed authentication
        │
        ▼
Successful authentication
        │
        ▼
Same source IP
```
This should be treated as higher severity than failed authentication alone.
New Local Account Creation
Monitor:
```text
useradd
adduser
groupadd
usermod
```
High-risk sequence:
```text
New account created
        │
        ▼
Password assigned
        │
        ▼
Added to sudo
```
Access to `/etc/shadow`
Monitor access to `/etc/shadow`, especially when performed by a recently created account or shortly after remote access.
External Tool Retrieval
Monitor utilities such as:
```text
curl
wget
scp
```
when retrieving scripts, binaries or tools from external infrastructure.
Containment & Remediation
Isolate or closely monitor the affected host.
Block or investigate `65.2.161.68`.
Disable and remove `cyberjunkie`.
Rotate the compromised `root` credentials.
Review privileged accounts for unauthorized changes.
Search for additional persistence.
Determine whether `linper.sh` or other content was executed.
Review SSH logs for additional source IPs or compromised accounts.
Search other systems for the same credentials or attacker IP.
Disable direct SSH login as `root` where possible.
Prefer SSH keys over passwords.
Apply rate limiting or banning controls for repeated failures.
Review `/etc/sudoers`.
Review `authorized_keys`.
Review cron jobs and scheduled tasks.
Review shell startup files and services.
Review outbound network activity.
Preserve forensic evidence before destructive remediation.
Hardening Opportunities
Where operationally appropriate:
```text
PermitRootLogin no
PasswordAuthentication no
```
Additional controls:
SSH key authentication
MFA through an appropriate access layer
Fail2ban or equivalent
Restricted management networks
Centralized authentication logging
Host-based monitoring
Alerts for new privileged users
Least privilege