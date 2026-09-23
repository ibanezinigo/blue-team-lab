# 01 — Initial Analysis

## Manual Review

The investigation started with a chronological review of `auth.log`.

An earlier successful root login was observed:

```text
Mar  6 06:19:52 ip-172-31-35-28 sshd[1465]: AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys root SHA256:4vycLsDMzI+hyb9OP3wd18zIpyTqJmRq/QIZaLNrg8A failed, status 22
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:19:54 ip-172-31-35-28 systemd-logind[411]: New session 6 of user root.
```

There is not enough evidence to classify `203.101.190.9` as malicious.

```text
203.101.190.9
Classification: Observed / Unknown
```

A successful login from an external IP is interesting, but is not enough by itself to attribute malicious activity.

## SSH Brute-Force Activity

At approximately `06:31:31`, `65.2.161.68` begins generating numerous SSH authentication failures:

```text
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68
Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: Invalid user admin from 65.2.161.68 port 46444
```

Observed target usernames include:

```text
admin
server_adm
backup
svc_account
root
```

The combination of multiple failed attempts, several usernames, rapid succession and a single source is consistent with an automated SSH credential attack.

## Useful Commands

### Authentication overview

```bash
grep -E "Invalid user|Failed password|Accepted password" auth.log
```

### Failed attempts by source IP

```bash
grep "Failed password" auth.log | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -nr
```

### Invalid users

```bash
grep "Invalid user" auth.log
```

### Count targeted usernames

```bash
grep "Invalid user" auth.log | awk '{print $8}' | sort | uniq -c | sort -nr
```

> The exact `awk` field may require adjustment depending on the log format.

### Follow the suspected attacker

```bash
grep "65.2.161.68" auth.log
```

With line numbers:

```bash
grep -n "65.2.161.68" auth.log
```

### Show context around an event

```bash
grep -B 5 -A 10 "Accepted password for root from 65.2.161.68" auth.log
```

## Initial Assessment

```text
65.2.161.68     High-confidence suspicious source
203.101.190.9   Observed / Unknown
```
