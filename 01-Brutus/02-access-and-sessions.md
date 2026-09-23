# 02 — Successful Access and Session Analysis

## Successful Root Authentication

After the failed attempts, the attacker successfully authenticates as `root`:

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

This strongly indicates that valid `root` credentials were obtained.

## Authentication vs Interactive Session

```text
Successful SSH authentication
        │
        ▼
Session initialization
        │
        ▼
Interactive terminal session
```

A successful SSH authentication does not necessarily imply that an interactive TTY was created.

This distinction matters when correlating `auth.log` with `wtmp`.

## Useful Commands

### Successful SSH logins

```bash
grep "Accepted password" auth.log
```

### Failed authentication

```bash
grep -E "Failed password|Invalid user" auth.log
```

### Session activity

```bash
grep -E "session opened|session closed" auth.log
```

## Analyst Assessment

The event at `06:31:40` confirms that the credential attack reached valid credentials.

The authentication at `06:32:44` is particularly relevant because it correlates with the interactive `pts/1` session later recorded in `wtmp`.
