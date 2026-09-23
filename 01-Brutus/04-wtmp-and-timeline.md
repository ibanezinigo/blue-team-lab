04 — `wtmp` Analysis and Incident Timeline
Parsing `wtmp`
Relevant entries produced by the supplied parser include:
```text
"USER"  "2549"  "pts/1" "ts/1"  "root"  "65.2.161.68"  "0"  "0"  "0"  "2024/03/06 01:32:45"  "387923"  "65.2.161.68"

"DEAD"  "2491"  "pts/1" ""      ""      ""             "0"  "0"  "0"  "2024/03/06 01:37:24"  "590579"  "0.0.0.0"

"USER"  "2667"  "pts/1" "ts/1"  "cyberjunkie"  "65.2.161.68"  "0"  "0"  "0"  "2024/03/06 01:37:35"  "475575"  "65.2.161.68"
```
Timestamp Difference
A five-hour difference was observed between `auth.log` and the parser output.
```text
auth.log
06:32:44

wtmp / utmp.py
01:32:45
```
A fixed five-hour offset strongly suggests a timezone conversion issue.
Normalize to UTC
```bash
TZ=UTC python3 utmp.py wtmp
```
Check the local timezone:
```bash
date
```
```bash
timedatectl
```
or:
```bash
python3 -c 'import datetime; print(datetime.datetime.now().astimezone())'
```
One-Second Difference
After timezone normalization:
```text
auth.log
06:32:44

wtmp
06:32:45
```
is not necessarily inconsistent.
```text
06:32:44
SSH authentication accepted
        │
        ▼
Session initialization
        │
        ▼
06:32:45
Interactive login recorded in wtmp
```
Incident Timeline
Time	Source	User	Activity
06:19:54	`203.101.190.9`	root	Earlier successful SSH login; not currently attributed to attacker
06:31:31	`65.2.161.68`	multiple	SSH credential attack begins
06:31:40	`65.2.161.68`	root	Successful root authentication
06:32:44	`65.2.161.68`	root	Second successful root authentication
~06:32:45	`65.2.161.68`	root	Interactive `pts/1` session recorded
06:34:18	Local	root	`cyberjunkie` group created
06:34:18	Local	root	`cyberjunkie` user created
06:34:26	Local	root	Password assigned
06:34:31	Local	root	User information modified
06:35:15	Local	root	`cyberjunkie` added to `sudo`
~06:37:24	Local	root	Root `pts/1` session terminates
06:37:34	`65.2.161.68`	cyberjunkie	Successful authentication
~06:37:35	`65.2.161.68`	cyberjunkie	Interactive session recorded in `wtmp`
06:37:57	Local	cyberjunkie → root	`/etc/shadow` accessed
06:39:38	Local	cyberjunkie → root	`linper.sh` retrieved using `curl`
> All timestamps should be normalized to the same timezone before final correlation.