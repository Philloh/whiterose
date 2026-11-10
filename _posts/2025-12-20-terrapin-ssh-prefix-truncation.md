---
title: "Terrapin (CVE-2023-48795): Prefix Truncation in the SSH Binary Protocol"
date: 2025-12-20 14:00:00 +0300
categories: [Security Research]
tags: [ssh, cryptography, cve-2023-48795, protocol-security]
pin: false
---

## Summary

**Terrapin** ([CVE-2023-48795](https://www.cve.org/CVERecord?id=CVE-2023-48795)) is a class of attacks against the **SSH Binary Packet Protocol (BPP)** disclosed in December 2023 by researchers Fabian Bäumer, Marcus Brinkmann, and Jörg Schwenk ([terrapin-attack.com](https://terrapin-attack.com/)). The attack is **not** a remote code execution bug; it is a **prefix truncation** vulnerability that can downgrade integrity guarantees for early handshake messages when specific cipher modes are negotiated.

## Threat model (as published)

The authors demonstrate that an **active network attacker** (person-in-the-middle) who can inject, drop, or reorder packets during the handshake may:

- Remove an arbitrary number of messages **at the beginning** of the secure channel.
- Under certain **Encrypt-then-MAC (EtM)** configurations with **`ext-info-c`** / **`kex-strict-c-v00@openssh.com`** negotiation nuances, affect which security extensions are effectively honored.

The attack name refers to **truncating the front** of the negotiated transcript—like clipping the head of a terrapin shell.

## Affected configurations (high level)

The Terrapin site maintains a **[vulnerable software table](https://terrapin-attack.com/vulnerable.html)** listing OpenSSH, PuTTY, libssh, and other implementations. Mitigation generally involves:

1. **Strict key exchange** — OpenSSH 9.6+ introduces **`strict-kex`** behavior documented in OpenSSH release notes.
2. **Disabling EtM MAC modes** that enable the truncation primitive in the proof-of-concept, where administratively acceptable.
3. **Patching** to vendor-advised fixed versions.

The researchers explicitly state Terrapin **does not break confidentiality of bulk channel data** in the same way as a key recovery attack; the concern is **integrity of the handshake transcript** and downstream trust in negotiated features (e.g., keystroke timing obfuscation extensions, security-related channel bindings).

## Why this matters for operators

SSH is treated as a **trust anchor** for admin access, Git over SSH, tunneling, and CI deploy keys. Protocol-level flaws remind us that:

- **Version banners alone** do not prove handshake integrity.
- **MITM on untrusted networks** (coffee-shop Wi‑Fi, compromised ISP routes) remains in scope for nation-state and criminal adversaries with placement.
- **Hardening** (`VerifyHostKeyDNS` off, known_hosts pinning, VPN overlays) composes with patches rather than replacing them.

## Detection and response

- Inventory SSH servers and clients; compare against Terrapin vendor matrix.
- Prioritize **Internet-facing** and **jump host** SSH endpoints.
- Monitor for outdated **`OpenSSH_7.x`** banners on critical assets after vendor EOL guidance.

## References

- [Terrapin Attack — official site](https://terrapin-attack.com/)
- [CVE-2023-48795](https://www.cve.org/CVERecord?id=CVE-2023-48795)
- [OpenSSH 9.6 release notes (strict-kex)](https://www.openssh.com/txt/release-9.6)
- [Original research PDF](https://terrapin-attack.com/TerrapinAttack.pdf)
