---
title: "The xz Utils Backdoor: How a Maintainer Compromise Rewrote Supply-Chain Risk"
date: 2025-11-22 11:00:00 +0300
categories: [Security Research]
tags: [supply-chain, backdoor, open-source, xz, cve-2024-3094]
pin: false
---

On **29 March 2024**, PostgreSQL developer **Andres Freund** reported unusual SSH latency on Debian sid. The root cause was not a kernel bug — it was a **deliberately planted backdoor** in upstream **xz Utils** versions **5.6.0** and **5.6.1**, tracked as **[CVE-2024-3094](https://www.cve.org/CVERecord?id=CVE-2024-3094)** with a CVSS score of **10.0**.

This incident is one of the most documented open-source supply-chain compromises in recent history. It is worth studying because the attacker optimized for **stealth**, **build-time activation**, and **social engineering of maintainer trust** — not a noisy npm typo-squat.

## What was compromised?

**xz** is a widely used compression library. Many Linux distributions link **OpenSSH** against **liblzma** (part of xz). The malicious release modified **Autotools build scripts** and obfuscated test files so that, under specific conditions, a **pre-build object** altered **`RSA_public_decrypt`** behavior in **`liblzma`**, enabling **unauthorized SSH authentication** on affected systems.

Red Hat's analysis ([RHSA-2024:1404](https://access.redhat.com/security/cve/CVE-2024-3094)) and Ubuntu's advisory ([USN-6735-1](https://ubuntu.com/security/notices/USN-6735-1)) confirmed vulnerable tarballs; most stable releases **never shipped** 5.6.0/5.6.1, limiting real-world exposure.

## The social-engineering timeline (documented)

Open-source investigator **Rhea Karty** and others reconstructed a multi-year pressure campaign against the sole xz maintainer (**Lasse Collin**), including coordinated mailing-list accounts pushing for faster merges and additional co-maintainers. The persona **Jia Tan** eventually gained commit access and introduced the backdoor over several commits — a pattern [summarized by BleepingComputer](https://www.bleepingcomputer.com/news/security/backdoor-found-in-xz-utils-allows-data-to-be-sent-via-ssh/) and in Freund's original [oss-security post](https://www.openwall.com/lists/oss-security/2024/03/29/1).

Key lesson: **maintainer burnout + slow merges** became an exploitable governance weakness.

## Technical trigger (high level)

The backdoor activated when builds used certain **GCC** features and when **`LD_PRELOAD`-free** linkage paths matched attacker expectations. Obfuscation lived in **`.build`** artifacts and seemingly innocent **test data** (`bad-3-corrupt_lzma2.xz`), as described in [GitHub's security lab write-up](https://github.blog/security/vulnerability-research/remediation-of-cve-2024-3094/).

Detection for defenders:

| Signal | Action |
| ------ | ------ |
| `xz --version` shows **5.6.0 / 5.6.1** | Upgrade or downgrade per vendor guidance |
| Unexpected **`liblzma`** hooks near SSH | Compare package signatures; rebuild from known-good sources |
| Anomalous **`sshd`** latency | Freund's original symptom — investigate linked libraries |

## Defensive takeaways

1. **Reproducible builds + diff reviews** for compression/crypto libraries touching auth paths.
2. **Package lag on bleeding-edge tarballs** — stable distros accidentally became a control.
3. **Maintainer sustainability** is a security property, not a community nicety ([OpenSSF response](https://openssf.org/blog/2024/04/01/open-source-security-openssf-and-openssc-response-to-the-xz-utils-backdoor/)).
4. **Runtime integrity monitoring** (EDR, library load auditing) complements pre-release scanning.

## References

- [NVD — CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)
- [Andres Freund — oss-security disclosure (2024-03-29)](https://www.openwall.com/lists/oss-security/2024/03/29/1)
- [OpenSSF — xz Utils backdoor response](https://openssf.org/blog/2024/04/01/open-source-security-openssf-and-openssc-response-to-the-xz-utils-backdoor/)
- [GitHub Security Lab — remediation analysis](https://github.blog/security/vulnerability-research/remediation-of-cve-2024-3094/)
