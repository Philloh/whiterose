---
title: "MITRE ATLAS: Threat Modeling for Machine Learning Systems"
date: 2026-02-14 10:00:00 +0300
categories: [AI]
tags: [mitre-atlas, threat-modeling, ml-security, adversarial-ml]
pin: false
---

## Summary

**MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base modeled after ATT&CK for enterprise IT, but focused on **ML lifecycle stages**—from dataset curation through deployment and monitoring. The framework is maintained at [atlas.mitre.org](https://atlas.mitre.org/) with community contributions from Microsoft, MITRE, and researchers. It helps teams vocabulary-align red teaming, bug bounty scopes, and control design.

## Structure of the framework

ATLAS organizes:

- **Tactics** — adversary goals (e.g., persistence in ML supply chain, evasion at inference time).
- **Techniques** — methods to achieve tactics (e.g., **AML.T0051.000 — LLM Prompt Injection** listed in the 2024/2025 matrix expansions).
- **Case studies** — public incidents mapped to techniques (e.g., poisoned models, adversarial examples against vision classifiers).

Unlike generic OWASP LLM lists, ATLAS explicitly covers **non-LLM ML**—gradient-based evasion, model inversion, membership inference—documented in academic literature ([Biggio & Roli, 2018 survey](https://arxiv.org/abs/1801.02774)).

## Example technique chain (conceptual)

| Stage | ATLAS-relevant concern |
| ----- | ---------------------- |
| Dataset | Poisoning / backdoor insertion (AML.T0020) |
| Training | Supply chain compromise of notebooks or pipelines |
| Deployment | Model stealing via query API |
| Inference | Evasion attacks on vision/spam filters |
| LLM apps | Prompt injection leading to tool abuse |

Mapping purple-team scenarios to ATLAS IDs makes **repeatable exercises** and audit artifacts.

## Using ATLAS with ATT&CK

Modern apps blend classic IT and ML:

- Initial access may be **phishing** (ATT&CK TA0001).
- Impact may be ** fraudulent inference** or **data exfil via LLM tools** (ATLAS).

Joint matrices help SOC analysts who already run ATT&CK detection engineering extend playbooks without reinventing taxonomy.

## Limitations

ATLAS documents **known adversary behaviors**—it is not a compliance standard. Technique coverage evolves; teams should cite matrix **version/date** in reports.

## References

- [MITRE ATLAS — official site](https://atlas.mitre.org/)
- [MITRE ATLAS GitHub](https://github.com/mitre-atlas/atlas-data)
- [Microsoft — MITRE ATLAS for AI red teaming (2021 announcement)](https://www.microsoft.com/en-us/security/blog/2021/10/22/mitres-ml-adversarial-threat-matrix/)
- [Biggio & Roli — Wild Patterns (2018)](https://arxiv.org/abs/1801.02774)
