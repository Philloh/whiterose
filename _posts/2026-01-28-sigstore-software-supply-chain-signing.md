---
title: "Sigstore, SLSA, and Artifact Signing: What Actually Changes in Supply Chain Defense"
date: 2026-01-28 09:00:00 +0300
categories: [Security Research]
tags: [supply-chain, sigstore, slsa, cosign]
pin: false
---

## Summary

Software supply chain attacks—**SolarWinds SUNBURST (2020)**, **Codecov bash uploader compromise (2021)**, **3CX desktop trojanization (2023)**—share a pattern: attackers substitute or modify **build artifacts** users already trust. **Sigstore** ([sigstore.dev](https://www.sigstore.dev/)) is an open-source project (Linux Foundation) aiming to make **cryptographic signing and verification** accessible for containers, binaries, and Git commits. This article summarizes what Sigstore components do—without claiming they alone prevent all supply-chain risk.

## Core Sigstore components

| Component | Purpose |
| --------- | ------- |
| **Fulcio** | Short-lived code-signing certificates bound to OIDC identity (e.g., GitHub Actions workflow identity) |
| **Rekor** | Immutable transparency log of signed artifact metadata |
| **Cosign** | CLI/tooling to sign and verify OCI images and blobs |

Google's [SLSA framework](https://slsa.dev/) (Supply-chain Levels for Software Artifacts) defines **provenance levels** (build liveness, isolated builds, non-falsifiable provenance). Sigstore is often deployed **alongside** SLSA generators in CI (e.g., GitHub Actions `slsa-github-generator`) to attest *who built what, from which commit, with which workflow*.

## What verification buys you

When a consumer runs:

```bash
cosign verify <image> --certificate-identity=... --certificate-oidc-issuer=...
```

they check that:

1. The image digest matches a signature in Rekor.
2. The signing certificate was issued to an expected OIDC identity.

This mitigates **casual registry tampering** and **wrong-image deploys** if policy enforcement (Kubernetes admission, deploy gates) **rejects unsigned or unverified images**.

## What it does not automatically fix

Sigstore does **not**:

- Prove the **source code is vulnerability-free**.
- Stop a **malicious insider** with legitimate signing credentials.
- Replace **dependency review** (npm/PyPI crates inside your app still need SBOM + scanning).

The [OpenSSF Scorecard](https://scorecard.dev/) and **[OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)** treat signing as one control among many.

## Practical adoption pattern

1. Sign release images in CI with **keyless** Cosign + Fulcio (OIDC).
2. Store Rekor bundle alongside deployment manifests.
3. Enforce verification in production admission (policy-as-code).
4. Publish SBOM ([SPDX](https://spdx.dev/) or [CycloneDX](https://cyclonedx.org/)) per release.

## References

- [Sigstore documentation](https://docs.sigstore.dev/)
- [SLSA.dev specification](https://slsa.dev/spec/v1.0/)
- [CISA — Securing Software Supply Chains (2024 guidance PDF)](https://www.cisa.gov/sites/default/files/2024-10/ESF%20Securing%20Software%20Supply%20Chains%20Recommended%20Practices%202024-10-09.pdf)
- [Google — Introducing SLSA](https://security.googleblog.com/2021/06/introducing-slsa-software-supply-chain.html)
