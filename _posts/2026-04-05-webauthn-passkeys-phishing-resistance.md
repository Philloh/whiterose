---
title: "WebAuthn Passkeys: What FIDO2 Actually Guarantees Against Phishing"
date: 2026-04-05 11:15:00 +0300
categories: [Security Research]
tags: [webauthn, fido2, passkeys, authentication]
pin: false
---

## Summary

**Passkeys** are user-facing credentials built on **WebAuthn** ([W3C Recommendation](https://www.w3.org/TR/webauthn/)) and **FIDO2** standards published by the [FIDO Alliance](https://fidoalliance.org/fido2/). Unlike password-only login, WebAuthn binds authentication to a **relying party ID (rpId)**—typically the registrable domain (e.g., `example.com`). This article explains the **cryptographic origin binding** that drives phishing resistance, and where deployments still fail.

## Ceremony recap

**Registration**

1. Server sends `PublicKeyCredentialCreationOptions` with `rp.id`.
2. Authenticator generates a key pair, returns attestation (optional) + public key.
3. Server stores public key credential ID.

**Authentication**

1. Server sends challenge + allowed credential IDs.
2. Authenticator signs `{authenticatorData, clientDataJSON}` where `clientDataJSON.origin` reflects the browser origin.
3. Server verifies signature, challenge freshness, and **`rpIdHash`** inside `authenticatorData`.

Because the authenticator will not sign for **`evil.com`** when the credential was registered for **`bank.com`**, classic **credential phishing pages** cannot complete the ceremony—even if the user is tricked into clicking approve on a rogue site (unless the attacker also controls a valid origin or the user registers on the wrong site).

## Synced vs device-bound passkeys

| Type | Behavior | Trade-off |
| ---- | -------- | --------- |
| **Platform passkey** (iCloud Keychain, Google Password Manager) | Syncs across user's devices | Convenience; trust shifts to platform vendor |
| **Roaming authenticator** (YubiKey) | Device-bound | Strongest possession factor; loss recovery harder |

Apple, Google, and Microsoft adopted passkeys per [FIDO multi-device credential guidance](https://fidoalliance.org/apple-google-and-microsoft-commit-to-expanded-support-for-fido-standard-to-accelerate-availability-of-passwordless-sign-ins/).

## Limits and real-world bypass classes

WebAuthn **does not** stop:

- **Session hijacking** after login (cookie theft, malware on device).
- **Real-time proxy phishing** that forwards WebAuthn to the legitimate site in specialized attacks (research topic; not equivalent to static password phishing).
- **Account recovery** flows that fall back to SMS or knowledge questions.
- **Misconfigured `rpId`** (overly broad parent domain, typosquat on sibling subdomain).

NIST **SP 800-63B** ([Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)) discusses authenticator assurance levels; passkeys typically map to **multi-factor** when combined with device possession.

## Deployment checklist

- Enforce **HTTPS** everywhere; WebAuthn requires secure contexts.
- Pin **`rpId`** to production domain; avoid cross-environment reuse.
- Provide **phishing-resistant recovery** (second device, admin break-glass).
- Log **`signCount`** (clone detection) when authenticators increment signature counters.

## References

- [W3C Web Authentication Level 2](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance — FIDO2 specifications](https://fidoalliance.org/specifications/)
- [Google Security Blog — passkeys overview](https://security.googleblog.com/2022/05/Seamless-security-with-passkeys.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
