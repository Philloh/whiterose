---
title: "Passkeys and WebAuthn: Phishing-Resistant Authentication in Practice"
date: 2026-04-05 16:15:00 +0300
categories: [Security Research]
tags: [webauthn, passkeys, fido2, authentication]
pin: false
---

## Summary

Password phishing remains a dominant initial-access vector in [Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) incident data year after year. **Web Authentication (WebAuthn)**—standardized by the **W3C** and aligned with **FIDO2**—binds login ceremonies to **origin** and **cryptographic key pairs** stored in secure hardware or platform authenticators. Major platforms (Apple, Google, Microsoft) market consumer deployments as **passkeys**. This article explains the security properties documented in the standards—not vendor marketing claims.

## How WebAuthn differs from passwords + TOTP

| Property | Password (+ OTP) | WebAuthn / passkey |
| -------- | ------------------ | ------------------ |
| Phishing | User can type secret on fake site | Browser/authenticator checks **rpId** (relying party ID) against current origin |
| Replay | Stolen password works until rotation | Assertions are **challenge–response** per session |
| Server breach | Often stores password hashes | Server stores **public key** only |
| UX | Typing + second factor | Platform prompts (biometric/PIN) |

The **[WebAuthn Level 2 spec](https://www.w3.org/TR/webauthn-2/)** defines ceremonies:

1. **Registration** — client generates key pair; attestation may prove authenticator model.
2. **Authentication** — client signs server challenge with private key; server verifies with stored public key.

## Authenticator types

- **Platform authenticators** — Touch ID, Windows Hello, Android credential store.
- **Roaming authenticators** — hardware security keys (YubiKey, etc.) via USB/NFC.

**Passkey sync** (iCloud Keychain, Google Password Manager) improves recovery but shifts trust to the sync provider's encryption architecture—documented in each vendor's security whitepapers.

## Deployment considerations (FIDO Alliance + NIST)

The [FIDO Alliance](https://fidoalliance.org/passkeys/) publishes deployment guides emphasizing:

- **Account recovery** flows (lost device) must not re-introduce phishable factors as the only backup.
- **Cross-device** authentication (QR + Bluetooth hybrid) has its own UX and threat considerations per [CA/B Forum](https://cabforum.org/) adjacent identity work and vendor docs.

[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) (Digital Identity Guidelines) classifies authenticator assurance levels (AAL). WebAuthn hardware keys typically support **AAL2/AAL3** when combined with proper verifier policy.

## Limitations (factual)

WebAuthn **does not**:

- Stop **session hijacking** after login (still need secure cookies, CSP, device binding).
- Prevent **real-time proxy** attacks if users approve prompts on the wrong origin due to UX confusion (rare but studied in FIDO research papers).
- Replace **authorization** — authenticated users may still be over-privileged.

## References

- [W3C WebAuthn Level 2 Recommendation](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance — Passkeys](https://fidoalliance.org/passkeys/)
- [MDN — Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
