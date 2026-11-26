---
title: "Deadbolt — ECDSA Nonce Reuse Attack"
date: 2026-09-08 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [crypto, ecdsa, nonce-reuse, secp256k1]
pin: false
---


## Challenge
A vault's locking mechanism authorizes release only against a signed
command. Two signed commands (deadbolt.json) were intercepted, both
signed with the same secp256k1 key. A checker script (checker.py)
verifies a candidate private key against the known public key and,
if correct, decrypts and prints a flag.

## Vulnerability
Both signatures in deadbolt.json share the exact same `r` value:

    r1 = 81068046878512155195417425815628850251053346547441462714808971338416069090423
    r2 = 81068046878512155195417425815628850251053346547441462714808971338416069090423

In ECDSA, r = (k * G).x mod n, where k is the per-signature random
nonce. An identical r across two signatures from the same key means
the same nonce k was reused for both signatures — a critical signing
flaw. Nonce reuse lets you solve for the private key directly.

## MATH
For each signature:
    s1 = k^-1 * (z1 + r * d) mod n
    s2 = k^-1 * (z2 + r * d) mod n

where z1, z2 are the (truncated) SHA-256 hashes of the two signed
messages, d is the private key, and n is the curve order.

Subtracting the two equations eliminates d:
    s1 - s2 = k^-1 * (z1 - z2) mod n
    k = (z1 - z2) * (s1 - s2)^-1 mod n

Once k is known, recover d from either equation:
    d = (s1 * k - z1) * r^-1 mod n

## Solve Script
    python3 - << 'EOF'
    import hashlib

    n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    msg1 = b"RELEASE-MANIFEST-2026-10-01: build 4471, approved for production rollout"
    msg2 = b"RELEASE-MANIFEST-2026-10-02: build 4472, hotfix for build 4471, approved"
    r  = 81068046878512155195417425815628850251053346547441462714808971338416069090423
    s1 = 3840508737756347497406687710396332359740879825496539163063209443880034111304
    s2 = 113503929155425957381462365769873416436477654667784827574471421629337517804939

    z1 = int.from_bytes(hashlib.sha256(msg1).digest(), 'big') % n
    z2 = int.from_bytes(hashlib.sha256(msg2).digest(), 'big') % n

    k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    print("k =", k)
    print("private key d =", d)
    EOF

## RESULTS
    k = 53130520420695175011684301494509184563431309515956049368739538313527684948405
    d = 2656466760151853485113498278724311908926037894305005865198209398276174907706

## Verification
    python3 checker.py 2656466760151853485113498278724311908926037894305005865198209398276174907706

Output:
    Key verified.
    r00t{n0nc3_reu5e_l34k5_th3_pr1v4t3_k3y}

## FLAG
    r00t{n0nc3_reu5e_l34k5_th3_pr1v4t3_k3y}

## Takeaway
Never reuse (or predict) the ECDSA nonce k. A single reused k across
two signatures from the same key is enough to fully recover the
private key with basic modular arithmetic — no brute force needed.
This is the same class of bug behind real-world incidents such as
the 2010 Sony PS3 signing-key leak.
