---
title: "Fianchetto — Wiener's Attack on RSA"
date: 2026-09-14 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [crypto, rsa, wiener-attack, continued-fractions]
pin: false
---

# FIANCHETTO.TXT - small private exponent RSA (Wiener's attack)

## FLAG
    r00t{w13n3rs_4tt4ck_br34ks_sm4ll_d}

Verified: encrypting this flag with (N, e) reproduces the given ciphertext c
exactly, and the recovered factors multiply to N.


## 1. The Setup
fianchetto_challenge.json has N, e, c.

  N: 2048 bits
  e: 2045 bits   <- huge, almost as large as N
  c: 2046 bits

The prompt says the key was built with an unusually small private exponent d
"for efficiency". A normal RSA public exponent is small (65537) and d is
large. Here e is huge, which is the sign of the opposite: d was picked first,
small, and e was computed as its inverse mod phi(N). A big e together with a
small d is the exact situation Wiener's attack targets.


## 2. Why It Works
Since e*d = 1 + k*phi(N) for some integer k, we have

    e/N  ~=  k/d       (the error is tiny because phi(N) is close to N)

Wiener (1990) proved that if

    d < (1/3) * N^(1/4)      (with p and q of similar size, q < p < 2q)

then k/d is one of the convergents of the continued fraction of e/N. For a
2048-bit modulus that bound is about 512 bits, so any d below that falls
to the attack.


## 3. The Attack
  1. Expand e/N as a continued fraction.
  2. For each convergent k/d:
       - skip it unless (e*d - 1) is divisible by k;
       - set phi = (e*d - 1) / k;
       - the primes are the roots of x^2 - (N - phi + 1)x + N, so compute
         s = N - phi + 1 and the discriminant s^2 - 4N;
       - accept the convergent if the discriminant is a perfect square r^2
         and p = (s + r)/2, q = (s - r)/2 satisfy p*q = N.
  3. The first convergent that passes recovers everything.

No tools beyond Python's big integers were needed; there is no library
dependency.


## 4. Result
The test passed on a single convergent:

    k = 133135277098716267441401076789225955062015891060
    d = 772939447021895568703677949971438238727760492091   (160 bits)

The private exponent is only 160 bits, far below the ~512-bit Wiener bound.

Factors (both 1024 bits):

    p = 152347720032201232945300405703561050373510602137391821460463322411477
        450457323133518021964488189112705269670836847439929735697994290299910
        071778197743822439942495547365516018651701268861845785401535399298863
        239860624544471599552338532172130635194857543491450501239509211376735
        102397376039058423316462855265797

    q = 141970311295564471373256099041321436038176149146828187122507629494704
        558750806585715612433009909397244692587841863354135252384743993614555
        662281573837119871771240682290531374239143881702983313989806964819693
        265064784481326842670806267968497407603981982868149923000216613728308
        819175018537137426921788953546627

(Wrapped onto several lines here for readability; each is one decimal number.)


## 5. Decryption And Checks
    m = c^d mod N
    m as bytes = r00t{w13n3rs_4tt4ck_br34ks_sm4ll_d}

Checks:
  - p * q == N                                  True
  - e * d == 1 (mod (p-1)(q-1))                 True
  - pow(m, e, N) == c                           True


## 6. Why The Flag Text Fits
"Wiener's attack breaks small d" in leetspeak. Because the plaintext is
unpadded and short, the decryption also came out directly as clean ASCII.


## 7. Fix / Takeaway
Do not pick d for speed. Choose a standard small public exponent such as
65537 (cheap encryption), and let d come out large (about the size of N).
If decryption speed is a concern, use the CRT optimisation with full-size d
instead of shrinking d.
