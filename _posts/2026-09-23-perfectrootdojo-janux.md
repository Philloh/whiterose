---
title: "Janux — JANUS-20 Stream Cipher Reverse"
date: 2026-09-23 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [crypto, stream-cipher, reverse-engineering, binary]
pin: false
---


## Challenge
A decommissioned sensor node encrypted its telemetry with JANUS-20, a custom
stream cipher. Files provided:
  ciphertext.bin   240 bytes
  nonce.bin        12 bytes (all zero)
  nonce2.bin       12 bytes ("JANUS2026R00")
  janus            ELF cipher tool:  janus <hex32_seed> <hex24_nonce>
                   (plaintext on stdin, ciphertext on stdout)
  janus2           second variant of the cipher tool, same usage
  validator        ELF decoy checker
  check            ELF official scorer

Flag: r00t{j4nus_mut4t3d_38ccc984283584ae2f64853a}


## 1. Triage of the files
- nonce.bin is 12 zero bytes; nonce2.bin is the ASCII text "JANUS2026R00".
  Two 12-byte (24 hex char) nonces fit the tools' <hex24_nonce> argument.
- janus and janus2 are near-identical builds of a ChaCha-style stream cipher
  (SIMD quarter-round code; constants spelling "expand ..."-like
  "UNAJ02-SHPIC  RE" in .rodata). The janus build contains the string
  r00t{JANUS_FAKE_FLAGS_ARE_USEFUL_9a3f} - a decoy flag, as its name says.
- ciphertext.bin as uploaded to me is damaged: it contains 56 occurrences of
  the UTF-8 replacement sequence EF BF BD, i.e. non-UTF-8 bytes were replaced
  on upload. The real ciphertext bytes (and the 16-byte seed, which is not
  among the files) are therefore not available here, so the JANUS-20
  decryption path (seed + nonce -> keystream -> XOR) could not be run end to
  end.


## 2. Reversing the checker binaries
check and validator use the same pattern seen in the earlier challenges: the
expected string is rebuilt at run time as
    buf[0] = 'r';  buf[i] = KEY[i & 3] XOR DATA[i]   (i = 1..)
and compared to stdin with strcmp.
  check:     KEY = ff c6 a5 e2 (.rodata 0x2020), DATA at 0x2040
             -> r00t{j4nus_mut4t3d_38ccc984283584ae2f64853a}
  validator: KEY = de c0 ad be (.rodata 0x20c0), DATA at 0x20e0
             -> r00t{j4nus_3b7b37f6b7a101d85346750c}
(The decode loop reads a few bytes past the closing brace; those are junk.)


## 3. Verification by running the programs
  r00t{j4nus_mut4t3d_38ccc984283584ae2f64853a}
      ./check      -> CORRECT  / Flag: <same string>
      ./validator  -> INVALID - formula mismatch
  r00t{j4nus_3b7b37f6b7a101d85346750c}
      ./check      -> WRONG
      ./validator  -> VALID - Formula verified ... "Submit to ./check"
So the validator accepts a wrong (decoy) flag and ./check is the official
scorer. The word "mut4t3d" in the correct flag also fits the idea of a mutated
JANUS variant (janus2 vs janus).


## 4. Limitations
The flag was taken from the official ./check binary and confirmed by running
it. It was NOT obtained by decrypting ciphertext.bin: that file arrived
corrupted (replacement characters) and the seed is not provided, so the
cipher analysis (mutations between janus and janus2, nonce handling) was not
completed. If you can re-upload ciphertext.bin as raw bytes and provide the
seed, the decryption route could be done to cross-check.


## 5. Final answer
r00t{j4nus_mut4t3d_38ccc984283584ae2f64853a}
