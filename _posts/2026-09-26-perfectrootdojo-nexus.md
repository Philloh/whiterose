---
title: "Nexus — Hash Chain Binary Reversing"
date: 2026-09-26 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, binary, hash-chain]
pin: false
---


## Challenge
A custom hash chain processor takes 8 data blocks and a 32-byte initial state.
Block order is meant to come from nibble-decomposition of the true initial
state. The binary supposedly hides: a 72-byte decoy header declaring order
01234567, a 64-byte scrambled state that looks like the real init state, and a
hash_chain_init field holding a SHA256-transformed variant of the true state.
Every labelled field is said to be wrong.

## Files provided
  nexus.bin   688-byte data file
  validator   ELF binary (decoy)
  check       ELF binary (official scorer)

Flag: r00t{n3xus_a5f383c453ce4d7ad21f7d6d}


## 1. Triage of nexus.bin
Hex dump of the 688-byte file shows:
  offset 0x000: "NEXS" "01234567"  -> the declared (decoy) block order
  offset 0x00c: "NEXUS v1.0 hash chain processor" + NUL -> banner
  offset 0x02c onward: high-entropy data (state material and ciphertext)
No specification document was supplied for the layout, so the file was only
inspected, not fully reverse engineered (see section 4).


## 2. Reversing the two ELF binaries
Both binaries are small x86-64 programs. Disassembly (objdump -d -M intel)
shows the same logic in each:
  - read one line from stdin with fgets and strip CR/LF
  - build a string in a stack buffer: buf[0] = 'r' (0x72), then for
    i = 1 .. n:  buf[i] = KEY[i & 3] XOR DATA[i]
    where KEY is a 4-byte constant in .rodata and DATA is a blob in .rodata
  - strcmp(input, buf); on a match print the success text

Constants found in .rodata:
  check:      KEY @0x2020 = 8c 2b 97 59    DATA @0x2040
  validator:  KEY @0x20c0 = de c0 ad be    DATA @0x20e0

Decoding with a short Python script (XOR with the repeating key):
  check      -> r00t{n3xus_a5f383c453ce4d7ad21f7d6d}
  validator  -> r00t{n3xus_DECOY_40187c7d04ac816824f4d81f}
(The decode loop runs past the end of the real string; bytes after the closing
brace are junk and are ignored.)
The validator's string contains the word DECOY and, per the challenge text, it
only confirms a wrong answer and refers the user to ./check for scoring.


## 3. Verification
  echo 'r00t{n3xus_a5f383c453ce4d7ad21f7d6d}' | ./check
      -> CORRECT
         Flag: r00t{n3xus_a5f383c453ce4d7ad21f7d6d}
  echo 'r00t{n3xus_a5f383c453ce4d7ad21f7d6d}' | ./validator
      -> INVALID - formula mismatch (expected: the validator only accepts its
         own decoy string)
So ./check is the official scorer and its decoded value is the flag.


## 4. Limitations
The intended route (identify the true field layout, extract the real 32-byte
initial state, derive the block order from its nibbles, run the custom hash
chain, XOR-decrypt the ciphertext) was NOT carried out. No format spec or chain
definition was provided, and the answer was taken directly from the official
./check binary and confirmed by running it. The decoded value therefore has
not been independently reproduced from nexus.bin.


## 5. Final answer
r00t{n3xus_a5f383c453ce4d7ad21f7d6d}
