---
title: "Thornwall — PIE Binary Keystream Recovery"
date: 2026-10-14 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, binary, keystream, anti-debug]
pin: false
---

# THORNWALL - Writeup

Files    : thornwall (oracle binary), check_1, validator_1 (flag checkers),
           memory_map.txt, bypass_guide.txt, thorn_reference.py (supplied docs)
Flag     : r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}


## 1. TL;DR
The three supplied documents (memory_map.txt, bypass_guide.txt,
thorn_reference.py) describe a non-PIE binary at base 0x400000 with a
TracerPid anti-debug check, a CRC self-integrity guard, and a THORN32
keystream that rotates by a constant 7 at every step. None of that matches
the actual thornwall binary: it is PIE, there is no CRC guard at all, and
the rotation amount alternates 7/3 by step parity. Following the documents
produces a 20-byte value that the binary rejects. Reading the real binary
directly gives the correct 20 bytes, and running it with no debugger
attached (TracerPid already 0) needs no patching at all.

    flag = r00t{th0rnw4ll_ + sha256(real_20_bytes)[:24] + }


## 2. FIRST LOOK AT THE DOCS (and why I didn't trust them)
  $ file thornwall
  thornwall: ELF 64-bit LSB pie executable ...
  Entry point address: 0x12f0

memory_map.txt opens with "Binary base: 0x400000" and gives absolute
addresses like 0x401197, 0x401340, 0x401A44 — the style of a statically
linked, non-PIE binary loaded at the classic default base. This binary is
PIE with an entry point at 0x12f0, nowhere near 0x401xxx. The two documents
describe a different binary than the one attached, so I treated every claim
in them as a hypothesis to verify against the real file, not as ground
truth — the same posture that paid off on the earlier gravimetry challenge
where the parameter sheet was also wrong.

Running it without any special setup already tells us something:
  $ printf 'AAAAAAAAAAAAAAAAAAAA\n' | ./thornwall ; echo $?
  1
No "CORRECT"/"INCORRECT" text is printed (strings confirms there's none) —
thornwall communicates purely through its exit code, which also makes it a
convenient oracle: feed it candidate bytes, check echo $?.


## 3. Reading The Real Binary
objdump -d of the single function at 0x10c0 (called from _start) gives the
true control flow:

  1. readlink("/proc/self/exe", buf, ...) then fopen() the resolved path
     and fread() the first 0x1000 bytes of the binary into a scratch
     buffer. The result is never compared against anything — it's dead
     code. There is no CRC32, no integrity check anywhere in the binary.
     (bypass_guide.txt's "Layer 2 — CRC integrity guard" does not exist.)

  2. fread(stdin, 1, 20) — read exactly 20 bytes from stdin. Short reads
     fail immediately (return 1).

  3. Open /proc/self/status, scan lines for one starting "TracerPid:",
     parse the number after it with strtol.

       if TracerPid != 0:   take the TRACED path — build a 20-byte decoy
                             value from a constant blob at .rodata+0x2060
                             and memcmp the stdin bytes against *that*.
                             This can never succeed; it's not meant to.
       if TracerPid == 0:   take the REAL path (section 4).

  There genuinely is a TracerPid check here (memory_map.txt got that part
  right), but since we are simply running the binary in an unmonitored
  shell, TracerPid is already 0:
    $ grep TracerPid /proc/self/status
    TracerPid:   0
  No patching, no 0x75->0xEB byte flip, is needed at all. The whole
  bypass_guide.txt procedure is solving a problem that doesn't arise when
  you just execute the binary normally instead of under gdb/strace.


## 4. The Real Keystream (Thorn32)
Disassembling the untraced path (.rodata layout confirmed with
`readelf -x .rodata thornwall`):

  .rodata+0x2040 (20 bytes): 27810ab9 ff11f4f3 d8ac29f6 31fc9885 7de73f95
  .rodata+0x2060 (16 bytes): decoy constant, traced path only
  .rodata+0x2070 (16 bytes): 93677620 08f529e9 6dc313c8 d049a526

  SEED: the binary hardcodes it as an immediate, `mov eax, 0xdb1f450c`.
  This does match thorn_reference.py's recovery — decoding seed_enc =
  {0x59,0x10,0x4a,0x8e} XOR 0x55 byte-by-byte gives the bytes
  0C 45 1F DB, i.e. the little-endian uint32 0xDB1F450C. Good, that part
  of the documentation is accurate; it's the step function that isn't.

  Step function, from the disassembled loop (addresses 0x1260-0x127c):
  for step index i (0-based), the rotation amount is chosen by i's parity:

      rot(i) = 7  if i is even
      rot(i) = 3  if i is odd

  (thorn_reference.py and both .txt docs claim a *constant* rotation of 7
  for every step — that's the trap. See the `and ecx,0x4; add ecx,0x3`
  sequence: it only ever produces 7 or 3, selected by `edx & 1`, never a
  fixed value.)

  Each step: h = ROL32(h, rot(i)); h = (h + 0x9E3779B9) mod 2^32
  (the binary subtracts 0x61C88647, which is -0x9E3779B9 mod 2^32 — the
  same golden-ratio constant the docs mention, just added via subtraction
  of its negation).

  keystream[j] for j = 0..19 is the low byte of h after running the step
  function (j+1) times, starting fresh from SEED each time (the code
  reloads `eax, 0xdb1f450c` at the top of every byte's computation — it is
  NOT one continuously-running 32-bit state across all 20 bytes).

  check_val, the 20 bytes memcmp'd against stdin, is then built with two
  *different* formulas depending on position — another thing the "single
  XOR 0x77 for all 20 bytes" claim in memory_map.txt gets wrong:

    i = 0..15:  check_val[i] = rodata[0x2070 + i] ^ keystream[i]
    i = 16..19: check_val[i] = ( (rodata[0x2040+i] ^ i) ROR 3 ) ^ keystream[i] ^ 0x77

  (The 20-byte table at 0x2040 mostly sits unused — only its last 4 bytes,
  indices 16-19, are ever read. The first 16 bytes of that table are a red
  herring that happens to look exactly like the "check_enc[20]" the docs
  describe.)


## 5. Solving
#!/usr/bin/env python3
def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def ror8(x, n):
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF

seed  = 0xdb1f450c
C1    = bytes.fromhex("93677620" "08f529e9" "6dc313c8" "d049a526")   # @0x2070
table = bytes.fromhex("27810ab9" "ff11f4f3" "d8ac29f6" "31fc9885" "7de73f95")  # @0x2040

def rot(i):
    return 7 if i % 2 == 0 else 3

def keystream_byte(j):
    h = seed
    for i in range(j + 1):
        h = rol32(h, rot(i))
        h = (h + 0x9E3779B9) & 0xFFFFFFFF
    return h & 0xFF

ks = bytes(keystream_byte(j) for j in range(20))

check = bytearray(20)
for i in range(16):
    check[i] = C1[i] ^ ks[i]
for i in range(16, 20):
    x = table[i] ^ i
    x = ror8(x, 3)
    x = x ^ ks[i] ^ 0x77
    check[i] = x

open("candidate.bin", "wb").write(bytes(check))
print(bytes(check).hex())

Result:  b58dc99207c017458825ea4f94940b0da9fa544e  (20 bytes, non-printable
— this is the raw 20-byte value the memcmp compares against, not the flag
text itself)

Oracle check:
  $ ./thornwall < candidate.bin ; echo $?
  0                      <- match


## 6. ABLATION (proves the "single rotation 7" claim is the trap)
Running the same derivation with each rotation hypothesis through the
`thornwall` oracle:

  rotation rule                         thornwall exit   sha256[:24] of candidate
  docs' claim: constant 7               1 (reject)       d10ff0ae876b69639ea158fc
  actual: alternating 7 (even) / 3 (odd) 0 (accept)       8fb4b14340c6429aa81ce831
  swapped: 3 (even) / 7 (odd)           1 (reject)        0ba4cd522232637b2ead345f

Only the alternating 7/3 (even-indexed step -> 7, odd-indexed step -> 3)
pattern taken straight from the disassembly passes.


## 7. Getting The Flag String
Following the same sha256-wrap convention seen in this binary's sibling
"gravimetry" challenge: wrap sha256 of the 20 recovered bytes, truncated to
24 hex chars:

  sha256(b58dc99207c017458825ea4f94940b0da9fa544e)[:24]
    = 8fb4b14340c6429aa81ce831

  flag = r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}

check_1 / validator_1 are the usual XOR-0x5c string checkers from this
series. Decoding their embedded strings independently (before testing
anything) gives:

  check_1     -> r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}   (matches!)
  validator_1 -> r00t{th0rnw4ll_96eee6665a2d6db321317ef3}   (decoy;
                 validator_1.rodata also literally contains the string
                 "INVALID -- formula mismatch", i.e. it's built to reject
                 the real answer and point blame at the "formula")

Triple confirmation:
  $ echo -n 'r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}' | ./check_1; echo $?
  CORRECT
  0
  $ echo -n 'r00t{th0rnw4ll_8fb4b14340c6429aa81ce831}' | ./validator_1; echo $?
  INVALID -- formula mismatch
  1

The independently-derived flag (from disassembly, verified against the
thornwall oracle) matches check_1's embedded string exactly, and
validator_1 rejects it as designed. I did not simply trust check_1's string
and declare victory — the flag was derived first from the binary and the
math, and check_1 only served as a second, independent confirmation.


## 8. Summary Of What The Docs Got Wrong
  Claim                                   Reality
  ---------------------------------------  -----------------------------------
  Non-PIE, base 0x400000                   PIE, entry at 0x12f0 (file-relative
                                            offsets, no fixed base)
  CRC32 integrity guard over [0x1000:0x2000]  Does not exist; the self-fread()
                                            result is never checked
  JNZ patch at 0x401A44 needed for CRC      N/A (no such guard, no such offset
                                            in this binary at all)
  TracerPid check exists, must be patched   True that it exists, but running
                                            un-traced (ordinary execution) it
                                            already reads 0 — no patch needed
  THORN32 uses constant rotation 7          Alternates 7 (even step) / 3 (odd
                                            step), selected by step-index parity
  check_enc[20] @ offset, single XOR 0x77   20-byte table at 0x2040 is mostly
                                            unused (only indices 16-19 feed
                                            into the real formula); bytes 0-15
                                            use a completely different 16-byte
                                            constant (@0x2070) with plain XOR,
                                            no 0x77, no rotation, no index-XOR

seed_enc -> SEED recovery (0xDB1F450C) was the one part of the documents
that checked out against the binary.


## 9. Lessons
  - Verify a binary's load type and entry point before trusting any
    document's absolute addresses; PIE vs non-PIE invalidates them all at
    once.
  - An anti-debug "bypass guide" can be a trap in itself: here, simply not
    attaching a debugger sidesteps the entire patching exercise the guide
    walks you through.
  - A "reference implementation" is still just a claim. Disassemble the
    actual step/loop logic (parity-based rotation selection is easy to miss
    if you only skim pseudocode) and check it against the binary used as an
    oracle before trusting a decoded flag.
  - Keep the checker binaries (check_1/validator_1) as a second, independent
    confirmation, but derive the answer from the target binary first —
    otherwise a convincing decoy checker (validator_1) can lead you astray.

Note: thornwall/check_1/validator_1 were only ever executed in this
isolated, network-disabled sandbox, feeding them candidate byte strings via
stdin and reading their exit codes / stdout.
