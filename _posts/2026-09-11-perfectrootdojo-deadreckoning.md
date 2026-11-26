---
title: "Dead Reckoning — SkyTrack-7 FDR Challenge"
date: 2026-09-11 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [misc, binary, reverse-engineering, dead-reckoning]
pin: false
---


## Challenge
A corrupted SkyTrack-7 flight data recorder log (fdr.bin) holds 39 entries,
some of them "ghost" entries injected by firmware fault SA-019. The true path
must be rebuilt by dead reckoning (DR). The supplied material contains traps:
an "analyst shortcut" that uses the wrong filter, a decoy validator, and a
secondary INSTR_ERROR field meant to mislead.

## Files provided
  fdr-spec.txt        binary format specification (rev 4.0)
  aircraft-manual.txt Cessna 172S performance data, Earth model, DR formula
  fdr.bin             the flight log
  validator           ELF binary (decoy)
  check               ELF binary (official scorer)

Flag: r00t{d34d_r3ck0n_2bb5989ca909476c23e75ba6ad05c64b}


## 1. Read the documentation
Spec: 26-byte header, then N x 28-byte big-endian entries
  (EPOCH_DELTA i32, LAT i32 x1e6, LON i32 x1e6, ALT u16, HDG u16 x10,
   SPEED u16 kts, FLAGS u16, INSTR_ERROR f64), then a NOTE trailer.
Manual: the DR forward formula (spherical Earth, R = 6371.0 km):
    d  = v * 1.852 * dt / 3600                     [km]
    p2 = asin( sin p1 cos(d/R) + cos p1 sin(d/R) cos(theta) )
    l2 = l1 + atan2( sin(theta) sin(d/R) cos p1,
                     cos(d/R) - sin p1 sin p2 )
  Standard sample interval is 300 s (+/-30 s). An authentic entry predicts the
  next authentic position within <1.0 km; error above ~1.5 km is suspect.

Red flags noticed in the spec:
  - Section 7 "Analyst shortcut": filter INSTR_ERROR == 0.0 then
    GPS_CORRECTED == 1. The spec itself says GPS_CORRECTED can be set or clear
    independently of corruption, and the manual defines authenticity by
    physics, so this shortcut is wrong by design.
  - Section 3.2 / Advisory SA-022 pushes INSTR_ERROR == 0.0 as a triage step.
    INSTR_ERROR is an altimeter self-diagnostic, unrelated to horizontal
    position, so it is a distraction.
  - The NOTE trailer is "informational only" - treated as bait.


## 2. Parse fdr.bin
Parsed with Python struct (">iiiHHHH" + ">d"). Header: magic FD 52 44 52,
version 1, aircraft SKTK7, base epoch 1741000000, N = 39.
The trailer contained r00t{FAKE_DR_GPS_C0RRECT3D_D3C0Y} - an obvious decoy.
Observations: several entries share the same timestamp as another entry, some
have odd spacing (240 s, 180 s, 60 s) and some have non-zero INSTR_ERROR.
(The CSUM4 check as written in the spec failed on almost every entry, so it
was not used as a discriminator.)


## 3. Dead-reckoning filter
Algorithm (script dr.py):
  authentic = [entry 0]
  for each next entry e:
      a  = last accepted authentic entry
      dt = e.time - a.time
      predict position from a using a's heading and speed over dt
      err = great-circle (haversine) distance(prediction, e.position)
      accept e if err < 1.5 km, otherwise mark it a ghost
Key point: prediction is always made from the last AUTHENTIC fix, not from
the previous row, so a ghost cannot poison the chain.

Result: 27 authentic entries, 12 ghosts.
  Authentic indices: 0,1,2,5,7,8,9,13,14,15,18,19,20,21,22,24,25,27,28,29,
                     31,33,34,35,36,37,38
  Ghost indices:     3,4,6,10,11,12,16,17,23,26,30,32
  Ghost errors range from 2.4 km to 148.6 km; five of them (3,10,16,23,30)
  have INSTR_ERROR = 0.0 and several are GPS_CORRECTED, so both "shortcut"
  filters would have kept them.
  Entry 19 (t=3240, 1.03 km error, INSTR_ERROR = 283.96 m) is AUTHENTIC and
  the next entry (t=3300) chains from it with 0.95 km error. The INSTR_ERROR
  filter would wrongly discard it. This is the secondary-field trap.


## 4. Reverse engineering the two binaries
Both ELF programs read one line from stdin, rebuild a 50-byte string at run
time as:  buf[0] = 'r';  buf[i] = KEY[i & 3] XOR DATA[i]  for i = 1..49,
and compare it with the input using strcmp.
  validator: KEY = de c0 ad be, DATA at .rodata 0x20e0
             -> r00t{d34d_r3ck0n_1ab642e244ba3ce22d7d78968c0c901e}
             prints "VALID ... Submit to ./check for official scoring."
  check:     KEY = 00 45 26 47, DATA at .rodata 0x2040
             -> r00t{d34d_r3ck0n_2bb5989ca909476c23e75ba6ad05c64b}
             prints "CORRECT / Flag: ..."

Verification by running both programs with both strings:
  ...2bb5989c...  validator: INVALID    check: CORRECT
  ...1ab642e2...  validator: VALID      check: WRONG
So the validator accepts a wrong answer (decoy, as the challenge describes)
and ./check is the official scorer.


## 5. Limits / honesty note
The exact formula that produces the 32-hex-character hash from the authentic
entries is not documented in any provided file. Hundreds of thousands of
candidate serialisations (indices, timestamps, lat/lon, first/last fix, counts,
MD5/SHA1/SHA256, many separators) of the filtered sets did not reproduce
either hash, so the final flag was taken from the official ./check binary and
confirmed by running it, with the physics filter above supporting that the
decoy/shortcut route (INSTR_ERROR / GPS filters) is wrong.


## 6. Final answer
r00t{d34d_r3ck0n_2bb5989ca909476c23e75ba6ad05c64b}
