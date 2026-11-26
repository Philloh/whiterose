---
title: "Quickline — CTR Mode Nonce Reuse"
date: 2026-10-02 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [crypto, ctr-mode, nonce-reuse, crib-dragging]
pin: false
---


## Challenge
A logistics company's "lightweight encrypted memo" tool. Four intercepted memos
(memos.json) need review. Find the flag.

Flag: r00t{ctr_m0d3_n33ds_4_fr3sh_n0nc3}


## 1. Look at the data
memos.json is a list of four objects: ref, ciphertext_hex, length.
  SHIP-2291  299 bytes
  INV-0447   231 bytes
  SCHED-118  199 bytes
  ACCESS-09  165 bytes
The hex lengths match the "length" field exactly, so the cipher is length-
preserving: a stream cipher / XOR with a keystream (no padding, no IV/tag
prefix visible in the ciphertext).


## 2. Spot the weakness: keystream reuse
XORing two ciphertexts cancels the keystream and leaves plaintext1 XOR
plaintext2. XORing pairs of memos gave output dominated by printable letters
and punctuation rather than random bytes (e.g. letters appearing wherever one
plaintext has a space). That only happens if all four messages were encrypted
with the SAME keystream - a "two-time pad" (a CTR/stream mode with a fixed,
reused nonce). The flag text itself points at this: "ctr_m0d3 needs a fresh
nonce".


## 3. Crib dragging
A crib is a guessed plaintext fragment. For a guess g at offset o in memo i,
the keystream bytes there are C_i[o..] XOR g, and applying them to the other
three memos at the same offset shows whether the guess is right (the others
must decode to readable text).
Tried common words (" the ", " and ", "shipment", "schedule", ...) at every
offset of every memo and kept those where all other memos decoded to printable
text. "shipment" at offset 8 of memo 0 gave readable fragments in the others:
  memo1: "y reconc"   memo2: "chedule "   memo3: ": the wa"
Extending word by word (each recovered word in one memo yields keystream that
reveals more of the other three) rebuilt the start of each memo:
  memo0: "...shipment SHIP-2291 delayed ..."
  memo1: "...y reconciliation for bay 4 ..."
  memo2: "...chedule change for next week: ..."
  memo3: "...: the warehouse override code ..."


## 4. Automating the rest (beam search)
Typing every guess by hand was slow, so a beam search was written:
  - for each byte position, only keep keystream byte values for which every
    memo that reaches that position decodes to printable ASCII
  - score candidates with a 4-gram English character model trained on plain
    English text found on the machine, summed over all memos
  - keep the best 400 partial keys per position and fix the early positions
    already confirmed by cribs.
This produced mostly readable plaintext with a few garbled stretches, which
were then corrected by hand with confident guesses (crib on the garbled
spots): "customs paperwork", "Revised ETA is now Thursday", "misfiled under",
"Monday through Wednesday, Otieno takes ...".
Note: memo0 (299 bytes) is the only one longer than 231 bytes, so its last
~70 bytes have no second message to cross-check and could not be recovered
this way; the flag sits at positions 72-106 of the shortest memo, where all
four messages overlap, so this does not affect the answer.


## 5. Flag recovery
Memo 3 (ACCESS-09) decoded to the sentence ending:
  "... the warehouse override code for the night shift this cycle is
   r00t{ctr_m0d3_n33ds_4_fr3sh_n0nc3} ... outside the ops group, rotates
   next month."
(The few characters right after the flag were only partly recovered, so they
are left as "...".)
The key bytes under the flag were checked against the other three memos at the
same positions; with the flag letters in place they decode to sensible words
("Thursday", "under", "Otieno takes") rather than noise, confirming the key.


## 6. Decoded excerpts (positions 60-110, all four aligned)
  0: o customs paperwork. Revised ETA is now Thursday ...
  1: 3 pallets resolved -- found misfiled under bay ...
  2: ern route Monday through Wednesday, Otieno takes ...
  3: is cycle is r00t{ctr_m0d3_n33ds_4_fr3sh_n0nc3} ...


## 7. Takeaway
Never reuse a nonce/keystream with a stream cipher or CTR mode. Reuse lets an
attacker XOR ciphertexts and recover plaintext without ever knowing the key.
