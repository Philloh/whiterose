---
title: "Sediment — Corrupt Database Recovery"
date: 2026-10-05 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, database, crc, binary-analysis]
pin: false
---

# SEDIMENT.TXT - rocks.db recovery notes

## FLAG
    r00t{s3d1m3nt_72c3793ec24273f994ad921f}

Confirmed by running the supplied `check` binary on it: it prints CORRECT.
The supplied `validator` binary prints INCORRECT for it (see "Decoy" below).


## 1. The Traps In The Provided Material
db_schema.txt and page_reader.py describe a method that does not produce the
right answer. page_reader.py even labels its own offsets "TRAP" and its
repair "wrong". Running it as-is follows the wrong chain and repairs with only
one sibling. Three things in the schema are false:

  a) "Follow next_id at offset 5."
     Offset 5 is a decoy chain. Starting at page 0 it goes
     0 -> 1 -> 2 -> 3 -> 20 -> 21 -> END. Page 3 jumps to the decoy pages 20
     and 21 and skips everything else.
     The real link is the "reserved" field at offset 9:
     0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> END.
     Page 3's offset-5 value is 20 but its offset-9 value is 4. Everywhere else
     the two fields agree, which is why the decoy is easy to miss.

  b) "There is only ONE sibling per page, at offset 7. Ignore offset 9."
     There is a second sibling, a uint16 at offset 11 (the "padding").
     Pages with a good checksum just point both siblings at the decoy pages
     20 and 21, which is why they look like filler.

  c) "Repair = stored XOR sibling.data_byte."
     Repair needs BOTH siblings:
         correct = stored ^ sib1.data ^ sib2.data


## 2. Method
  - rocks.db: 14 pages of 512 bytes. They are stored in shuffled file order,
    so I keyed pages by the page_id in their first two bytes.
  - Checksum: CRC16 (poly 0xA001, init 0xFFFF) over [pid_lo, pid_hi, data].
    Five chain pages fail it: 1, 4, 5, 7 and 11. Pages 20 and 21 pass.
  - For each bad page I first found the byte that satisfies the stored CRC
    (only one of 256 values does). That gives ground truth independent of any
    XOR rule. Then I checked the two-sibling rule against it.

  Page  stored  sib1(off 7) sib2(off 11)   stored^sib1^sib2  CRC-valid byte
  ----  ------  ----------- ------------   ----------------  --------------
   1    0x4c    p9  = 0x7f  p20 = 0x5f     0x6c              0x6c
   4    0x94    p6  = 0x1f  p20 = 0x5f     0xd4              0xd4
   5    0x5d    p0  = 0x48  p3  = 0x96     0x83              0x83
   7    0x61    p10 = 0x6d  p8  = 0x9b     0x97              0x97
  11    0x3d    p2  = 0x04  p10 = 0x6d     0x54              0x54

  All five repairs match, so the two-sibling XOR rule is right.

  Pages 0,2,3,6,8,9,10 pass their checksum unchanged.


## 3. Recovered Bytes
Chain 0..11 (via offset 9):

    48 6c 04 96 d4 83 1f 97 9b 7f 6d 54

    sha256(those 12 bytes) = 72c3793ec24273f994ad921f8b58f57d...

The page_reader.py output formula takes the first 24 hex digits of the sha256:

    r00t{s3d1m3nt_72c3793ec24273f994ad921f}


## 4. Cross-Check With The Binaries
`check` and `validator` are near-identical programs: each builds an expected
string by XORing a rodata blob with 0x5c, then strcmp()s it against stdin.
(The first character is loaded as an immediate, so it is easy to read the
decoded string with a duplicated leading "r" if you are not careful. The
real string is one "r".)

  check     expects  r00t{s3d1m3nt_72c3793ec24273f994ad921f}
  validator expects  r00t{s3d1m3nt_wr0ng_0rd3r_00000000}   <- decoy

The check string matches the hash I computed independently from the database,
so the reconstruction is confirmed from two directions (CRC ground truth +
hash match), and then by running the binary (CORRECT).


## 5. What I Did Not Use
  - index_map.bin (14 records of four uint16: page, a repeating 7/10/1/4
    value, (page+5) mod 14, 0). Not needed: the offset-9 chain and the hash
    match already pin down the answer.
  - The `sediment` binary (reads a file and writes output). I did not
    analyse it or run it, so I can't say what it does.
  - The nonzero bytes after offset 13 in each page. They look like random
    padding.
