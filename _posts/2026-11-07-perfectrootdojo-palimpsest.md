---
title: "Palimpsest — Layered Document Format Reversing"
date: 2026-11-07 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, reverse-engineering, binary, xor]
pin: false
---

# Palimpsest: write-up

**Flag:** `r00t{p4l1mp535t_65222ca0faf7ae73354bb43f}`

## Files given

| File | What it is |
|---|---|
| `manuscript.pls` | 567-byte "PLMS v2" layered document (the data) |
| `revision_log.txt`, `revision_metadata.txt` | notes describing how to decode it |
| `layer_extractor.py` | script implementing the notes |
| `palimpsest` | ELF verifier: takes the manuscript as `argv[1]`, expected plaintext on stdin |
| `check`, `validator` | two ELF programs that each read a line from stdin and report whether it is the flag |

## 1. The documentation is a trap

Following the notes does not work:

- `revision_log.txt` says the xref table at offset 20 is `[0,1,2,3,4,5,6]` and that the 4-byte `reserved` field at offset 9 is
  "write-time bookkeeping that readers must ignore". Following it (`layer_extractor.py`) XORs all 7 layers
  and gives `6915dad1ed5c20dbed324abe821f4cbfd9ae3a6d`, which is not text.
- `revision_metadata.txt` says each layer is first unmasked with a key from `SHA256(str(i))[:4]`.
  Doing that gives `84f2386000bbc26a...`, also not text.

Neither document tells you what the answer is, so I checked what the verifier binary actually does.

## 2. The file format

Parsing `manuscript.pls`:

```
PLMS | n=7 | xref_offset=20 | reserved=0x230 (560) | version=2 | flags=0 | xref@20: 00 01 02 03 04 05 06
then 7 layers, each: uint16 length (=20) + 20 bytes
then zero padding up to offset 560, where the last 7 bytes are:  01 05 04 00 02 06 03
```

The "ignored" `reserved` field is 560, which is the file offset of a **second, hidden xref table**
`[1,5,4,0,2,6,3]` at the very end of the file.

## 3. What `palimpsest` really does (disassembly)

1. Reads the 27-byte header and checks the `PLMS` magic.
2. Reads the layers (each must be 20 bytes).
3. Computes CRC-32 of **layer 0** and requires `reserved == (crc32(layer0) & 0x1ff) + 0x100`.
   I confirmed this for the sample: `crc32(layer0)` is `0x140eb330`, which gives 560. So `reserved` is a checksummed pointer, not bookkeeping.
4. Seeks to `reserved`, reads 7 bytes (the real order), and XORs the layers in that order.
5. Reads 20 bytes from stdin and compares them with the result (exit code 0 means they match).

Because XOR is commutative, any permutation gives the same bytes, so the plaintext is the XOR of all seven layers:

```
6915dad1ed5c20dbed324abe821f4cbfd9ae3a6d      (20 bytes)
```

Piping those bytes into `./palimpsest manuscript.pls` exits with 0. Twenty `A`s exit with 1.

## 4. From the plaintext to the flag

The 20 bytes are not readable text. They are the secret that the flag is built from. `check` and `validator` are the
same small program with different embedded data. Each decodes a string from `.rodata` by XOR with `0x5c`, reads a line,
and compares it with `strcmp`:

| Program | Decoded string | Output on its own string |
|---|---|---|
| `check` | `r00t{p4l1mp535t_65222ca0faf7ae73354bb43f}` | `CORRECT` |
| `validator` | `r00t{p4l1mp535t_wr0ng_0rd3r_l4y3r5_00xx}` | `VALID` |

Two different flags, so one is a decoy. The tail of the first one is not arbitrary:

```
sha256(6915dad1ed5c20dbed324abe821f4cbfd9ae3a6d)[:12 bytes] = 65222ca0faf7ae73354bb43f
```

That means the flag derives from the recovered manuscript plaintext
(`r00t{p4l1mp535t_` + first 24 hex chars of `SHA-256(plaintext)` + `}`), which independently confirms the flag in `check`.
The `validator` string (`wr0ng_0rd3r_l4y3r5`, "wrong order layers") has no such tie to the manuscript. It
is the answer you would be steered toward by a wrong decoding, and the `validator` binary rejects the real flag with
`INVALID -- formula mismatch`.

## Reproduce

```python
import struct, hashlib
from functools import reduce
d = open('manuscript.pls','rb').read()
off, L = 27, []
for _ in range(d[4]):
    n = struct.unpack_from('<H', d, off)[0]; off += 2
    L.append(d[off:off+n]); off += n
plain = bytes(reduce(lambda a, b: a ^ b, col) for col in zip(*L))
print(plain.hex())                                   # 6915dad1ed5c20dbed324abe821f4cbfd9ae3a6d
print('r00t{p4l1mp535t_%s}' % hashlib.sha256(plain).hexdigest()[:24])
```

Output: `r00t{p4l1mp535t_65222ca0faf7ae73354bb43f}`

## Takeaways

- The "reserved, ignore it" field was the real pointer; the documented xref was the decoy. (Order does not change a pure XOR, so the order itself does not matter.)
- The 20-byte plaintext is only an intermediate value; the flag comes from hashing it.
- A "VALID" from `validator` did not mean the answer was right. The flag was cross-checked against the manuscript and the verifier.
