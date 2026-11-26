---
title: "Sealed Decree — PDF Orphaned Object Analysis"
date: 2026-11-10 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, pdf, steganography, crypto]
pin: false
---

# Sealed Decree: write-up

**Flag:** `r00t{0rph4n3d_0bj3cts_h1d3_1n_pl41n_s1ght}`

## 1. The visible document

`sealed_decree.pdf` is a 2,400-byte, one-page ReportLab PDF with a short "Decree of the Western Holdings".
There are no embedded images, no attachments, no forms, no JavaScript and no encryption.
The text layer and the decoded page content stream match what is printed, with no white or off-page text.

Two details stand out:

- The decree says the copy bears "no further annotation beyond the **reference mark** affixed by the clerk's office".
- The Info dictionary contains `Keywords: Filing ref: QUILL-7734-W`. That is the "reference mark".

## 2. The orphan object

`pdfinfo`, `pdftotext` and `pdfdetach` all follow the cross-reference table, so they never see everything in the file.
Reading the raw bytes shows content **after `%%EOF`** (offset 2253):

```
9999 0 obj
<< /Type /Metadata /Subtype /CommissionSeal /Length 46 >>
stream
... 46 bytes ...
endstream
endobj
```

Object 9999 is not listed in the xref table (which has only 10 entries, 0 to 9), and the trailer's
`/Size` is 10. The object is therefore invisible to normal readers, yet it sits in plain sight in the file.
Its subtype, `CommissionSeal`, is what gives the challenge its name.

## 3. Decoding the 46-byte stream

Raw bytes (hex):

```
0000002a c38579c0c781c7b9b480bf88adab7cb3bf7cafc0c4b4b17db084b47abaabc1c17d7dbab0c87ab3b4c5d2
```

- The first 4 bytes are `00 00 00 2a`: a big-endian length of **42**, which equals the remaining byte count.
- Everything after that is high-valued bytes, which suggests an additive (Vigenère-style byte) cipher rather than XOR.
- Key: **`QUILL`**, the word from the reference mark `QUILL-7734-W`. The full reference string and the other
  metadata strings did not work; only the short word did.

Decryption: `plain[i] = (cipher[i] - key[i % 5]) mod 256` over the 42 bytes after the length header.

```python
b = open('sealed_decree.pdf','rb').read()
i = b.find(b'9999 0 obj'); s = b.find(b'stream\n', i) + 7
blob = b[s:b.find(b'\nendstream', s)]
n = int.from_bytes(blob[:4], 'big')          # 42
ct, key = blob[4:4+n], b'QUILL'
print(bytes((c - key[j % 5]) & 255 for j, c in enumerate(ct)).decode())
```

Output:

```
r00t{0rph4n3d_0bj3cts_h1d3_1n_pl41n_s1ght}
```

The flag text itself explains the trick: an orphaned object hidden in plain sight.

## Method summary

1. Inventory the PDF and find nothing in the usual places.
2. Note the "reference mark" hint and the `Filing ref` in the metadata.
3. Read the raw bytes and spot data after `%%EOF` that isn't in the xref.
4. Treat the length-prefixed blob as a byte-wise additive cipher and use `QUILL` as the key.
