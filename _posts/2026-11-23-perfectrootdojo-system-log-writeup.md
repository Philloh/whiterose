---
title: "System Log — Multi-Layer Audio/PNG/AES Stego"
date: 2026-11-23 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, steganography, audio, png, aes-gcm]
pin: false
---

# Decommissioned Server Log – Write-up

**Challenge:** *A decommissioned server's last system log was pulled before the disk was wiped. Whatever was on that machine, it isn't in the log text itself.*
**File:** `system.log` (40,892 lines, 3.8 MB)
**Flag:** `r00t{thr33_l4y3rs_n0_sh0rtcuts}`

The flag was recovered by a full end-to-end run of `solve.py` (below). The final step is AES-GCM, so the authentication tag also confirms it.

## Layer 0 – the log

About 24,500 lines are filler (`heartbeat ok`, `queue depth N`, `disk usage at N%`, ...) with random levels and numbers. They carry nothing, and I checked levels, values and timestamp gaps for a covert channel.

The other 16,357 lines have the form `seq=N stream=X chunk=<base32>`:

- **Stream A** has 16,356 chunks, `seq` 0–16355, shuffled in file order. Each is 120 base32 characters (75 bytes), and the last is shorter.
- **Stream B** has one chunk (`seq=0`) holding 32 bytes: `73ef0218b2241c235b764c0afc34461a69bef022f1ca071ea87c80266c74471b`.

Sorting stream A by `seq` and base32-decoding gives 1,226,632 bytes: a valid **RIFF/WAVE file** (16-bit mono, 44.1 kHz, 13.9 s). Stream B looks like a key.

## Layer 1 – the audio

Spectrally the WAV is Gaussian noise (autocorrelation 1, .8, .6, .4, .2, 0 means white noise through a 5-tap moving average). The only visible structure is three tones at 3101, 3445 and 3790 Hz, which are exactly bins 9, 10 and 11 of a 128-point DFT (fs/128 = 344.53 Hz spacing).

Taking a 128-sample DFT of every block shows that in **every block** the DFT values at bins 9, 10 and 11 are almost purely imaginary (99% of the energy), while all other bins are ordinary noise. The three bins carry the same sign nearly every block (98.4% agree). So the audio is a **BPSK-style carrier with a 3x repetition code**, with one bit per 128-sample block:

```
bit = majority(sign(Im F[9]), sign(Im F[10]), sign(Im F[11]))
```

4,688 blocks give 586 bytes: a 4-byte big-endian length (`00 00 02 46` = 582) followed by a valid **PNG** (`89 50 4E 47 ...`, all chunk CRCs good). The remaining blocks (~4688+) are only leftover noise padding.

## Layer 2 – the PNG

The PNG is 20x20 RGB and almost flat blue-grey (R 84–94, G 104–115, B 124–135), with an unusually large IDAT for its size. That is LSB steganography. Reading the least significant bit of each channel in row-major, R,G,B order, packed MSB-first, gives 150 bytes:

```
00 00 00 3b | ce d1 e7 82 64 e7 b0 5f ...
```

That is a 4-byte length (59) followed by 59 bytes of high-entropy data.

## Layer 3 – the ciphertext

59 bytes = 12-byte nonce + 31-byte ciphertext + 16-byte tag, which is the layout of AES-GCM. Stream B (32 bytes) is the AES-256 key:

```python
AESGCM(B).decrypt(ct[:12], ct[12:], None)  ->  b'r00t{thr33_l4y3rs_n0_sh0rtcuts}'
```

GCM authentication passed, so the key, layout and plaintext are right. Every other mode I tried (XOR, ChaCha20-Poly1305, AES-CTR/CFB/OFB, ECB) gave garbage.

## Flag

```
r00t{thr33_l4y3rs_n0_sh0rtcuts}
```

(Three layers: audio, then image, then ciphertext, which matches the flag text.)

## Solve script

```python
#!/usr/bin/env python3
"""Solve: decommissioned-server system.log -> flag.  usage: python3 solve.py system.log"""
import re, sys, base64, struct, wave, io
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Layer 1: base32 chunks in the log (stream A = WAV, stream B = 32-byte key)
A, B = {}, None
for line in open(sys.argv[1]):
    m = re.search(r'seq=(\d+) stream=(\w) chunk=(\S+)', line)
    if not m: continue
    seq, st, c = int(m[1]), m[2], m[3]
    c += '=' * (-len(c) % 8)
    if st == 'A': A[seq] = base64.b32decode(c)
    else:         B = base64.b32decode(c)
wav = b''.join(A[i] for i in range(len(A)))
assert wav[:4] == b'RIFF' and len(B) == 32

# 2. Layer 2: audio. Per 128-sample block, bins 9,10,11 of the DFT are purely
#    imaginary; their sign (majority of the 3) is one bit -> 1 bit / block.
x = np.frombuffer(wav[44:], dtype='<i2').astype(float)
nb = len(x) // 128
F = np.fft.rfft(x[:nb*128].reshape(nb, 128), axis=1)[:, 9:12]
bits = ((F.imag < 0).sum(1) >= 2).astype(np.uint8)
raw = np.packbits(bits).tobytes()
n = struct.unpack('>I', raw[:4])[0]
png = raw[4:4+n]                      # length-prefixed PNG (20x20 RGB)

# 3. Layer 3: PNG pixel LSBs (row-major, R,G,B order, MSB first) -> length-prefixed blob
px = np.array(Image.open(io.BytesIO(png)).convert('RGB'))
blob = np.packbits((px & 1).reshape(-1).astype(np.uint8)).tobytes()
m = struct.unpack('>I', blob[:4])[0]
ct = blob[4:4+m]                      # 12-byte nonce | ciphertext | 16-byte GCM tag

# 4. Layer 4: AES-256-GCM, key = stream B
print(AESGCM(B).decrypt(ct[:12], ct[12:], None).decode())
```
