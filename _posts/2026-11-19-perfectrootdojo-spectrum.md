---
title: "Spectrum — Spectrogram AES Steganography"
date: 2026-11-19 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, steganography, audio, aes, png]
pin: false
---

# Ledger Intercept: Write-up

**Category:** Forensics / Steganography (multi-layer)
**Flag:** `r00t{sp3ctr0gram_c4rv1ng_ls8_l3dg3r}`

## Challenge

> Two files, intercepted together. Neither looks like much on its own.

| File | Type | Notes |
|---|---|---|
| `ledger_intercept.wav` | RIFF WAVE, PCM 16-bit, mono, 44.1 kHz | 14.4 s, 635,040 samples |
| `image.png` | PNG, 320x180, RGB | Caption: "ledger intercept - camera 4" |

## Solution overview

```
ledger_intercept.wav --(spectrogram)--> KEY: de37d38d2ddf354d53f8da0a1e34fe41
                                              |
image.png --(data after IEND)--> IV (00..0f) + ciphertext
                                              |  AES-128-CBC
                                              v
                                         ZIP archive -> inside.png (256x256 noise)
                                              |  LSB extraction (interleaved RGB, MSB-first)
                                              v
                                   r00t{sp3ctr0gram_c4rv1ng_ls8_l3dg3r}
```

## Step 1: Triage

`file` and `strings` showed nothing obvious in either file. The PNG's size stood out: a 320x180 image of flat colour with a text caption should be a few KB, but the file is **199,228 bytes**.

Walking the PNG chunks confirmed it. There is one `IHDR`, one `IDAT` of only 1,795 bytes, and an `IEND`. Everything after `IEND` is extra data.

```python
d = open('image.png','rb').read()
i = d.index(b'IEND') + 8
trail = d[i:]          # 197,376 bytes
```

I also checked the PNG's colour channels for LSB steganography. The image has only 104 distinct colours (anti-aliased caption text) and its LSB planes are all zero, apart from the text pixels. The payload is not in the pixels.

## Step 2: The audio is a spectrogram painting

The WAV has no metadata or LSB structure worth noting. Its sample LSBs are roughly random, and the first samples are zero.

A spectrogram shows text drawn in the 2.2-5.4 kHz band:

```python
f, t, S = scipy.signal.spectrogram(x, 44100, nperseg=1024, noverlap=900)
```

The spectrogram has 36 glyph slots, one every 0.4 s, separated by near-silent gaps. A coarse spectrogram is blurry, so I segmented the audio on the silent gaps. Each glyph was rendered on its own with a finer time step:

- Slots 0-2 spell `KEY`.
- Slot 3 is the narrow `:`.
- Slots 4-35 are 32 hex characters.

Reading each glyph gives:

```
KEY: de37d38d2ddf354d53f8da0a1e34fe41
```

That is 32 hex characters, or 16 bytes, which fits an **AES-128** key.

## Step 3: The PNG trailer is an AES-encrypted blob

The trailer is 197,376 bytes = 16 x 12,336. It begins with `00 01 02 03 ... 0f`, a sequential-byte pattern used as an IV. The rest is high-entropy data of 197,360 bytes (a multiple of 16).

Decrypting the remaining bytes as AES-128-CBC, with the spectrogram key hex-decoded and the first 16 bytes as the IV, produced a file with a `PK\x03\x04` header:

```bash
K=de37d38d2ddf354d53f8da0a1e34fe41
tail -c +17 trail.bin > ct.bin
openssl enc -d -aes-128-cbc -K $K -iv 000102030405060708090a0b0c0d0e0f -in ct.bin -out p1.zip
unzip p1.zip        # -> inside.png
```

## Step 4: `inside.png` and LSB extraction

`inside.png` is 256x256 RGB (196,608 bytes of pixel data). Visually it is pure RGB noise. There is no trailing data after its `IEND`.

I extracted the least significant bit of every channel value, reading pixels in row-major order and channels in R, G, B order, then packed the bits into bytes MSB-first:

```python
import numpy as np
from PIL import Image
im = np.array(Image.open('inside.png'))
bits = (im & 1).ravel()
data = np.packbits(bits, bitorder='big')
print(data[:40])    # b'r00t{sp3ctr0gram_c4rv1ng_ls8_l'...
```

The message is `r00t{sp3ctr0gram_c4rv1ng_ls8_l3dg3r}`.

Other orderings did not work. Extracting each channel's LSB plane separately gave nothing, and neither did the other bit orders or higher bit planes. Only the interleaved, MSB-first LSB read decodes.

## Flag

```
r00t{sp3ctr0gram_c4rv1ng_ls8_l3dg3r}
```

The flag text confirms the chain: a **spectrogram** carries the key, and **LSB** steganography hides the payload.

## Notes

- **Reading the key:** I read the key by eye from the rendered glyphs. A misread character would make the AES decrypt produce garbage, and CBC with a wrong key would not yield a valid `PK` header. The clean ZIP header confirms all 32 characters are correct.
- **IV choice:** The IV was stored in plaintext at the start of the trailer. That is why the sequential `00..0f` bytes were a strong hint.
- **Why neither file works alone:** The PNG alone has an undecryptable trailer. The WAV alone has only a key with nothing to unlock.

## Tools used

`file`, `strings`, Python (`numpy`, `scipy`, `matplotlib`, `Pillow`), `openssl`, `unzip`.
