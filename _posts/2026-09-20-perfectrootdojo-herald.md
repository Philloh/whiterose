---
title: "Herald — Echo Hiding in Audio"
date: 2026-09-20 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, audio, steganography, echo-hiding]
pin: false
---

# HERALD.TXT - herald_recording.wav solve notes

## FLAG
    r00t{c3pstr4l_4n4lys1s_r3v34ls_th3_3ch0}

No checker was supplied for this challenge. The evidence that it is right is
that the decoded frame is self-consistent: its length byte says 40, the text
is exactly 40 characters, it starts with r00t{ and ends with }, and the
phrase reads as a sentence ("cepstral analysis reveals the echo"), which is
also the technique used to find this kind of hidden data.


## 1. First Look
  - Mono, 16-bit PCM, 44,100 Hz, 32.69 s (1,441,792 samples = 352 x 4096).
  - Sounds like noise. The level is flat the whole way (std ~5640 per
    half-second), and the spectrogram shows no tones, speech or morse.
  - Sample LSBs and the lower bit planes are balanced and show no text, so
    this is not LSB steganography.
  - Autocorrelation of the whole file has two clear peaks:
        lag 100 samples: 0.246
        lag 150 samples: 0.144
    Everything else is ~0.003. Noise does not do that. These are echoes of the
    signal at delays of 100 and 150 samples (2.27 ms and 3.40 ms).


## 2. THE HIDING METHOD: ECHO HIDING
Echo hiding adds a faint copy of the signal back onto itself. The delay of the
copy carries the bit. Here:

    delay 100 samples  -> bit 0
    delay 150 samples  -> bit 1

I measured the autocorrelation at both lags in windows to find the pattern.
Per-window results fall into clean runs whose lengths are all multiples of
4096 samples, so each bit occupies one 4096-sample segment: 352 segments, 352
bits, 44 bytes.

Decoding rule per segment: compare the autocorrelation at lag 150 with the one
at lag 100; the larger one wins (150 -> 1, 100 -> 0). It is not close: across
all 352 segments the weakest decision still has a margin of 0.81 (|a-b| over
|a|+|b|), and the winning lag has a normalised autocorrelation of about 0.39
in every segment.


## 3. The Frame
The bits, read MSB-first from the start of the file, give 44 bytes:

    00 00 00 28 | 1a 55 42 15 17 07 50 11 1f 18 1a 51 1e 3e 58 0a
                  57 0d 15 1f 59 16 2d 13 5f 12 50 55 00 1f 37 11
                  1a 52 33 57 00 09 5c 11

  - 00 00 00   three zero bytes (the leading 24+ zero bits are a lead-in)
  - 28         = 40, the payload length
  - 40 bytes   payload, which is not readable as-is

The payload has no byte above 0x5f, so it is not plain ASCII. I tried a
single-byte XOR first, then a repeating-key XOR.


## 4. Breaking The Xor
Known-plaintext attack: assume the flag begins "r00t{" and XOR that against
the first five payload bytes. The key bytes come out as

    68 65 72 61 6c  =  "heral"

which is the challenge name (herald) cut off. So the key is built on
"herald". Decrypting with the repeating key "herald" or "heral" gives the
right start but corrupts later positions, so the key is longer than that.

Using the long key "heral" (period 5) most of the text came out right
("tr4l_4", "s1s_r3", "_th3_") but four character positions in every group of
10 were wrong in a consistent way. Positions 5-8, 15-18, 25-28 and 35-38 all
share a key byte, so each of those four slots had four ciphertext samples under
one unknown key byte. Trying each key byte against those four samples left only
one candidate where all four plaintext characters were sensible:

    slot 5/15/25/35:  key 'd'  -> c, n, v, 3
    slot 6/16/26/36:  key 'c'  -> 3, 4, 3, c
    slot 7/17/27/37:  key 'a'  -> p, l, 4, h
    slot 8/18/28/38:  key 'l'  -> s, y, l, 0

That gives the full 10-byte key (and 'l' was already fixed by position 9):

    heraldcall      ("herald call")

Decrypting the 40 payload bytes with key "heraldcall" repeated:

    r00t{c3pstr4l_4n4lys1s_r3v34ls_th3_3ch0}

The leet-speak reads "cepstral analysis reveals the echo". A cepstrum is the
standard way to detect echoes, which matches the hiding method.


## 5. Reproduce
  1. Read the WAV as int16. Split into 4096-sample segments.
  2. For each segment compute  a = sum(x[n]*x[n+100]),  b = sum(x[n]*x[n+150]).
     Bit = 1 if b > a else 0.
  3. Pack the 352 bits MSB-first into 44 bytes.
  4. Skip the 3 zero bytes, read the length byte (0x28 = 40), take the next
     40 bytes and XOR with the repeating key "heraldcall".


## Notes On Confidence
Confirmed from the data: the echo delays, the 4096-sample bit length, the
44-byte frame and its length byte, and the key bytes (each fits the decrypted
text from several positions). The one thing I could not check against an
external answer is the flag itself, since no checker was provided.
