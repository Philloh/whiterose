---
title: "Gravimetry — Matched Filter Signal Decoding"
date: 2026-09-17 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [misc, signal-processing, binary-analysis, reverse-engineering]
pin: false
---

# GRAVIMETRY - Writeup ("Defy Gravity and Beat the Metrics")

Files   : strain.dat, wave_analysis.py, detector_params.txt,
          gravimetry, check, validator (three x86-64 ELF binaries)
Flag    : r00t{gr4v1m3try_a6fa1c0992a133734391c957}


## 1. TL;DR
The provided analysis script runs happily and prints a flag-shaped string,
but it is a decoy: it decodes 160 zero bits. detector_params.txt and
wave_analysis.py both describe the detector wrongly. Four separate things are
wrong (calibration offset, bandpass, template, threshold metric). The real
parameters can be recovered from the `gravimetry` binary, which embeds the
true template, the true threshold and a built-in oracle. Decoding with the
true parameters yields a 20-byte message; the flag is

    r00t{gr4v1m3try_ + sha256(message)[:24] + }

The message is 43c99d220fbaadf12ea088325d29dd970b7bf09d.


## 2. First Look
  $ python3 wave_analysis.py
  r00t{gr4v1m3try_de47c9b27eb8d300dbb5f2c3}

Too easy, and the script's own comments admit problems ("Hann window, NOT
Gaussian", "wrong: AR(1) noise std is inflated"). Checking it:

  sha256(20 zero bytes)[:24] = de47c9b27eb8d300dbb5f2c3

so that "flag" is the hash of an all-zero message: the detector found no
signal in any window. That is the first sign the pipeline is broken, not
that the data is empty.

Layout of strain.dat (float32, 164,864 bytes):

  41,216 samples = 161 blocks of 256 = 256 (calibration) + 160 x 256 (signal)

The parameter sheet says "512-sample header, calibration at offset 512" and
the script reads calib = strain[512:768]. That layout needs 41,728 samples,
more than the file holds. Per-block statistics show what is really there:

  block 0       : mean|x| = 1.0000 exactly, std 1.25   <- calibration pulse
  blocks 1..160 : std ~0.10, mean|x| ~0.08-0.10        <- 160 signal windows

So the calibration pulse is at samples 0..255 and gain = 1.0 / 0.1 = 10.0.
The script computes 0.935 from signal data (mean|x| of block 2), a 10x error.


## 3. The Binaries
Triage with file/strings/objdump (no tshark-style tooling needed):

  gravimetry : usage "./gravimetry strain.dat", sqrtf, memcmp, "need 20 bytes"
  check      : fgets/strcmp, prints CORRECT / INCORRECT (overlapping strings)
  validator  : same code as check, different embedded string

### 3.1 gravimetry is a reference oracle. Disassembly of main shows:

  - fread of 0xA100 = 41,216 floats from the file
  - sum |x| over the first 0x400 bytes (256 floats) * (1/256), divided by 0.1
        -> gain, with calibration at sample 0, confirming section 2
  - norm of a 256-float template stored in .rodata at 0x2060 (it is unit norm)
  - for each of 160 windows (start 256, step 256, RAW data):
        stat = |dot(window, template) * gain| / ||template||
        if stat > threshold: set bit k  (byte k>>3, bit k&7, LSB first)
  - read 20 bytes from stdin and memcmp them with the decoded message;
    exit 0 on match, 1 on mismatch, no output either way

Constants read from .rodata: 1/256, REF_AMP = 0.1, THRESHOLD = 3.5.

Takeaways: no bandpass filter, no division by a noise std, and a plain
### 3.5 threshold on the gain-scaled dot product. It gives ground truth to test
any decoder against.

### 3.2 The real template. Extracting the 256 floats at 0x2060 and analysing them:
  - zero crossings every ~10.24 samples  -> half period of 2.5 ms
  - Hilbert instantaneous frequency flat at 200.0 Hz
  - symmetric about sample 128, peak 0.166 there
A least-squares fit gives, with max error 1.1e-8:

    template[n] = cos(2*pi*200*(t - t0)) * exp(-(t - t0)^2 / (2*0.010^2)),
    t = n/4096, t0 = 128/4096, normalised to unit L2 norm

A Hann taper makes the fit worse (best max error 3e-3), so there is none.

### 3.3 check / validator. Both XOR a string from .rodata with 0x5c at run time
and strcmp it with the line read from stdin. Decoding the strings offline:

  check     -> r00t{gr4v1m3try_a6fa1c0992a133734391c957}
  validator -> r00t{gr4v1m3try_wr0ng_d3t3ct0r_000000000000}   (decoy)

I did not take `check` on trust; the flag below was derived independently
from the signal first, and only then compared with it.


## 4. What The Documents Got Wrong
  Item            Documented                 Actual (from binary / data)
  --------------  -------------------------  ---------------------------------
  Calibration     offset 512, 512-sample     samples 0..255, no header;
                  header                     gain = 10.0, not 0.935
  Carrier         100 Hz                     200 Hz
  Envelope        Hann / Gaussian-Hann,      Gaussian only, sigma = 0.010 s
                  sigma = 0.020 s
  Bandpass        Butterworth 50-150 Hz      none (and it would delete the
                                             signal, see below)
  Metric          dot/noise_std(full) > 8.5  |dot*gain| > 3.5 on raw data

The bandpass is the nastiest trap. The real signal sits at 200 Hz +/- ~16 Hz
(spectral width of a 10 ms Gaussian), well above the 150 Hz upper edge:
on the windows that carry a 1-bit, the matched-filter statistic falls from
### 7.90 (raw) to 0.20 (bandpassed), so 97.5 % of the signal is filtered out.
That alone explains why the script decodes all zeros.


## 5. ABLATION: ONE FIX AT A TIME
Bit errors versus the oracle-confirmed message (160 windows):

  step                                                       ones  errors
  0 original script (BP, doc template, gain@512, SNR>8.5)      0      81
  1 + gain from samples 0..255 (10.0)                        129      80
  2 + remove bandpass                                         36      85
  3 + true 200 Hz Gaussian template                          110      29
  4 + metric |dot*gain| > 3.5 (binary's own)                  81       0

Step 3 still has 29 errors because dividing by std(full signal)=0.144 turns
"8.5 sigma" into an effective threshold of ~1.23 on the gain-scaled dot, which
is inside the noise. Only the final step removes it. The "8.5 sigma" figure
also cannot be rescued by estimating the noise properly: the noise-window
statistic has sigma ~0.77, so 8.5 sigma = 6.6, above the weakest real signal
window (5.571). The sigma estimate there uses the windows classified as noise
by the decode, so it is indicative, not independent.


## 6. Decoding
With the right pipeline the statistic is cleanly bimodal:

  noise windows  : mean 1.08, max 2.997        (79 windows)
  signal windows : mean 7.90, min 5.571        (81 windows)

Any threshold from 3.0 to 5.55 decodes identically, so the 3.5 threshold is
safe, and a threshold-free method (split at the widest gap in the sorted
statistics, 4.284) gives the same bits. Packing bits LSB-first into bytes:

  message = 43c99d220fbaadf12ea088325d29dd970b7bf09d      (20 bytes)

Oracle:

  $ ./gravimetry strain.dat < msg.bin ; echo $?
  0

Flag, using the same formula as the original script:

  sha256(message) = a6fa1c0992a133734391c957ab84eb7348d131e8430bc896d3acfd6aa25733d0
  flag            = r00t{gr4v1m3try_a6fa1c0992a133734391c957}

Cross-checks:

  $ echo 'r00t{gr4v1m3try_a6fa1c0992a133734391c957}' | ./check       -> CORRECT
  $ echo 'r00t{gr4v1m3try_a6fa1c0992a133734391c957}' | ./validator   -> INCORRECT
  $ python3 wave_analysis.py | ./check                              -> INCORRECT


## 7. SOLVER (verified; uses only the closed-form template, nothing from the binary)
#!/usr/bin/env python3
import hashlib
import numpy as np

SR, N, NWIN = 4096, 256, 160
strain = np.fromfile("strain.dat", dtype=np.float32).astype(np.float64)

# gain from the calibration pulse (samples 0..255, not 512..767)
gain = np.mean(np.abs(strain[:N])) / 0.1            # -> 10.0

# true template: 200 Hz cosine, sigma = 10 ms Gaussian, centred, unit norm
t = np.arange(N) / SR
tc = 128 / SR
tmpl = np.cos(2*np.pi*200*(t - tc)) * np.exp(-(t - tc)**2 / (2*0.010**2))
tmpl /= np.linalg.norm(tmpl)

# matched filter on RAW data, 160 windows starting at sample 256
wins = strain[N:N + NWIN*N].reshape(NWIN, N)
stat = np.abs(wins @ tmpl) * gain

# threshold-free sanity: split at the widest gap in the sorted statistic
srt = np.sort(stat)
k = np.argmax(np.diff(srt))
gap_thr = (srt[k] + srt[k+1]) / 2
bits_gap = (stat > gap_thr).astype(int)
bits = (stat > 3.5).astype(int)
assert (bits == bits_gap).all()

msg = bytearray(NWIN // 8)
for i, b in enumerate(bits):                         # LSB-first per byte
    msg[i // 8] |= int(b) << (i % 8)

open("msg.bin", "wb").write(bytes(msg))
print("message:", bytes(msg).hex())
print(f"r00t{gr4v1m3try_" + hashlib.sha256(bytes(msg)).hexdigest()[:24] + "}")

Output:
  gain=10.000  noise max=2.997  signal min=5.571  gap threshold=4.284
  message: 43c99d220fbaadf12ea088325d29dd970b7bf09d
  r00t{gr4v1m3try_a6fa1c0992a133734391c957}


## 8. Lessons
  - A script that "works" is not a script that is right. An all-zero message
    is a red flag; hash-wrapped flags hide that.
  - Documentation in a challenge is an adversary too. Trust the artifacts:
    the file size, the block statistics and the binary's constants beat the
    parameter sheet on every point.
  - A reference binary is a free oracle even when you cannot (or need not)
    read its flag: extract its constants and template, then test your
    decoder against its exit code.
  - Filters belong to the signal's band. Check the template's real
    frequency before choosing a passband.
  - Beware a plausible-looking decoy string (`validator`) sitting next to
    the real one (`check`): derive the answer first, then match it.

Notes: the three provided binaries were run locally in an isolated sandbox
with no network access, only to read their exit codes and output.
