---
title: "Sessions — Memory Cache XOR Recovery"
date: 2026-11-13 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [forensics, memory, xor, binary-analysis]
pin: false
---

# SESSCACHE_v2 Recovery — Write-up

## 1. Locating the cache

Scanned `memdump.bin` (5,242,880 bytes) for the ASCII marker `SESSCACHE_v2`.
It appears exactly once, at file offset **2,234,639**.

## 2. Header layout

Bytes immediately following the marker:

```
53 45 53 53 43 41 43 48 45 5f 76 32   "SESSCACHE_v2"
00 00 00 00                           4-byte reserved/padding field (always 0)
12 00 00 00                           record_count, uint32 LE -> 18
```

So the header is `marker (12B) + reserved (4B) + count (4B)` = 20 bytes,
and the record array starts right after it, at offset **2,234,659**.

## 3. Record layout

The spec names the fields but not their sizes, so I brute-forced the
total record length: for each candidate length `L`, I treated the
first 8 bytes as `record_id` + `timestamp` (both uint32 LE, per the
spec calling them "plain"), decoded the remaining bytes except the
last 4 with the given keystream, summed the decoded bytes mod 2^32,
and compared against the trailing 4 bytes interpreted as the plain
checksum.

Only **L = 76** validates (and it validates on all 18 records):

| Field          | Offset | Size | Encoding          |
|----------------|-------:|-----:|--------------------|
| `record_id`    | 0      | 4 B  | plain, uint32 LE   |
| `timestamp`    | 4      | 4 B  | plain, uint32 LE (Unix epoch, seconds) |
| `username`     | 8      | 16 B | XOR-obfuscated, NUL-padded |
| `session_token`| 24     | 48 B | XOR-obfuscated, NUL-padded |
| `checksum`     | 72     | 4 B  | plain, uint32 LE   |

Total record size: 76 bytes. Keystream index `i` is 0-based from the
start of the obfuscated region (byte 8 of the record), per the spec's
formula:

```
key_byte(record_id, i) = ((record_id * 2654435761 + i * 40503) & 0xFFFFFFFF) & 0xFF
```

`checksum = sum(decoded username+token bytes) mod 2^32` — confirmed
correct on every one of the 18 records.

## 4. Recovered sessions

| # | record_id | timestamp (UTC)        | username   | session_token |
|---|-----------|-------------------------|------------|----------------|
| 1 | 1000 | 2026-02-02 02:40:00Z | hyamamoto | sess_fb35288aa017ab5a68807255866c4fd1 |
| 2 | 1009 | 2026-02-02 02:45:00Z | rpatel    | sess_41e3584df7162c667fcd364e996a1f5d |
| 3 | 1017 | 2026-02-02 02:50:00Z | tnguyen   | sess_6ba3800665b6398a7e6283393144de5b |
| 4 | 1023 | 2026-02-02 02:55:00Z | hyamamoto | sess_a6fb49f3e221fb032bfb788c0bb70e20 |
| 5 | 1030 | 2026-02-02 03:00:00Z | rpatel    | sess_e331c27d305122a40a06987f544dfbfd |
| 6 | 1037 | 2026-02-02 03:05:00Z | kwilliams | sess_17b66f40ab82ab4ac11500b1ee085c54 |
| 7 | 1043 | 2026-02-02 03:10:00Z | kwilliams | sess_9056859370bc388f18cec754c29c0595 |
| 8 | 1049 | 2026-02-02 03:15:00Z | hyamamoto | sess_4f2b5942be72f3ba920e9838344df6e0 |
| 9 | 1058 | 2026-02-02 03:20:00Z | dcohen    | sess_261b0f55af3a1b593f583fa139e5a835 |
| 10 | 1066 | 2026-02-02 03:25:00Z | sokafor   | sess_27e3689ad1c6d1f18742f90d9b386c47 |
| 11 | 1073 | 2026-02-02 03:30:00Z | asingh    | sess_d2d24f550731896c17006b13e8477cc6 |
| 12 | 1077 | 2026-02-02 03:35:00Z | fibrahim  | **r00t{x0r_k3ys_d3r1v3d_fr0m_1ds_4r3nt_3n0ugh}** |
| 13 | 1086 | 2026-02-02 03:40:00Z | dcohen    | sess_344a9b7f724488fd2b374e2865bc1dc8 |
| 14 | 1091 | 2026-02-02 03:45:00Z | jmartinez | sess_6a6e965052432a0a0e2adb21978793f5 |
| 15 | 1100 | 2026-02-02 03:50:00Z | sokafor   | sess_339f2b75b8b6dd60a59a5f848ace7958 |
| 16 | 1108 | 2026-02-02 03:55:00Z | bchen     | sess_c9cfd7c6c0f6f3f3bb4e11ad2f27d9da |
| 17 | 1113 | 2026-02-02 04:00:00Z | mrossi    | sess_72da1e427e03c6d2e5484abe00dd4831 |
| 18 | 1122 | 2026-02-02 04:05:00Z | bchen     | sess_b7e4904928798f2955a04f588d0b642a |

All 18/18 records decode with a matching checksum.

## 5. The twist

Record #11 (`record_id = 1077`, user `fibrahim`) doesn't contain a
`sess_...` token at all — its 48-byte token field decodes to a flag:

```
r00t{x0r_k3ys_d3r1v3d_fr0m_1ds_4r3nt_3n0ugh}
```

This is the intended takeaway of the exercise: since the "obfuscation"
keystream is derived entirely from the record's own `record_id` (a
small, sequential, guessable value), it's not real encryption — anyone
who can see the ciphertext and infer/brute-force the `record_id` can
recover every field. It's a textbook XOR-with-a-derivable-key weakness,
not a secure obfuscation scheme.

## 6. Method summary

1. Locate `SESSCACHE_v2` marker → offset 2,234,639.
2. Skip 12-byte marker + 4-byte reserved field → read `record_count` (uint32 LE) = 18.
3. Brute-force record length against the per-record checksum → 76 bytes/record confirmed.
4. Parse `record_id` (u32), `timestamp` (u32), then XOR-decode 64 bytes using
   `key_byte(record_id, i)`, split into `username[16]` / `session_token[48]`
   (NUL-padded), verify against the trailing `checksum` (u32).
5. All 18 records verified; record #11 contains the flag instead of a session token.
