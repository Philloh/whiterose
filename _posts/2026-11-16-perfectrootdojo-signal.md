---
title: "Signal — React Native Bundle Reversing"
date: 2026-11-16 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, javascript, react-native, obfuscation]
pin: false
---

# Signal – Write-up

**Challenge file:** `index_android.bundle` (3,730 bytes, plain JavaScript – a React Native–style Metro bundle)

## Flag

```
r00t{h3rm3s_h1d3s_1n_th3_bundl3}
```

## TL;DR

The bundle's "license verification" screen contains a hidden decryption routine. Its key and ciphertext are stored in an obfuscated string table. Decoding the table and running the app's own `__cipherDecode` routine on the ciphertext yields the flag.

## 1. Recon

```
$ file index_android.bundle
index_android.bundle: JavaScript source, ASCII text, with very long lines
```

It is readable JS, not Hermes bytecode (despite the flag's hint), so no disassembler is needed. The file contains:

- A tiny module loader (`__d` / `__r`)
- An obfuscated string array `__STR_ARR` (14 Base64 entries)
- Helpers: `__b64d`, `__sidx`, `__hex2bytes`, `__str2bytes`, `__cipherDecode`
- Three modules: two stubs and `LicenseScreen` (module 2)

The interesting code is `onVerifyPress` in `LicenseScreen`. It **ignores the user's input** (`_inputCode` is never used) and just decrypts a hardcoded blob:

```js
var _keyStr = __sidx(342);
var _ctHex  = __sidx(343);
var _ptBytes = __cipherDecode(__hex2bytes(_ctHex), __str2bytes(_keyStr));
```

So the "signal" is the ciphertext at string index 343, and the key is at index 342.

## 2. Defeating the string obfuscation

String lookups go through `__sidx(idx)`, which does three things:

1. **Array rotation.** On startup an IIFE rotates `__STR_ARR` left by 11 positions (`rotator(++cnt)` with `cnt = 11` gives `n = 12`, and `while (--n)` runs 11 push/shift steps).
2. **Index offset.** `realIndex = idx - 336`.
3. **Decode.** Base64-decode the entry, then subtract 3 from every byte (a Caesar shift).

Rather than re-implement the rotation by hand, I executed the bundle's own helpers in Node (after reading the code and confirming it does nothing but string/byte manipulation) and dumped indices 336–349:

| idx | decoded string |
|-----|----------------|
| 336 | `Activate License` |
| 337 | `Enter activation code` |
| 338 | `Invalid code, try again` |
| 339 | `License verified` |
| 340 | `Loading...` |
| 341 | `Network error` |
| **342** | **`dojo-signal-key!`** ← key |
| **343** | **`3be94dfe52cf7bceef6d1218214a6a6d572fe857c230d0d7c2c48adc11298388`** ← ciphertext (hex) |
| 344–349 | UI strings (`Settings`, `Cancel`, `Retry`, `com.dojo.signalkey`, …) |

Everything else is decoy UI text.

## 3. The cipher

`__cipherDecode(bytes, key)` runs 4 rounds in reverse order (`r = 3 … 0`). Each round:

1. **Rotate right** every byte by `(r + 1) % 8` bits.
2. For each byte `i`: subtract `(r * 7 + 1)` (mod 256), then XOR with `key[(i + r) % key.length]`.

This is a simple custom byte-wise rotate/subtract/XOR cipher – the decode function is shipped inside the bundle, so no inversion work is required.

## 4. Solve

```js
// Load the bundle's helpers, then:
var f = __r(2);
console.log(f.onVerifyPress("anything"));
```

Output:

```
r00t{h3rm3s_h1d3s_1n_th3_bundl3}
```

Decoded plaintext is 32 printable ASCII bytes in the expected `r00t{...}` format, which confirms the key, ciphertext and round logic are all correct.

## Takeaways

- Client-side "license checks" that decrypt a constant are not verification at all – the input is never used.
- Obfuscating strings (rotation + Base64 + Caesar shift) only adds a speed bump when the decoder ships in the same file.
- Key and ciphertext shipped together in one bundle means anyone with the file can recover the secret.
