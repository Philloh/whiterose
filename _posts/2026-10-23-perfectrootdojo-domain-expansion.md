---
title: "Domain Expansion — Flutter APK Reversing"
date: 2026-10-23 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, android, flutter, dart]
pin: false
---

# Domain Expansion: write-up (INCOMPLETE)

**Status: not solved.** I mapped out what the APK is and where the check lives, but I did **not** recover the
16-character input or any flag. Everything below was observed directly. Nothing is guessed.

## 1. What the APK is

- `domain_expansion.apk`, 44 MB, package `com.example.domain_expansion`, version 1.0.0.
- A **Flutter** app. The Android side is only a stock `MainActivity`; `classes.dex` is the Flutter embedding plus AndroidX.
- The app logic is in the compiled Dart AOT snapshot: `lib/{arm64-v8a,armeabi-v7a,x86_64}/libapp.so`.
  The APK is large only because it ships three ABIs of `libflutter.so` and `libapp.so`.
- Nothing useful in the other assets: no custom assets (only the icon fonts and shaders), no extra resources,
  and the manifest has nothing unusual.
- The Dart build is **obfuscated** (identifiers look like `_hR@69206165`), and the binary is stripped.

## 2. App-specific strings found in `libapp.so`

Searching the snapshot's string table turned up only three user-interface strings that are clearly the app's own:

| String | Likely meaning |
|---|---|
| `DOMAIN EXPANSION` | the button label |
| `INSUFFICIENT CURSED ENERGY` | shown when the input length is not 16 (matches the challenge text) |
| `DOMAIN OVERRIDE FAILED` | shown when the 16-character check fails |

There is **no success string and no flag text** in the snapshot. The success output (and possibly the flag)
is probably computed at runtime from the correct input, so it cannot be read with `strings`.
`ENCRYPTED_SIZE` also appears in the snapshot, but it is present in `libflutter.so` too, so it is not app-specific.

## 3. Why I stopped

The validation function is compiled Dart machine code. Dart AOT code reaches strings and constants through an
object pool whose indices only make sense after parsing the snapshot's serialized heap. I disassembled the x86_64
`libapp.so` (about 9,500 functions) and inspected several candidates with 16-length checks, but the ones I looked at
were SDK code (BigInt, Set, and so on). With no Dart snapshot tooling available offline in the sandbox, I could not
tell which function is the app's check, so I could not read its constants.

## 4. How to finish this

1. Run [blutter](https://github.com/worawit/blutter) (or reFlutter / Doldrums) on `lib/arm64-v8a/libapp.so`
   to dump the object pool and annotated assembly.
2. Find the callers that reference `INSUFFICIENT CURSED ENERGY` and `DOMAIN OVERRIDE FAILED`.
   The comparison logic between them is the check.
3. Invert it. It is a 16-character check, so it is probably a per-character transform or a hash-like comparison
   against embedded constants, and the expected result may be the input itself.

If you can run blutter, or send me its output (the `pp.txt` and the `asm` file for `main.dart`), I can finish the
solve and update this write-up with the real flag.
