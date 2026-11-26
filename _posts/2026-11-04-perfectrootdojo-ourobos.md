---
title: "Ouroboros — Nested VM Reverse Engineering"
date: 2026-11-04 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, vm, binary, obfuscation]
pin: false
---

# Ouroboros – Write-up ("Can you escape it?")

**Flag:** `r00t{0ur0b0r0s_6f86002f214455d445fd6522}`

The flag is confirmed by running the provided `check` binary: it prints `CORRECT` for this string and `INCORRECT` for everything else. One caveat: the uploaded `inner.enc` was corrupted in transfer, so I could not run the two-VM chain (`outer.orb` -> `inner.orb` -> `inner_vm`) end to end. Details in "Caveats" below.

## Files provided

| File | What it is |
|---|---|
| `ouroboros` | Outer loader. Runs `outer.orb` in a tiny VM, derives a key from its RAM, XOR-decrypts `inner.enc` into `inner.orb`. |
| `outer.orb` | Outer VM program (ORB1 format): 256-byte RAM init + bytecode. |
| `inner.enc` | Encrypted inner VM program. |
| `inner_vm` | Inner VM. Usage: `echo -n <20 bytes> \| ./inner_vm inner.orb`. |
| `check`, `validator` | Two ELF "flag checkers". |
| `isa_outer.txt`, `isa_inner.txt`, `outer_disasm.txt` | Documentation for the two VMs and a "pre-generated" disassembly. |

## 1. The two checkers (this is where the flag is)

Both ELF checkers (`check`, `validator`) have the same shape: an XOR-obfuscated string sits in `.rodata` at `0x2020`, right after `"INCORRECT"`. Their `main`:

1. decodes the string with XOR `0x5c` into a stack buffer (the loop at `0x10e0`: `xor eax,0x5c`),
2. reads one line from stdin with `fgets` (strips `\n`),
3. `strcmp`s the input against the decoded string.

Decoding the two embedded strings with XOR `0x5c`:

```
validator: r00t{wr0ng_t00_34sy_haha00}          <- decoy ("wrong, too easy, haha")
check:     r00t{0ur0b0r0s_6f86002f214455d445fd6522}
```

The decoy is not just a decoy string: `validator`'s branches are **inverted** (diffing the two disassemblies shows `je`/fall-through swapped). It prints `INCORRECT` only when the input equals the decoy and prints `CORRECT` for every other input, including garbage:

```
$ echo 'r00t{x}' | ./validator          -> CORRECT     (accepts anything but its decoy)
$ echo 'r00t{wr0ng_t00_34sy_haha00}' | ./validator -> INCORRECT
```

So `validator` is useless as an oracle and a false "solved" signal. `check` has normal logic:

```
$ echo 'r00t{0ur0b0r0s_6f86002f214455d445fd6522}' | ./check -> CORRECT (exit 0)
$ echo 'r00t{wr0ng_t00_34sy_haha00}'               | ./check -> INCORRECT
$ echo 'r00t{x}'                                   | ./check -> INCORRECT
```

Because `check` is a plain `strcmp` against one string, that string is the only input it accepts. That makes it the flag.

## 2. The VM chain (how the loader works)

### Loader (`ouroboros`, from disassembly)

1. Read `outer.orb`: magic `ORB1`, 2-byte big-endian program length, 256 bytes RAM init, then bytecode.
2. Run the outer VM (6-opcode interpreter over 8 byte registers and 256 bytes RAM).
3. Derive an 8-byte key from the outer VM's RAM after it halts:

   ```
   t = RAM[0x10:0x18] XOR RAM[0x18:0x20]
   for j in 0..7:  t[j] = ror8(t[(j+1) & 7], 3) ^ t[j] ^ 0x3c      # in place, sequential
   key = t
   ```
4. Write `inner.orb[i] = inner.enc[i] ^ key[i & 7]`.

### The "outer" program is a no-op

`outer.orb` is 263 bytes: `ORB1`, length `0x0001`, the RAM init, and a single `0x07` (`HLT`) as bytecode. The documentation's "pre-generated disassembly" says the same, and it is true. So the key depends only on the RAM init. The documented key material is `RAM[0x10:0x18] = 3e97a1d3e239c7ba` and `RAM[0x18:0x20] = f9921126a724c935` (both verified in the file), giving:

```
t0  = 3e97a1d3e239c7ba ^ f9921126a724c935
key = 5b2f3261dae0c3d8
```

Decrypting the first bytes of `inner.enc` with this key gives `49 4e 52 31` = `"INR1"`, which is the inner VM's magic (`inner_vm` prints `Bad inner magic` otherwise). That confirms the key and the cipher.

Notes where the docs and the binary disagree: `isa_outer.txt` says `ADD r, r2` (two registers) but the binary's `ADD` takes an immediate operand; `isa_inner.txt` calls opcode 6 `JNZ` but describes "jump if equal". The binaries are what runs, so treat the docs as hints.

### The inner program (partial reconstruction)

`inner.orb` = `INR1`, length `0x01a2` (418), 256 bytes RAM init, 418 bytes bytecode (total 680). The bytecode is a setup prefix (`LDI ... 0; LDI r3, 0x14` i.e. count 20) followed by **10 identical 40-byte blocks**, one per pair of the 20 input bytes. The block counter immediates run `00, 02, 04 ... 12`, and per-block constants step by 2 (`0x21, 0x23 ... 0x33` and `0xe1, 0xe3 ... 0xf3`). Each block loads two input bytes, applies a transform and compares against a table in the program's RAM init (around `RAM[0x20..0x33]`), with a 3-byte tail (`06 03 06 02 ...`) ending the program.

## Caveats (what I could not verify)

- **`inner.enc` was damaged in the upload.** Every byte `>= 0x80` was replaced by the UTF-8 replacement character (`EF BF BD`), about half the file. Runs of high bytes were also collapsed, so 2 bytes are missing from the RAM-init region (I resolved the length: 680 total = 6 + 256 + 0x1a2). The key and the structure above are recoverable, but the constants and the expected table are not, so I could not rebuild a runnable `inner.orb` or solve the inner VM's 20-byte input.
- Because of that, I did not independently derive the flag from the VM path. The flag above comes from the `check` binary, whose acceptance I tested directly.
- If you can re-upload `inner.enc` as a binary (zip it, or send it base64-encoded), I can run the full chain and confirm the 20-byte input as well.

## Solve script (extracts the flag from `check`)

```python
import re, sys
d = open(sys.argv[1], 'rb').read()            # ./check
i = d.find(b'INCORRECT') + 9
s = re.match(rb'\x00+(.+?)\x00', d[i:i+120], re.S).group(1)   # obfuscated string
print(bytes(c ^ 0x5c for c in s).decode())    # r00t{0ur0b0r0s_6f86002f214455d445fd6522}
```
