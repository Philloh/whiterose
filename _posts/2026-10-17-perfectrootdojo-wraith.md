---
title: "Wraith — WebAssembly VM Reverse Engineering"
date: 2026-10-17 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, wasm, vm, bytecode]
pin: false
---

# WRAITH.TXT - wraith.wasm solve notes

## FLAG
    r00t{w4sm_vm_byp4ss_unl0ck3d}

Verified against the real module: check_flag returns 1 and calls js_print_ok
for this string; changing the last character makes it call js_print_fail.


## 1. Recon
wraith.wasm is 2,094 bytes, built with clang 18.1.3.
  - Imports:  env.js_print_ok, env.js_print_fail (both void -> void)
  - Exports:  memory, check_flag(i32 ptr) -> i32
  - Memory:   2 pages, one active data segment of 731 bytes at address 1024
No wasm2wat/wasm-objdump was available, so I parsed the section headers by
hand (section 10 = code, section 11 = data) and read the code bytes directly.


## 2. WHAT check_flag DOES
It is a small bytecode VM, not a direct string compare.

  a) It scans the input for a NUL terminator (length capped at 64).
  b) It decrypts 330 bytes of VM bytecode onto the stack. The bytecode is
     stored in the data segment at 1040 and XORed with a 4-byte repeating
     key at 1024..1027 (index i uses key[i & 3]).
  c) It runs an interpreter loop. The opcode dispatch is a br_table over the
     bytes 0x41..0x48, plus two special cases, 0xad and 0xde.
  d) At the end it calls js_print_ok or js_print_fail depending on a result
     flag kept in the VM state.

So the flag is never present as plain text in the binary. The comparison
targets only exist after the XOR decryption.


## 3. Getting The Decrypted Bytecode
Rather than re-implement the XOR by hand, I instantiated the module in Node,
wrote a dummy string into memory, called check_flag, then dumped the stack
region. Memory is exported and the decrypted bytecode stays in linear memory
after the call returns (stack pointer starts at 66912, frame size 416, so the
bytecode is at 66496..66825).

The decoded bytecode is highly regular:

    de | 42 idx 41 K 43 45 R 41 T 46 | 42 idx 41 K 43 45 R 41 T 46 | ...
    ... ad 00 47 47 47 47 ...

Read as VM instructions, each flag character is checked like this:

    0x42 idx   push input[idx]
    0x41 K     push constant K
    0x43       combine the top two values (xor/add/sub - see below)
    0x45 R     rotate the result left by R bits (8-bit rotate)
    0x41 T     push target T
    0x46       compare equal, AND into the result flag
    0xde       separator / state marker between groups
    0xad       end of program -> final result
    0x47       padding

There are 29 groups, idx 0..28, so the flag is 29 characters long.


## 4. Solving
For each group I know (K, R, T) and need the input byte c such that

    rotl8( c OP K , R ) == T

I did not fully trust my reading of what op 0x43 does (xor vs add vs sub),
so I inverted all four candidates (xor, add, K-sub, sub-K) with both rotation
directions and printed each result. Only one combination produced readable
text:

    OP = xor, rotation = left, giving
    r00t{w4sm_vm_byp4ss_unl0ck3d}

That makes the formula: rotl8(input[i] ^ K, R) == T, so
    input[i] = rotr8(T, R) ^ K.


## 5. Verification
    r00t{w4sm_vm_byp4ss_unl0ck3d}    -> js_print_ok   (returns 1)
    r00t{w4sm_vm_byp4ss_unl0ck3e}    -> js_print_fail (returns 0)

Side observation: appending extra characters (e.g. the flag plus "x") still
returns OK. The VM only checks the first 29 positions and never compares the
input length, so trailing junk is accepted. The real flag is the 29-character
string above.


## Reproduce
  1. Instantiate wraith.wasm in Node with stub js_print_ok/js_print_fail.
  2. Copy any string to memory, call check_flag, dump 330 bytes at 66496.
  3. Split into (idx, K, R, T) groups and compute rotr8(T, R) ^ K per index.
