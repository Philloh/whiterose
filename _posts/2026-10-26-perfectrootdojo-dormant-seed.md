---
title: "Dormant Seed — Python Loader Static Analysis"
date: 2026-10-26 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, python, malware, static-analysis]
pin: false
---

# Dormant Seed: write-up

**Flag:** `r00t{s33d_n3v3r_sp0uts_st4ys_st4t1c}`

The loader was solved by static analysis only. I never executed `loader.dsk`, its stub, or its payload.
"Activating the dormancy" here just means decoding the hidden config. Actually running the loader
would be the step that contacts the host named inside it, so I deliberately did not do that.

## 1. Container format (`DSK1`)

`loader.dsk` is 3,371 bytes. The layout matches the byte count exactly:

| Offset | Size | Contents |
|---|---|---|
| 0 | 4 | magic `DSK1` |
| 4 | 4 | `stub_len`, big-endian = 1124 |
| 8 | 4 | `blob_len`, big-endian = 2155 |
| 12 | 64 | `sig` (the same 32 bytes repeated twice) |
| 76 | 1124 | stub: a `marshal`-ed Python code object (`<stub>`) |
| 1200 | 2155 | encrypted blob |
| 3355 | 16 | trailer `END-DSK-ARCHIVE\0` |

`strings` on the file already shows the stub's identifiers (`hashlib`, `marshal`, `from_bytes`,
`sha256`, `digest`, `stub_len`, `blob_len`, `blob_start`, `encrypted`, `decrypted`, `payload_code`).

## 2. The stub (`unpack`)

`marshal.loads(d[76:])` parses the stub, but its bytecode is scrambled and does not disassemble.
The constants, names and locals are still intact, so the logic can be rebuilt from them:

```python
def unpack(raw):
    stub_len = int.from_bytes(raw[4:8], 'big')
    blob_len = int.from_bytes(raw[8:12], 'big')
    sig = raw[12:76]
    blob_start = 76 + stub_len
    key = hashlib.sha256(sig).digest()
    encrypted = raw[blob_start:blob_start + blob_len]
    decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
    payload_code = marshal.loads(decrypted)
```

The exact key derivation is inferred, so I tested it. Trying several candidate keys against
`marshal.loads` (which only parses and does not run code), `sha256(sig)` was the only one that yielded a valid code object.
Key: `9b0e0266e854dbe44ce898ba3123ed5527472dcd8b55c7900426e7adbca206bc`.

## 3. The payload: a tiny byte-VM

The decrypted payload is another code object with a scrambled `co_code`, but again its constants are readable:

- Opcodes: `OP_XOR_KEY=1, OP_ADD_CONST=2, OP_SUB_CONST=3, OP_ROL=4, OP_ROR=5, OP_HALT=255`
- `VM_PROGRAM` (20 bytes, `(op, operand)` pairs):
  `XOR 0 → ADD 17 → ROL 3 → XOR 0 → SUB 7 → ROR 5 → XOR 0 → ADD 41 → ROL 1 → HALT`
- `VM_CONFIG`: a 64-byte blob, the data to decode.
- `run_vm` names include `reversed`, `_ror8` (used for `OP_ROL`) and `_rol8` (used for `OP_ROR`).
  So `VM_PROGRAM` describes the *encoding*, and `run_vm` **decodes** by undoing the steps in reverse order with inverse operations.

Decoding rules applied per byte, in reverse program order:

| Step | Inverse |
|---|---|
| `XOR_KEY` | `b ^= key[j % 32]` |
| `ADD n` | `b = (b - n) & 0xff` |
| `SUB n` | `b = (b + n) & 0xff` |
| `ROL n` | rotate right by `n` |
| `ROR n` | rotate left by `n` |

The VM key is the same `sha256(sig)` digest. Other candidate keys gave only about 30 to 45% printable output; this one gave 100%.

## 4. Result

Decoding `VM_CONFIG` gives:

```
beacon.lordsudo.com|OPFALCON-7|r00t{s33d_n3v3r_sp0uts_st4ys_st4t1c}
```

That is `host | operation tag | flag`. The host is a beacon endpoint, which is why I did not run the loader.

## Reproduce (static, safe)

```python
import hashlib, marshal
d = open('loader.dsk', 'rb').read()
k = hashlib.sha256(d[12:76]).digest()
blob = d[1200:1200 + 2155]
payload = marshal.loads(bytes(b ^ k[i % 32] for i, b in enumerate(blob)))  # parse only
prog, cfg = [c for c in payload.co_consts if isinstance(c, bytes)]
rol = lambda b, n: ((b << n) | (b >> (8 - n))) & 255
ror = lambda b, n: ((b >> n) | (b << (8 - n))) & 255
buf = list(cfg)
for op, x in reversed([(prog[i], prog[i + 1]) for i in range(0, len(prog) - 2, 2)]):
    for j in range(len(buf)):
        if op == 1: buf[j] ^= k[j % 32]
        elif op == 2: buf[j] = (buf[j] - x) & 255
        elif op == 3: buf[j] = (buf[j] + x) & 255
        elif op == 4: buf[j] = ror(buf[j], x)
        elif op == 5: buf[j] = rol(buf[j], x)
print(bytes(buf).decode())
```
