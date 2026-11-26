---
title: "StormBreaker — Android AES Hardcoded Key"
date: 2026-11-21 09:00:00 +0300
categories: [CTFs, PerfectrootDojo]
tags: [reverse-engineering, android, aes, java, apk]
pin: false
---

# StormBreaker – Android Reverse Engineering Write-up

**Challenge:** *"To wield the axe, one must first bypass the forge's final lock."*
**File:** `STORMBREAKER.apk` (package `com.fryda.stormbreaker`)
**Category:** Reverse engineering / Android
**Flag:** `r00t{h4rdc0d3d_k3ys_f0r_th3_st0rm_br34k3r_4cbdcc80a590c924bb11eafd7de444dd}`

The app itself only ever prints the inner string, `h4rdc0d3d_k3ys_f0r_th3_st0rm_br34k3r_4cbdcc80a590c924bb11eafd7de444dd`, and never a wrapper. Earlier submissions of the bare string were rejected. The `r00t{...}` wrapper comes from the flag format of the sibling challenge in this set (`r00t{thr33_l4y3rs_n0_sh0rtcuts}`), not from anything inside this APK, so it is an inference and I could not check it against the platform.

---

## 1. Recon

Unzipping the APK shows a Jetpack Compose / Kotlin app. The only native library is `libandroidx.graphics.path.so`, which is part of AndroidX and not custom code. The challenge logic is therefore in the DEX files.

Decompiling with `jadx` gives a very small app package, `com.fryda.stormbreaker`:

```
MainActivity.java
MainActivityKt.java                      <-- all the logic
ComposableSingletons$MainActivityKt.java <-- Compose UI lambdas (title, "Unlock" label)
ui/theme/*                               <-- theme boilerplate
```

The UI is a single "vault" screen: a title ("StormBreaker"), a text field for a PIN, an **Unlock** button and an output text.

## 2. The lock

The core is in `MainActivityKt.java`:

```java
private static final String BLOB = "ocBtN+01RjIU0RWW7jEIz/rBCprw4dndwksr9XAv8sLADrTyj/hdsyEQAsSM3BuNqKABM7ikwqmuSb4vZmjVzHEJgdn67h8+/f4BlQk40dU=";
private static final String IV   = "0123456789abcdef";
private static final int[]  K    = {20,106,46,9,106,9,105,57,40,105,46,17,105,35,123,123};

private static final byte[] key() {
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) b[i] = (byte)(K[i] ^ 90);
    return b;
}

private static final String decryptVault() {
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(DECRYPT_MODE, new SecretKeySpec(key(), "AES"), new IvParameterSpec(IV.getBytes(UTF_8)));
    return new String(c.doFinal(Base64.decode(BLOB, 0)), UTF_8);
}
```

The button handler is:

```java
output = pin.equals(decryptVault()) ? decryptVault() : "Wrong PIN";
```

So the app does the following:

1. It rebuilds the AES key by XORing the `K` array with `0x5A`.
2. It decrypts a hard-coded Base64 blob with AES-128-CBC and a hard-coded IV.
3. It compares the result with what the user typed.
4. If they match, it shows the decrypted text. Otherwise it shows "Wrong PIN".

## 3. The flaw

The "PIN" is the plaintext of the blob, and the app has everything needed to decrypt it:

- The key is derived from constants with a trivial XOR, so it is obfuscated but not secret.
- The IV is a constant string.
- The ciphertext is embedded in the APK.

Nothing is derived from user input or from a secret held outside the APK. This means nobody has to guess a PIN. The check can be bypassed by reproducing `decryptVault()` offline, and the string it returns is the answer.

## 4. Solving

Key derivation:

```
K ^ 0x5A = 4e 30 74 53 30 53 33 63 72 33 74 4b 33 79 21 21
         = "N0tS0S3cr3tK3y!!"
```

The key is itself leetspeak for "NotSoSecretKey!!", which confirms the obfuscation is only cosmetic.

Decryption script (`python3 -I dec.py`):

```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

K = [20,106,46,9,106,9,105,57,40,105,46,17,105,35,123,123]
key = bytes(k ^ 90 for k in K)
iv  = b"0123456789abcdef"
blob = base64.b64decode("ocBtN+01RjIU0RWW7jEIz/rBCprw4dndwksr9XAv8sLADrTyj/hdsyEQAsSM3BuNqKABM7ikwqmuSb4vZmjVzHEJgdn67h8+/f4BlQk40dU=")

d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
p = d.update(blob) + d.finalize()
u = padding.PKCS7(128).unpadder()
print(u.update(p) + u.finalize())
```

Output:

```
h4rdc0d3d_k3ys_f0r_th3_st0rm_br34k3r_4cbdcc80a590c924bb11eafd7de444dd
```

The 80-byte ciphertext decrypts to a valid PKCS#7-padded plaintext. That confirms the key and IV are correct.

Entering this string into the app's PIN field and tapping **Unlock** passes the equality check and shows the same string. I checked the decryption offline and did not run the app on a device.

## 5. Flag

```
h4rdc0d3d_k3ys_f0r_th3_st0rm_br34k3r_4cbdcc80a590c924bb11eafd7de444dd
```

The leetspeak text reads "hardcoded keys for the stormbreaker", which sums up the flaw.

## 6. Takeaways

- **Do not hard-code key material in a client.** XOR-ing a constant array is obfuscation and does not protect anything. A decompiler plus a few lines of script recovers the key.
- **Do not make the secret its own verifier.** Because the app compares input against a value it can decrypt unaided, an attacker never needs to know the PIN.
- **A real design** would need a secret that is not shipped in the APK. Examples are a key derived from the user's PIN (PBKDF2 or Argon2 with a salt) so the ciphertext is useless without it, a key held in the Android Keystore, or a server-side check with rate limiting.

## Tools used

`unzip`, `jadx 1.5.1` for decompilation, and Python `cryptography` for AES-CBC decryption.

## 7. Open issue: submission was rejected

The string above was submitted as-is and marked incorrect. To rule out a mistake in the analysis I checked the following:

- **Bytecode vs decompiler:** the Dalvik bytecode of `key()`, `decryptVault()`, the `K` array initializer and the button handler matches the jadx output. The blob and IV in the raw DEX match as well.
- **Decryption validity:** the blob decrypts to valid PKCS#7-padded UTF-8, so the key and IV are correct.
- **Other app code:** only 21 classes belong to the app. The rest of the roughly 17,000 classes are Compose, AndroidX, Kotlin and R8 library code.
- **Manifest and resources:** there is no extra component or metadata, and the only app string is `app_name`.
- **Files and signing:** there are no assets and no custom native code. The zip has no hidden or trailing data, and the signing block padding is zero. The APK is debug-signed.

The decrypted string is therefore the only secret the app contains. The remaining possibilities are a flag wrapper or format not stated in the challenge text, or a different build of the APK from the one the platform checks.

## 8. Update: wrapper

The second upload of this APK is byte-identical to the first (same MD5, `fa45de60449e5601d4336b5968c811f4`), so nothing new is hidden in a different build. The only new evidence is the flag format of the other challenge in this set, `r00t{...}`. The recovered string is therefore submitted as `r00t{<string>}`.
