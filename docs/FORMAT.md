# SEAL file format

This document specifies the on-disk format used by the `seal` tool.
Two versions exist; current files are written in v2 and v1 is still
readable for backward compatibility.

## Common conventions

- All multi-byte integers are **big-endian**.
- The format is designed to be streamed: encryption and decryption do
  not require seeking and never load the whole input into memory.
- The crypto primitives are **AES-256-GCM** (authenticated encryption)
  and **scrypt** (memory-hard key derivation).

## Header

### v2 (current) — 30 bytes total

| offset | size | field         | meaning                                      |
|-------:|-----:|---------------|----------------------------------------------|
|     0  |   4  | `magic`       | ASCII `"SEAL"` (`0x53 0x45 0x41 0x4C`)       |
|     4  |   1  | `version`     | `0x02`                                       |
|     5  |   1  | `kind`        | `0x00` = file, `0x01` = directory archive, `0x02` = file with hidden name |
|     6  |  16  | `salt`        | random; input to scrypt                      |
|    22  |   8  | `nonce_pfx`   | random; first 8 bytes of every chunk's nonce |

### v1 (legacy) — 29 bytes total

| offset | size | field         | meaning                                |
|-------:|-----:|---------------|----------------------------------------|
|     0  |   4  | `magic`       | `"SEAL"`                               |
|     4  |   1  | `version`     | `0x01`                                 |
|     5  |  16  | `salt`        | random                                 |
|    21  |   8  | `nonce_pfx`   | random                                 |

v1 has no `kind` field — readers treat it as `kind = file`.

## Key derivation

```
key = scrypt(password, salt,
             N = 2^17, r = 8, p = 1,
             dklen = 32,        # AES-256
             maxmem = 256 MiB)
```

Tuned for ~1 second on a modern CPU and ~128 MiB of memory. This is
what makes a captured ciphertext expensive to brute-force offline.

## Body

The body is a sequence of **encrypted chunks**, each up to 64 KiB of
plaintext. Each chunk on disk is:

```
ciphertext_i  (1 to 65536 bytes)  ||  GCM tag_i  (16 bytes)
```

so a non-final chunk is exactly 65536 + 16 = 65552 bytes.

### Per-chunk nonce

```
nonce_i = nonce_pfx (8 bytes) || counter_i (4 bytes, big-endian)

counter_i = i,                 0 ≤ i < 2^31, for non-final chunks
counter_i = i | 0x80000000,    for the final chunk
```

The high bit of the counter is **set on the last chunk only**. Because
the nonce is part of the AEAD's authenticated state, this flag is
implicitly authenticated:

- Truncating the ciphertext (removing the real last chunk) makes some
  earlier chunk become "last" without its high bit set, which means its
  GCM tag won't verify under the now-required `last`-bit nonce.
- Appending extra chunks after the real last chunk makes the previously
  authenticated last chunk no longer be last, so its tag won't verify
  under the now-required non-`last` nonce.

Either way, decryption fails with a clear authentication error.

### Empty input

For an input with zero plaintext bytes, the body is a single chunk of:

```
GCM_encrypt(key, nonce(0, last=true), plaintext = b"", aad = none)
        →  16-byte tag, no ciphertext bytes
```

So the on-disk minimum is `header (29 or 30 bytes) || tag (16 bytes)`.

## Directory archives (`kind = 0x01`)

When `kind == 1`, the plaintext stream is a **gzip-compressed tar**
archive (`tar.gz`) of the source directory's contents. The encryption
layer is unchanged — chunking, nonce scheme, and headers all behave the
same as for ordinary files.

The tar archive contains entries with **paths relative to the source
directory** (no leading `/`, no top-level wrapper directory). On
extraction, `seal` rejects:

- absolute paths (starting with `/` or `\`)
- any path component equal to `..`
- entries whose resolved path escapes the destination
- device files and FIFOs
- symbolic / hard links whose target escapes the destination

Symlinks are never *added* to the archive during encryption, so a
well-formed directory archive produced by `seal` itself contains only
regular files and directory entries.

## Hidden-name files (`kind = 0x02`)

When `kind == 2`, the original filename is wrapped inside the encrypted
payload so the on-disk `.seal` output reveals nothing about the source.
The encryption layer is identical to a regular file (same chunking,
same nonce scheme); only the *interpretation* of the decrypted plaintext
differs.

The decrypted plaintext is laid out as:

```
+---------+----------------+-------------------+
| name_len | filename       | file content      |
| (2 B BE) | (UTF-8 bytes)  | (the actual file) |
+---------+----------------+-------------------+
```

- `name_len`: unsigned 16-bit big-endian, max `0xFFFF` (65535 bytes).
- `filename`: UTF-8 encoded, may be any length up to `name_len`.
- `file content`: the rest of the plaintext, of arbitrary length.

On decryption, readers must:

1. Decrypt the entire payload (all chunks, normally).
2. Parse `name_len` and the embedded filename from the start.
3. **Sanitize the filename**: strip directory components (`/` and `\`),
   reject empty names, `.`, `..`, and any name containing control
   characters (bytes < 0x20). Reject filenames whose UTF-8 decoding
   fails strict mode.
4. Write the rest of the plaintext to the sanitized basename inside
   the user-specified destination directory.

The sanitization step is critical: an attacker who can craft a `.seal`
file (e.g. a malicious sender) must not be able to write outside the
recipient's chosen destination. Stripping path components is sufficient
because the writer never interprets the filename as a path.

This kind only applies to single files. For directories with hidden
names, encrypt them as a directory archive (kind 1) and rename the
output `.seal` yourself.

## Testing the format

The pytest suite in `tests/test_seal.py` includes:

- round trips at every interesting size (empty, sub-chunk, exact chunk
  boundary, just-over, multi-chunk + remainder)
- tamper / truncate / append-garbage / not-a-SEAL-file rejection
- a hand-built v1 file (no `kind` byte) to verify backward compat
- malicious tarball entries (absolute paths, `..` traversal, escaping
  symlinks) are rejected by safe-extract

so changes to the format implementation that break any of the above
will surface immediately.
