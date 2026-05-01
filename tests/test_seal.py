"""Tests for seal — file & folder encryption.

Run with:
    pytest -q

These tests cover the crypto core, round trips for both files and
directories, backward compatibility with v1 files, and the safe
tar-extraction logic.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

# Add the repo root to sys.path so `import seal` finds the local module.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import seal  # noqa: E402


PW = b"correct horse battery staple"


# =============================================================================
# round-trip tests — file mode
# =============================================================================

@pytest.mark.parametrize("size,label", [
    (0, "empty"),
    (1, "one byte"),
    (1024, "1 KB"),
    (seal.CHUNK_SIZE - 1, "just under one chunk"),
    (seal.CHUNK_SIZE, "exact chunk boundary"),
    (seal.CHUNK_SIZE + 1, "just over one chunk"),
    (3 * seal.CHUNK_SIZE + 17, "multi-chunk + remainder"),
])
def test_file_round_trip(tmp_path: Path, size: int, label: str) -> None:
    src = tmp_path / "src.bin"
    enc = tmp_path / "src.bin.seal"
    dec = tmp_path / "out.bin"

    data = os.urandom(size) if size else b""
    src.write_bytes(data)

    seal.encrypt_path(src, enc, PW)
    seal.decrypt_path(enc, dec, PW)

    assert dec.read_bytes() == data, f"round trip failed for {label}"


def test_encrypt_path_returns_kind_and_bytes(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"
    src.write_bytes(b"hello world")
    res = seal.encrypt_path(src, tmp_path / "x.seal", PW)
    assert res == {"kind": seal.KIND_FILE, "bytes": 11}


def test_peek_info(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"
    src.write_bytes(b"abc")
    enc = tmp_path / "x.seal"
    seal.encrypt_path(src, enc, PW)

    info = seal.peek_info(enc)
    assert info == {
        "version": seal.CURRENT_VERSION,
        "kind": seal.KIND_FILE,
        "kind_name": "file",
    }


# =============================================================================
# security — tamper, truncation, wrong password
# =============================================================================

def test_wrong_password_rejected(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"; src.write_bytes(b"secret data here" * 10)
    enc = tmp_path / "x.seal"; out = tmp_path / "out.txt"
    seal.encrypt_path(src, enc, PW)

    with pytest.raises(ValueError, match="wrong password|corrupted"):
        seal.decrypt_path(enc, out, b"wrong password")
    assert not out.exists(), "partial output should have been cleaned up"


def test_tampered_ciphertext_rejected(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"; src.write_bytes(b"x" * 200_000)
    enc = tmp_path / "x.seal"; out = tmp_path / "out.txt"
    seal.encrypt_path(src, enc, PW)

    raw = bytearray(enc.read_bytes())
    # Flip a byte well inside the ciphertext (past header, within first chunk).
    raw[100] ^= 0x01
    enc.write_bytes(bytes(raw))

    with pytest.raises(ValueError, match="corrupted|wrong password"):
        seal.decrypt_path(enc, out, PW)
    assert not out.exists()


def test_truncated_ciphertext_rejected(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"; src.write_bytes(b"x" * 200_000)
    enc = tmp_path / "x.seal"; out = tmp_path / "out.txt"
    seal.encrypt_path(src, enc, PW)

    raw = enc.read_bytes()
    enc.write_bytes(raw[:-100])

    with pytest.raises(ValueError):
        seal.decrypt_path(enc, out, PW)
    assert not out.exists()


def test_appended_garbage_rejected(tmp_path: Path) -> None:
    src = tmp_path / "x.txt"; src.write_bytes(b"x" * 200_000)
    enc = tmp_path / "x.seal"; out = tmp_path / "out.txt"
    seal.encrypt_path(src, enc, PW)

    with open(enc, "ab") as f:
        f.write(os.urandom(1000))

    with pytest.raises(ValueError):
        seal.decrypt_path(enc, out, PW)
    assert not out.exists()


def test_not_a_seal_file_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.seal"; bad.write_bytes(b"this is not a seal file at all")
    out = tmp_path / "out.txt"
    with pytest.raises(ValueError, match="not a SEAL file|magic"):
        seal.decrypt_path(bad, out, PW)


# =============================================================================
# v1 backward-compat — manually construct a v1 file and decrypt it
# =============================================================================

def _make_v1_file(path: Path, plaintext: bytes, password: bytes) -> None:
    """Hand-build a v1 SEAL file (no kind byte) so we can verify backward
    compatibility with files produced by earlier versions of the tool."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(seal.SALT_SIZE)
    nonce_prefix = os.urandom(seal.NONCE_PREFIX_SIZE)
    aes = AESGCM(seal.derive_key(password, salt))

    with open(path, "wb") as f:
        f.write(seal.MAGIC)
        f.write(bytes([seal.VERSION_V1]))   # v1 has NO kind byte
        f.write(salt)
        f.write(nonce_prefix)

        if not plaintext:
            f.write(aes.encrypt(seal._nonce(nonce_prefix, 0, True), b"", None))
            return

        chunks = [plaintext[i:i + seal.CHUNK_SIZE]
                  for i in range(0, len(plaintext), seal.CHUNK_SIZE)]
        for i, chunk in enumerate(chunks):
            is_last = (i == len(chunks) - 1)
            f.write(aes.encrypt(seal._nonce(nonce_prefix, i, is_last), chunk, None))


def test_v1_decrypts_as_file_kind(tmp_path: Path) -> None:
    plaintext = b"hello from a v1 file " * 5000   # multi-chunk
    enc = tmp_path / "old.seal"
    out = tmp_path / "old.out"
    _make_v1_file(enc, plaintext, PW)

    info = seal.peek_info(enc)
    assert info["version"] == 1 and info["kind"] == seal.KIND_FILE

    seal.decrypt_path(enc, out, PW)
    assert out.read_bytes() == plaintext


def test_v1_empty_file(tmp_path: Path) -> None:
    enc = tmp_path / "old-empty.seal"
    out = tmp_path / "old-empty.out"
    _make_v1_file(enc, b"", PW)
    seal.decrypt_path(enc, out, PW)
    assert out.read_bytes() == b""


# =============================================================================
# directory round trips
# =============================================================================

def _make_tree(root: Path) -> None:
    """Build a small directory tree with a few files and subdirs."""
    (root / "top.txt").write_text("top file\n")
    (root / "sub").mkdir()
    (root / "sub" / "a.bin").write_bytes(os.urandom(1234))
    (root / "sub" / "b.txt").write_text("hello\n")
    (root / "sub" / "deep").mkdir()
    (root / "sub" / "deep" / "deep.txt").write_text("deeper\n")
    (root / "empty").mkdir()  # empty subdir


def _tree_snapshot(root: Path) -> dict:
    """Snapshot a directory's contents for comparison."""
    snap: dict = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_file():
            snap[rel] = ("file", p.read_bytes())
        elif p.is_dir():
            snap[rel] = ("dir", None)
    return snap


def test_directory_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "project"; src.mkdir()
    _make_tree(src)
    enc = tmp_path / "project.seal"
    dst = tmp_path / "restored"

    res = seal.encrypt_path(src, enc, PW)
    assert res["kind"] == seal.KIND_DIR

    info = seal.peek_info(enc)
    assert info["kind_name"] == "directory"

    seal.decrypt_path(enc, dst, PW)

    assert _tree_snapshot(src) == _tree_snapshot(dst)


def test_directory_with_large_file(tmp_path: Path) -> None:
    src = tmp_path / "big-dir"; src.mkdir()
    big = os.urandom(3 * seal.CHUNK_SIZE + 7)  # multi-chunk, non-aligned
    (src / "huge.bin").write_bytes(big)
    (src / "small.txt").write_text("small")

    enc = tmp_path / "big.seal"
    dst = tmp_path / "out"

    seal.encrypt_path(src, enc, PW)
    seal.decrypt_path(enc, dst, PW)

    assert (dst / "huge.bin").read_bytes() == big
    assert (dst / "small.txt").read_text() == "small"


def test_directory_decrypt_to_existing_empty_dir(tmp_path: Path) -> None:
    src = tmp_path / "p"; src.mkdir()
    (src / "f.txt").write_text("hi")
    enc = tmp_path / "p.seal"
    dst = tmp_path / "out"; dst.mkdir()  # empty existing dir is OK

    seal.encrypt_path(src, enc, PW)
    seal.decrypt_path(enc, dst, PW)
    assert (dst / "f.txt").read_text() == "hi"


def test_directory_decrypt_to_nonempty_dir_requires_force(tmp_path: Path) -> None:
    src = tmp_path / "p"; src.mkdir()
    (src / "f.txt").write_text("new")
    enc = tmp_path / "p.seal"
    dst = tmp_path / "out"; dst.mkdir()
    (dst / "old.txt").write_text("old")

    seal.encrypt_path(src, enc, PW)

    with pytest.raises(FileExistsError):
        seal.decrypt_path(enc, dst, PW)
    # The existing file must NOT have been touched.
    assert (dst / "old.txt").read_text() == "old"

    # With force=True, it gets replaced.
    seal.decrypt_path(enc, dst, PW, force=True)
    assert (dst / "f.txt").read_text() == "new"
    assert not (dst / "old.txt").exists()


def test_directory_decrypt_failure_leaves_dst_untouched(tmp_path: Path) -> None:
    src = tmp_path / "p"; src.mkdir()
    (src / "f.txt").write_text("hello")
    enc = tmp_path / "p.seal"
    dst = tmp_path / "out"; dst.mkdir()
    (dst / "preexisting.txt").write_text("important")

    seal.encrypt_path(src, enc, PW)

    # Wrong password should fail without touching the existing dst contents.
    with pytest.raises(ValueError):
        seal.decrypt_path(enc, dst, PW + b"x", force=True)
    assert (dst / "preexisting.txt").read_text() == "important"
    assert not (dst / "f.txt").exists()


# =============================================================================
# overwrite / collision behaviour
# =============================================================================

def test_encrypt_refuses_existing_output_without_force(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"; src.write_text("a")
    enc = tmp_path / "a.seal"; enc.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        seal.encrypt_path(src, enc, PW)


def test_encrypt_force_overwrites(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"; src.write_text("new content")
    enc = tmp_path / "a.seal"; enc.write_bytes(b"existing")
    seal.encrypt_path(src, enc, PW, force=True)
    out = tmp_path / "a.out"
    seal.decrypt_path(enc, out, PW)
    assert out.read_text() == "new content"


# =============================================================================
# safe extraction — defense against malicious tarballs
# =============================================================================

def _tarball_with_member(member_name: str, content: bytes = b"x") -> io.BytesIO:
    """Build a minimal in-memory tar.gz containing one file entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|gz") as tf:
        ti = tarfile.TarInfo(name=member_name)
        ti.size = len(content)
        tf.addfile(ti, io.BytesIO(content))
    buf.seek(0)
    return buf


@pytest.mark.parametrize("bad_name", [
    "/etc/passwd",          # absolute path
    "../escape.txt",        # parent traversal
    "ok/../../escape.txt",  # parent traversal hidden in path
    "ok/../sibling.txt",    # would land outside dst
])
def test_safe_extract_rejects_bad_paths(tmp_path: Path, bad_name: str) -> None:
    buf = _tarball_with_member(bad_name)
    dst = tmp_path / "out"
    with tarfile.open(fileobj=buf, mode="r|gz") as tf:
        with pytest.raises(ValueError):
            seal._safe_extract(tf, dst)


def test_safe_extract_accepts_normal_paths(tmp_path: Path) -> None:
    buf = _tarball_with_member("sub/dir/ok.txt", content=b"hello")
    dst = tmp_path / "out"
    with tarfile.open(fileobj=buf, mode="r|gz") as tf:
        seal._safe_extract(tf, dst)
    assert (dst / "sub" / "dir" / "ok.txt").read_bytes() == b"hello"


def test_safe_extract_rejects_unsafe_symlink(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|gz") as tf:
        ti = tarfile.TarInfo(name="evil-link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"   # absolute, escapes destination
        tf.addfile(ti)
    buf.seek(0)
    dst = tmp_path / "out"
    with tarfile.open(fileobj=buf, mode="r|gz") as tf:
        with pytest.raises(ValueError, match="unsafe link"):
            seal._safe_extract(tf, dst)


# =============================================================================
# stream API — ensure encrypt_stream/decrypt_stream still work end-to-end
# =============================================================================

def test_stream_round_trip_file_kind() -> None:
    plaintext = os.urandom(50_000)
    enc = io.BytesIO()
    seal.encrypt_stream(io.BytesIO(plaintext), enc, PW, kind=seal.KIND_FILE)
    enc.seek(0)
    out = io.BytesIO()
    n, kind = seal.decrypt_stream(enc, out, PW)
    assert n == len(plaintext)
    assert kind == seal.KIND_FILE
    assert out.getvalue() == plaintext


def test_stream_round_trip_dir_kind() -> None:
    payload = os.urandom(10_000)
    enc = io.BytesIO()
    seal.encrypt_stream(io.BytesIO(payload), enc, PW, kind=seal.KIND_DIR)
    enc.seek(0)
    out = io.BytesIO()
    n, kind = seal.decrypt_stream(enc, out, PW)
    assert n == len(payload)
    assert kind == seal.KIND_DIR
    assert out.getvalue() == payload


# =============================================================================
# hidden-name mode (KIND_FILE_NAMED)
# =============================================================================

def test_hidden_name_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "secret-document.txt"
    src.write_text("classified contents\n" * 100)
    enc = tmp_path / "vault-XYZ.seal"

    res = seal.encrypt_path(src, enc, PW, hide_name=True)
    assert res["kind"] == seal.KIND_FILE_NAMED
    assert res["embedded_name"] == "secret-document.txt"

    # Output filename reveals nothing.
    assert "secret" not in enc.name

    # Decrypting into a directory uses the embedded name.
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    res2 = seal.decrypt_path(enc, out_dir, PW)
    assert res2["kind"] == seal.KIND_FILE_NAMED
    assert res2["embedded_name"] == "secret-document.txt"
    recovered = out_dir / "secret-document.txt"
    assert recovered.read_text() == "classified contents\n" * 100


def test_hidden_name_decrypt_to_specific_path(tmp_path: Path) -> None:
    src = tmp_path / "original.txt"
    src.write_text("hi")
    enc = tmp_path / "v.seal"
    seal.encrypt_path(src, enc, PW, hide_name=True)

    # When dst is a file path, that path is used and the embedded name
    # is recovered but ignored for output naming.
    explicit = tmp_path / "different-name.txt"
    res = seal.decrypt_path(enc, explicit, PW)
    assert explicit.read_text() == "hi"
    assert res["embedded_name"] == "original.txt"


def test_hidden_name_directory_rejected(tmp_path: Path) -> None:
    src = tmp_path / "d"
    src.mkdir()
    (src / "f").write_text("x")
    with pytest.raises(ValueError, match="only supported for files"):
        seal.encrypt_path(src, tmp_path / "out.seal", PW, hide_name=True)


def test_hidden_name_unicode_filename(tmp_path: Path) -> None:
    src = tmp_path / "日本語.txt"
    src.write_text("unicode!")
    enc = tmp_path / "v.seal"
    seal.encrypt_path(src, enc, PW, hide_name=True)
    out = tmp_path / "out"
    out.mkdir()
    res = seal.decrypt_path(enc, out, PW)
    assert res["embedded_name"] == "日本語.txt"
    assert (out / "日本語.txt").read_text() == "unicode!"


def test_hidden_name_long_filename(tmp_path: Path) -> None:
    long_name = "a" * 200 + ".txt"
    src = tmp_path / long_name
    src.write_text("ok")
    enc = tmp_path / "v.seal"
    seal.encrypt_path(src, enc, PW, hide_name=True)
    out = tmp_path / "out"
    out.mkdir()
    res = seal.decrypt_path(enc, out, PW)
    assert res["embedded_name"] == long_name


def test_safe_basename_strips_path_components() -> None:
    # Basename extraction (no rejection) for these — they're harmless
    # since only the basename is used.
    assert seal._safe_basename("../escape.txt") == "escape.txt"
    assert seal._safe_basename("/etc/passwd") == "passwd"
    assert seal._safe_basename("a/b/c.txt") == "c.txt"
    assert seal._safe_basename("C:\\Windows\\evil.exe") == "evil.exe"


def test_safe_basename_rejects_dangerous_names() -> None:
    for bad in ["", ".", "..", "   ", "\x00", "name\x00with-null"]:
        with pytest.raises(ValueError):
            seal._safe_basename(bad)


def test_hidden_name_with_dotdot_only_payload_rejected(tmp_path: Path) -> None:
    """A maliciously crafted .seal whose embedded name decodes to '..'
    must be rejected at decrypt time."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    pfx = os.urandom(8)
    aes = AESGCM(seal.derive_key(PW, salt))
    evil_name = b".."
    pt = len(evil_name).to_bytes(2, "big") + evil_name + b"x"
    ct = aes.encrypt(seal._nonce(pfx, 0, True), pt, None)

    enc = tmp_path / "evil.seal"
    enc.write_bytes(seal.MAGIC + bytes([seal.VERSION_V2, seal.KIND_FILE_NAMED])
                    + salt + pfx + ct)

    with pytest.raises(ValueError, match="unsafe"):
        seal.decrypt_path(enc, tmp_path / "out", PW)


def test_hidden_name_unknown_kind_rejected(tmp_path: Path) -> None:
    """A SEAL file with an unknown kind byte must be rejected cleanly."""
    enc = tmp_path / "unknown.seal"
    enc.write_bytes(seal.MAGIC + bytes([seal.VERSION_V2, 99])
                    + os.urandom(16) + os.urandom(8) + os.urandom(20))

    with pytest.raises(ValueError, match="unknown SEAL kind"):
        seal.peek_info(enc)


# =============================================================================
# passphrase generation
# =============================================================================

def test_generate_passphrase_default() -> None:
    pw = seal.generate_passphrase()
    parts = pw.split("-")
    assert len(parts) == 5
    for p in parts:
        assert p in seal._WORDLIST


def test_generate_passphrase_custom_words() -> None:
    pw = seal.generate_passphrase(words=8)
    assert len(pw.split("-")) == 8


def test_generate_passphrase_custom_separator() -> None:
    pw = seal.generate_passphrase(words=3, separator="_")
    assert "_" in pw
    assert "-" not in pw
    assert len(pw.split("_")) == 3


def test_generate_passphrase_randomness() -> None:
    """A few hundred passphrases should all be unique."""
    seen = {seal.generate_passphrase() for _ in range(200)}
    assert len(seen) == 200, f"expected 200 unique, got {len(seen)}"


def test_generate_passphrase_invalid_words() -> None:
    with pytest.raises(ValueError):
        seal.generate_passphrase(words=0)


def test_passphrase_entropy_bits() -> None:
    # 1024 = 2^10, so each word is 10 bits.
    assert seal.passphrase_entropy_bits(5) == 50.0
    assert seal.passphrase_entropy_bits(7) == 70.0


def test_wordlist_quality() -> None:
    """All words should be lowercase, no special chars, reasonable length."""
    for w in seal._WORDLIST:
        assert w.isalpha(), f"non-alpha word: {w!r}"
        assert w.islower(), f"non-lowercase word: {w!r}"
        assert 2 <= len(w) <= 8, f"unusual word length: {w!r}"


def test_wordlist_no_duplicates() -> None:
    assert len(seal._WORDLIST) == len(set(seal._WORDLIST))
    assert len(seal._WORDLIST) == 1024
