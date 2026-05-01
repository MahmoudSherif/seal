#!/usr/bin/env python3
"""
seal — simple, secure password-based file & folder encryption.

Encrypts files or directories with AES-256-GCM (authenticated encryption)
using a key derived from your password via scrypt. Files are processed in
64 KB chunks so very large inputs work without loading them into memory,
and each chunk is individually authenticated so any tampering, truncation,
or extension is detected on decryption. Directories are streamed as
tar.gz through the same chunked pipeline.

USAGE
    seal encrypt PATH [-o OUTPUT]      # PATH may be a file OR a directory
    seal decrypt FILE [-o OUTPUT]      # auto-detects file vs. directory
    seal info FILE                     # show kind/version, no password needed
    seal -e PATH    /    seal -d FILE  # short aliases

OPTIONS
    -o, --output PATH         Output path. Use "-" for stdout (file mode).
                              Input may also be "-" for stdin (file mode).
    -k, --key-file PATH       Read password from the first line of PATH.
    -P, --password-stdin      Read password from stdin (first line only).
    -f, --force               Overwrite OUTPUT if it already exists.
                              For directories, replaces the existing dir.
    -q, --quiet               Suppress progress messages.
    -h, --help                Show this help and exit.

EXAMPLES
    seal encrypt notes.txt                  # → notes.txt.seal
    seal encrypt my-project/                # → my-project.seal (directory)
    seal decrypt notes.txt.seal             # → notes.txt
    seal decrypt my-project.seal            # → my-project/ (recreated)
    seal info vault.seal                    # → "directory archive, v2"

FILE FORMAT
    See FORMAT.md (or docs/FORMAT.md in the source repo).
    v2 header (30 bytes): magic "SEAL" | version 0x02 | kind (1 B)
                          | scrypt salt (16 B) | nonce prefix (8 B)
    Body: chunks of ciphertext(<=64 KB) || GCM tag(16 B). The high bit
    of the per-chunk counter is set on the LAST chunk only — this binds
    the chunk count into the AEAD so truncation/extension is detected.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    sys.stderr.write(
        "error: missing dependency 'cryptography'.\n"
        "  install with:  pip install cryptography\n"
        "  (or:           pip install --user --break-system-packages cryptography)\n"
    )
    sys.exit(2)


# ---------- format constants ----------
MAGIC = b"SEAL"
VERSION_V1 = 1
VERSION_V2 = 2
CURRENT_VERSION = VERSION_V2

KIND_FILE = 0
KIND_DIR = 1
KIND_FILE_NAMED = 2     # file with filename embedded in encrypted payload
_KIND_NAMES = {
    KIND_FILE: "file",
    KIND_DIR: "directory",
    KIND_FILE_NAMED: "file (hidden name)",
}

# Hidden-name format: plaintext is [u16-be name_len][name bytes][file content].
HIDDEN_NAME_MAX = 0xFFFF        # max bytes for embedded filename

SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
KEY_SIZE = 32           # AES-256
TAG_SIZE = 16           # AES-GCM tag
CHUNK_SIZE = 64 * 1024
ENC_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE
EOF_FLAG = 0x80000000   # set in counter on last chunk
MAX_CHUNKS = EOF_FLAG

# scrypt: ~1s on a modern CPU, ~128 MiB memory. Strong against offline cracking.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024


# ---------- crypto core ----------
def derive_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password, salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM, dklen=KEY_SIZE,
    )


def _nonce(prefix: bytes, counter: int, is_last: bool) -> bytes:
    if counter >= MAX_CHUNKS:
        raise ValueError("input too large for SEAL format")
    flag = EOF_FLAG if is_last else 0
    return prefix + (counter | flag).to_bytes(4, "big")


def encrypt_stream(reader: BinaryIO, writer: BinaryIO, password: bytes,
                   *, kind: int = KIND_FILE) -> int:
    """Encrypt reader → writer in v2 format. Returns plaintext bytes."""
    if kind not in (KIND_FILE, KIND_DIR, KIND_FILE_NAMED):
        raise ValueError(f"invalid kind: {kind}")

    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)

    writer.write(MAGIC)
    writer.write(bytes([CURRENT_VERSION]))
    writer.write(bytes([kind]))
    writer.write(salt)
    writer.write(nonce_prefix)

    aes = AESGCM(derive_key(password, salt))
    counter = 0
    total = 0

    chunk = reader.read(CHUNK_SIZE)
    if not chunk:
        # Empty input: still emit one authenticated empty "last" chunk.
        writer.write(aes.encrypt(_nonce(nonce_prefix, 0, True), b"", None))
        return 0

    while chunk:
        ahead = reader.read(CHUNK_SIZE)
        is_last = not ahead
        writer.write(aes.encrypt(_nonce(nonce_prefix, counter, is_last), chunk, None))
        total += len(chunk)
        counter += 1
        chunk = ahead
    return total


def _read_header(reader: BinaryIO) -> Tuple[int, int, bytes, bytes]:
    """Read a SEAL header, supporting both v1 and v2."""
    head = reader.read(5)
    if len(head) < 5 or head[:4] != MAGIC:
        raise ValueError("not a SEAL file (bad magic / truncated header)")
    version = head[4]

    if version == VERSION_V1:
        rest = reader.read(SALT_SIZE + NONCE_PREFIX_SIZE)
        if len(rest) < SALT_SIZE + NONCE_PREFIX_SIZE:
            raise ValueError("truncated SEAL v1 header")
        return version, KIND_FILE, rest[:SALT_SIZE], rest[SALT_SIZE:]

    if version == VERSION_V2:
        rest = reader.read(1 + SALT_SIZE + NONCE_PREFIX_SIZE)
        if len(rest) < 1 + SALT_SIZE + NONCE_PREFIX_SIZE:
            raise ValueError("truncated SEAL v2 header")
        kind = rest[0]
        if kind not in (KIND_FILE, KIND_DIR, KIND_FILE_NAMED):
            raise ValueError(f"unknown SEAL kind byte: {kind}")
        return version, kind, rest[1:1 + SALT_SIZE], rest[1 + SALT_SIZE:]

    raise ValueError(f"unsupported SEAL version: {version}")


def decrypt_stream(reader: BinaryIO, writer: BinaryIO,
                   password: bytes) -> Tuple[int, int]:
    """Decrypt reader → writer. Returns (plaintext_bytes, kind)."""
    version, kind, salt, nonce_prefix = _read_header(reader)
    aes = AESGCM(derive_key(password, salt))
    counter = 0
    total = 0

    chunk = reader.read(ENC_CHUNK_SIZE)
    if not chunk:
        raise ValueError("truncated SEAL file (no body)")

    while chunk:
        ahead = reader.read(ENC_CHUNK_SIZE)
        is_last = not ahead
        try:
            pt = aes.decrypt(_nonce(nonce_prefix, counter, is_last), chunk, None)
        except InvalidTag:
            raise ValueError(
                "decryption failed: wrong password, or file is corrupted/tampered"
            )
        writer.write(pt)
        total += len(pt)
        counter += 1
        chunk = ahead
    return total, kind


def peek_info(path) -> dict:
    """Return {'version', 'kind', 'kind_name'} without decrypting."""
    with open(path, "rb") as f:
        version, kind, _, _ = _read_header(f)
    return {"version": version, "kind": kind, "kind_name": _KIND_NAMES[kind]}


# ---------- safe tar extraction ----------
def _safe_extract(tf: tarfile.TarFile, dst_dir: Path) -> None:
    """Extract a tar stream into dst_dir, refusing dangerous entries.

    Rejects: absolute paths, paths containing '..', paths that resolve
    outside dst_dir, device/FIFO entries, and links whose target escapes
    dst_dir. Independent of Python's 3.12+ data filter so it works on
    any supported Python version.
    """
    dst = dst_dir.resolve()
    dst.mkdir(parents=True, exist_ok=True)

    for member in tf:
        name = member.name
        if not name or name == ".":
            continue

        # Reject absolute paths or any '..' component.
        parts = Path(name).parts
        if name.startswith(("/", "\\")) or any(p == ".." for p in parts):
            raise ValueError(f"unsafe path in archive: {name!r}")

        target = (dst / name).resolve()
        try:
            target.relative_to(dst)
        except ValueError:
            raise ValueError(f"path escapes destination: {name!r}")

        # Skip special files outright.
        if member.isdev() or member.isfifo():
            continue

        # Validate links stay within dst.
        if member.issym() or member.islnk():
            link_target = (target.parent / member.linkname).resolve()
            try:
                link_target.relative_to(dst)
            except ValueError:
                raise ValueError(
                    f"unsafe link in archive: {name!r} → {member.linkname!r}"
                )

        # On Python 3.12+ also pass the strict 'data' filter for defense in
        # depth. Our own validation above is already sufficient, but the
        # built-in filter rejects the same dangerous shapes and silences
        # the upcoming-default deprecation warning.
        try:
            tf.extract(member, str(dst), filter="data")
        except TypeError:
            tf.extract(member, str(dst))


# ---------- high-level path API ----------
def encrypt_path(src, dst, password: bytes, *, force: bool = False,
                 hide_name: bool = False) -> dict:
    """Encrypt a file or directory. Returns {'kind', 'bytes'}.

    If hide_name=True (file mode only), the original filename is wrapped
    inside the encrypted payload so the on-disk .seal output reveals
    nothing about the original. The recipient gets the real name back
    on decryption.
    """
    src = Path(src)
    dst = Path(dst)

    if not src.exists():
        raise FileNotFoundError(f"no such path: {src}")
    if dst.exists() and not force:
        raise FileExistsError(f"output exists (use force=True): {dst}")

    if src.is_file():
        if hide_name:
            return _encrypt_file_hidden_name(src, dst, password)
        try:
            with open(src, "rb") as fin, open(dst, "wb") as fout:
                n = encrypt_stream(fin, fout, password, kind=KIND_FILE)
        except Exception:
            _silent_unlink(dst)
            raise
        return {"kind": KIND_FILE, "bytes": n}

    if src.is_dir():
        if hide_name:
            raise ValueError("hide_name is only supported for files, not directories")
        return _encrypt_dir(src, dst, password)

    raise ValueError(f"not a regular file or directory: {src}")


def _encrypt_file_hidden_name(src: Path, dst: Path, password: bytes) -> dict:
    """Encrypt src as KIND_FILE_NAMED, embedding src.name in the payload."""
    name_bytes = src.name.encode("utf-8")
    if len(name_bytes) > HIDDEN_NAME_MAX:
        raise ValueError(f"filename too long to embed: {len(name_bytes)} bytes")

    r_fd, w_fd = os.pipe()
    error_box: list = []

    def writer_thread() -> None:
        try:
            with os.fdopen(w_fd, "wb") as w:
                w.write(len(name_bytes).to_bytes(2, "big"))
                w.write(name_bytes)
                with open(src, "rb") as fin:
                    while True:
                        buf = fin.read(CHUNK_SIZE)
                        if not buf:
                            break
                        w.write(buf)
        except BrokenPipeError:
            pass
        except Exception as e:
            error_box.append(e)

    t = threading.Thread(target=writer_thread, daemon=True)
    t.start()

    try:
        with os.fdopen(r_fd, "rb") as r, open(dst, "wb") as fout:
            n = encrypt_stream(r, fout, password, kind=KIND_FILE_NAMED)
    except Exception:
        t.join(timeout=2)
        _silent_unlink(dst)
        raise

    t.join(timeout=10)
    if error_box:
        _silent_unlink(dst)
        raise error_box[0]
    # Report bytes of original content (subtract the name prefix).
    return {"kind": KIND_FILE_NAMED, "bytes": n - 2 - len(name_bytes),
            "embedded_name": src.name}


def _encrypt_dir(src: Path, dst: Path, password: bytes) -> dict:
    """Stream tar.gz of src through encrypt_stream into dst."""
    r_fd, w_fd = os.pipe()
    error_box: list = []

    def writer_thread() -> None:
        try:
            with os.fdopen(w_fd, "wb") as w:
                with tarfile.open(fileobj=w, mode="w|gz") as tf:
                    # Add entries in sorted order for determinism.
                    # Skip symlinks for safety — we don't extract them either.
                    for path in sorted(src.rglob("*")):
                        if path.is_symlink():
                            continue
                        rel = path.relative_to(src).as_posix()
                        if not rel:
                            continue
                        try:
                            tf.add(str(path), arcname=rel, recursive=False)
                        except (OSError, PermissionError) as e:
                            # Skip unreadable entries silently rather than abort
                            # the whole archive.
                            sys.stderr.write(f"warning: skipping {path}: {e}\n")
        except BrokenPipeError:
            # Reader closed early (e.g. encrypt_stream errored); the
            # original error will surface from the main thread.
            pass
        except Exception as e:
            error_box.append(e)

    t = threading.Thread(target=writer_thread, daemon=True)
    t.start()

    try:
        with os.fdopen(r_fd, "rb") as r, open(dst, "wb") as fout:
            n = encrypt_stream(r, fout, password, kind=KIND_DIR)
    except Exception:
        # Drain the pipe so the writer thread can exit cleanly.
        t.join(timeout=2)
        _silent_unlink(dst)
        raise

    t.join(timeout=10)
    if error_box:
        _silent_unlink(dst)
        raise error_box[0]
    return {"kind": KIND_DIR, "bytes": n}


def decrypt_path(src, dst, password: bytes, *, force: bool = False) -> dict:
    """Decrypt src to dst. Auto-detects file vs. directory mode from the
    SEAL header. For directory mode, dst is the directory to (re)create.

    For KIND_FILE_NAMED, dst may be either a file path or a directory.
    If dst is a directory (or None), the embedded filename is used.
    The embedded filename is sanitized: any path components are stripped
    so a malicious archive can't write outside dst's parent.
    """
    src = Path(src)

    if not src.is_file():
        raise FileNotFoundError(f"not a file: {src}")

    info = peek_info(src)
    kind = info["kind"]

    if kind == KIND_FILE:
        dst = Path(dst)
        if dst.exists() and not force:
            raise FileExistsError(f"output exists (use force=True): {dst}")
        if dst.is_dir():
            raise IsADirectoryError(
                f"output exists as a directory, refusing to overwrite: {dst}"
            )
        try:
            with open(src, "rb") as fin, open(dst, "wb") as fout:
                n, _ = decrypt_stream(fin, fout, password)
        except Exception:
            _silent_unlink(dst)
            raise
        return {"kind": KIND_FILE, "bytes": n}

    if kind == KIND_FILE_NAMED:
        return _decrypt_file_hidden_name(src, dst, password, force=force)

    if kind == KIND_DIR:
        return _decrypt_dir(src, Path(dst), password, force=force)

    raise ValueError(f"unknown SEAL kind: {kind}")


def _safe_basename(name: str) -> str:
    """Strip any directory components and reject empty/dangerous names."""
    # Take only the basename, defending against both '/' and '\' separators.
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not base or base in (".", ".."):
        raise ValueError(f"embedded filename is unsafe: {name!r}")
    # Reject NUL and control characters.
    if any(ord(c) < 0x20 for c in base):
        raise ValueError(f"embedded filename contains control characters: {name!r}")
    return base


def _decrypt_file_hidden_name(src: Path, dst, password: bytes,
                              *, force: bool) -> dict:
    """Decrypt KIND_FILE_NAMED, recovering the embedded filename.

    `dst` may be:
      - a directory (or None): write to <dir>/<embedded_name>
      - a file path: write to that path, ignoring the embedded name
    """
    # Decrypt to a temp file first so we can read the name header
    # before deciding the final destination.
    parent = (Path(dst).parent if dst and not Path(dst).is_dir()
              else Path(dst) if dst else Path("."))
    parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".seal-decrypt-", dir=str(parent))
    tmp_path = Path(tmp_path)
    try:
        with open(src, "rb") as fin, os.fdopen(tmp_fd, "wb") as tmp_out:
            decrypt_stream(fin, tmp_out, password)

        # Read the embedded name header from the start of the temp file,
        # then split into name + content.
        with open(tmp_path, "rb") as f:
            header = f.read(2)
            if len(header) < 2:
                raise ValueError("hidden-name payload too short")
            name_len = int.from_bytes(header, "big")
            name_bytes = f.read(name_len)
            if len(name_bytes) < name_len:
                raise ValueError("hidden-name payload truncated")
            try:
                embedded_name = name_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("embedded filename is not valid UTF-8")
            safe_name = _safe_basename(embedded_name)

            # Determine final destination.
            if dst is None:
                final = Path(".") / safe_name
            else:
                dst_path = Path(dst)
                if dst_path.is_dir():
                    final = dst_path / safe_name
                else:
                    final = dst_path

            if final.exists() and not force:
                raise FileExistsError(
                    f"output exists (use force=True): {final}"
                )
            if final.is_dir():
                raise IsADirectoryError(
                    f"output exists as a directory: {final}"
                )

            # Stream the rest of the temp file to the final destination.
            content_bytes = 0
            with open(final, "wb") as fout:
                while True:
                    buf = f.read(CHUNK_SIZE)
                    if not buf:
                        break
                    fout.write(buf)
                    content_bytes += len(buf)

        return {"kind": KIND_FILE_NAMED, "bytes": content_bytes,
                "embedded_name": embedded_name, "safe_name": safe_name,
                "output_path": final}
    finally:
        _silent_unlink(tmp_path)


def _decrypt_dir(src: Path, dst: Path, password: bytes,
                 *, force: bool) -> dict:
    """Stream-decrypt src into a temp dir, then atomically swap into dst."""
    if dst.exists() and not dst.is_dir():
        raise NotADirectoryError(f"output exists and is not a directory: {dst}")
    if dst.exists() and any(dst.iterdir()) and not force:
        raise FileExistsError(
            f"output directory is not empty (use force=True): {dst}"
        )

    # Extract into a sibling temp dir so a failed extraction never
    # touches the user's existing data.
    parent = dst.parent if dst.parent != Path("") else Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    tmp_root = Path(tempfile.mkdtemp(prefix=".seal-extract-", dir=str(parent)))

    r_fd, w_fd = os.pipe()
    error_box: list = []

    def decrypt_thread() -> None:
        try:
            with open(src, "rb") as fin, os.fdopen(w_fd, "wb") as w:
                decrypt_stream(fin, w, password)
        except BrokenPipeError:
            pass
        except Exception as e:
            error_box.append(e)

    t = threading.Thread(target=decrypt_thread, daemon=True)
    t.start()

    try:
        with os.fdopen(r_fd, "rb") as r:
            try:
                with tarfile.open(fileobj=r, mode="r|gz") as tf:
                    _safe_extract(tf, tmp_root)
            except (tarfile.TarError, EOFError):
                # If decryption failed, that error is what the user wants
                # to see; don't mask it with a tar-format error.
                t.join(timeout=2)
                if error_box:
                    raise error_box[0]
                raise
    except Exception:
        t.join(timeout=2)
        shutil.rmtree(tmp_root, ignore_errors=True)
        if error_box and not isinstance(sys.exc_info()[1], type(error_box[0])):
            raise error_box[0]
        raise

    t.join(timeout=10)
    if error_box:
        shutil.rmtree(tmp_root, ignore_errors=True)
        raise error_box[0]

    # Swap into place: rmtree existing dst (only if force confirmed empty
    # / overwrite earlier), then rename tmp_root → dst.
    try:
        if dst.exists():
            shutil.rmtree(dst)
        tmp_root.rename(dst)
    except Exception:
        shutil.rmtree(tmp_root, ignore_errors=True)
        raise

    return {"kind": KIND_DIR, "bytes": 0}


def _silent_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


# ---------- password sourcing ----------
def get_password(args, *, confirm: bool) -> bytes:
    if args.key_file:
        try:
            with open(args.key_file, "rb") as f:
                pw = f.readline().rstrip(b"\r\n")
        except OSError as e:
            sys.exit(f"error: cannot read key file: {e}")
        if not pw:
            sys.exit("error: key file is empty")
        return pw

    if args.password_stdin:
        if args.input == "-":
            sys.exit("error: --password-stdin cannot be used with stdin input")
        line = sys.stdin.buffer.readline()
        pw = line.rstrip(b"\r\n")
        if not pw:
            sys.exit("error: empty password on stdin")
        return pw

    try:
        pw = getpass.getpass("password: ").encode("utf-8")
    except (EOFError, KeyboardInterrupt):
        sys.exit("\nerror: no password provided")
    if not pw:
        sys.exit("error: empty password")
    if confirm:
        try:
            pw2 = getpass.getpass("confirm:  ").encode("utf-8")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nerror: cancelled")
        if pw != pw2:
            sys.exit("error: passwords do not match")
    return pw


# ---------- passphrase generation ----------
# Curated list of 1024 common, short, easily-typed English words. log2(1024) = 10
# bits of entropy per word, so a 5-word passphrase has 50 bits, which combined
# with scrypt (~128 MiB memory per attempt) is computationally infeasible to
# brute-force. Words chosen to be 3–6 chars, unambiguous when read aloud, and
# unlikely to collide with autocorrect.
_WORDLIST = (
    "able acid aged also area army away baby back bake "
    "ball band bank bare barn base bath bear beat been "
    "bell belt bend best bike bill bind bird bite blue "
    "boat body bold bone book boot born both bowl brave "
    "bread brick bring broad brown buddy bulk bull burn bush "
    "busy cabin cake calm camp cane cape card care cash "
    "cast cave cell chain chair chalk chart cheap check cheek "
    "cheer chest chief child chill chip chop city clay clean "
    "clear cliff climb cloak clock close cloud club clue coach "
    "coal coast coat code coin cold come cook cool copy "
    "corn cost couch cough count court cover crab craft crane "
    "crash cream creek crew crisp crop cross crowd crown cube "
    "cup curl dance dare dark dart data dawn deal dear "
    "deep deer desk dial diet dime dine dirt dish dive "
    "dock door dose dove dozen draft drag draw dream drift "
    "drill drink drive drop drum duck dust eager early earn "
    "earth east easy edge eight elbow elder empty enemy enjoy "
    "enter entry equal even ever evil exit fable face fact "
    "fade fair faith fall fame farm fast favor fear feast "
    "feed feel fence ferry few field fifth fight final finch "
    "find fine fire firm first fish five flag flame flash "
    "flat flax flesh float flock flood floor flour flow fluid "
    "flute fly foam focus fog fold folk food foot ford "
    "forge form fort found four fox frame free fresh frog "
    "front frost fruit fuel full fun fund game gap gate "
    "gaze gear gem gift give glad glass globe glove glow "
    "goal gold golf good goose grab grace grade grain grand "
    "grant grape grass gray great green grid grin grip groom "
    "group grow guard guess guest guide gulf hail hair half "
    "hall halt hand happy hard harp hash haste hatch have "
    "hawk haze head heap hear heart heat help herb here "
    "hero hide high hill hint hire hold hole holy home "
    "honey hood hook hope horn horse hotel hour house huge "
    "human humor hunt hurry husk ice idea idle inch ink "
    "inn iron item ivory ivy jade jail jaw jazz jeep "
    "jelly jet jewel join joke joy judge juice jump junior "
    "just keen keep kept key kick kid kind king kiss "
    "kite knee knife knit knob knock know lab lace lady "
    "lake lamb lamp land lane large lark last late laugh "
    "lava law lawn layer lazy lead leaf lean learn leash "
    "least leave left lemon lend lens less life lift light "
    "like lily lime limit line link lion lip list live "
    "load loaf lobby local lock log lone long loop lose "
    "lost lot loud love loyal luck lump lunar lunch lung "
    "lure lyric magic maid main make mango many maple march "
    "mark marsh mask mass mast match meal mean meat medal "
    "melt member memo mend menu merit merry metal might milk "
    "mill mind mine mint mist mode model mole monk month "
    "moon morse most moth motor mount mouse mouth move much "
    "mud muse music must myth nail name nap navy near "
    "neat neck need nest never news next nice night nine "
    "noble noise none north nose note novel now nurse nut "
    "oak oasis oat oats ocean odd offer often oil okay "
    "olive once onion only open opera opt orange orbit other "
    "otter ounce out oval oven over owl own oxide pace "
    "pack page paid pail pain paint pair palm pan panda "
    "paper park part pass past patch path peace peach pear "
    "peer pen penny perch piano pick pie pill pilot pinch "
    "pine pink pipe pitch pixel pizza place plain plan plant "
    "plate play plot plug plum poem poet point poll polo "
    "pool poppy port pose post pouch pound power press pride "
    "print prize proud prune pulp pulse pump pure push quail "
    "quart queen quest quick quiet quill quilt quite quote rabbit "
    "race radio rage rail rain raise rake ramp ranch rapid "
    "rare rat rate raven raw reach read ready real rebel "
    "reef relax relay relic rely remix rent reply reset rest "
    "rice rich ride rifle right rigid ring rinse ripe rise "
    "risk rival river road robe robin rock rocky rod role "
    "roof room root rope rose rough round route royal ruby "
    "rude rug ruin rule run rural rush rust safe sage "
    "sail saint salad salt same sand save scale scarf scene "
    "scent scout sea seal seam search seat seed seek seem "
    "seize sell send sense serve seven shade shake shape share "
    "sharp shawl sheep shelf shell shine ship shirt shoe shop "
    "shore short shout show shown shrub side sigh sight silk "
    "silly silo silver sing sink sip site six size skate "
    "ski skill skin skip skirt sky slab slack slam slate "
    "sleep sleet slice slim slip slope slot slow small smart "
    "smile smoke snake snap snow soap soft soil sold solid "
    "solo solve some song soon sort soul soup sour space "
    "spade spare spark speak speed spell spend spice spike spin "
    "spine spire splat split spoke spoon sport spot spray spree "
    "spring spy stack stage stair stamp stand star stark start "
    "stash state stay steam steel steep stem step stern stick "
    "still sting stir stock stone stop store storm story stove "
    "straw stream street strict stride strike string strong study stuff "
    "stump style such suds sugar sulky summer sun sunny super "
    "swamp swan swap sweat sweep sweet swift swim swing sword "
    "table tail take talk tall tame tank tape task taste "
    "teach team tear teeth tell ten tent term test text "
    "than that thaw their them then there these they thick "
    "thin thing think third this thorn those thread three throat "
    "throw thumb tide tidy tie tiger tight tile time tin "
    "tiny tip tire title toast today toe tonic tool tooth "
    "top torch total touch tour tower town toxic toy track "
    "trade trail train trap travel tray treat tree trek trial "
    "tribe trick trip troop truck true trunk trust truth try "
    "tube tuna tune turf turn tutor twin twist two type "
    "ugly umpire under unit until upon urge urn use user "
    "usual valid value vapor vary vase vast vault verb verse "
    "very vest video view vine vinyl visit vivid vocal voice "
    "volt vote vow wade wage wagon wait wake walk wall "
    "walnut wand want ward "
).split()

assert len(_WORDLIST) == 1024, f"wordlist size is {len(_WORDLIST)}, expected 1024"


def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    """Generate a random passphrase using the embedded wordlist.

    Each word contributes 9 bits of entropy. Default of 5 words gives 45 bits,
    which is computationally infeasible to brute-force given the scrypt KDF.

    Uses os.urandom for cryptographic randomness.
    """
    if words < 1:
        raise ValueError("words must be at least 1")
    chosen = []
    n = len(_WORDLIST)
    for _ in range(words):
        # Unbiased uniform selection from a 1024-word list: 1024 divides
        # 65536 cleanly so any 16-bit value mod 1024 is uniform.
        idx = int.from_bytes(os.urandom(2), "big") % n
        chosen.append(_WORDLIST[idx])
    return separator.join(chosen)


def passphrase_entropy_bits(words: int) -> float:
    """Bits of entropy in a passphrase of `words` words from this wordlist."""
    import math
    return words * math.log2(len(_WORDLIST))


# ---------- file plumbing for stdin/stdout file mode ----------
def _open_input_file(path: str) -> BinaryIO:
    if path == "-":
        return sys.stdin.buffer
    p = Path(path)
    if not p.is_file():
        sys.exit(f"error: not a file: {p}")
    return p.open("rb")


def _open_output_file(path: str, force: bool) -> BinaryIO:
    if path == "-":
        return sys.stdout.buffer
    p = Path(path)
    if p.exists() and not force:
        sys.exit(f"error: output exists (use -f to overwrite): {p}")
    return p.open("wb")


def _close_if_file(stream: BinaryIO) -> None:
    if stream not in (sys.stdin.buffer, sys.stdout.buffer):
        try:
            stream.close()
        except Exception:
            pass


# ---------- commands ----------
def _default_encrypt_output(input_path: str) -> str:
    p = Path(input_path)
    # Strip any trailing slash for clean naming.
    return str(p.with_name(p.name + ".seal"))


def _default_decrypt_output(input_path: str) -> str:
    if input_path.endswith(".seal"):
        return input_path[: -len(".seal")]
    return input_path + ".dec"


def cmd_encrypt(args) -> int:
    if not args.input:
        sys.exit("error: input path is required")

    # Streaming-pipe mode (input or output is "-"): force file kind.
    streaming = args.input == "-" or (args.output is not None and args.output == "-")

    if args.hide_name and streaming:
        sys.exit("error: --hide-name cannot be combined with stdin/stdout streaming")

    if args.output is None:
        if args.input == "-":
            sys.exit("error: -o/--output is required when reading from stdin")
        if args.hide_name:
            # Default to a generic, contents-revealing-nothing output name
            # in the same directory as the input.
            src_path = Path(args.input)
            args.output = str(src_path.with_name("vault.seal"))
        else:
            args.output = _default_encrypt_output(args.input)

    password = get_password(args, confirm=True)

    if streaming:
        in_file = _open_input_file(args.input)
        out_file = _open_output_file(args.output, args.force)
        if not args.quiet and args.output != "-":
            sys.stderr.write("deriving key (this takes about a second)...\n")
        try:
            n = encrypt_stream(in_file, out_file, password, kind=KIND_FILE)
        finally:
            _close_if_file(in_file)
            _close_if_file(out_file)
        if not args.quiet and args.output != "-":
            sys.stderr.write(f"encrypted {n} bytes → {args.output}\n")
        return 0

    src = Path(args.input)
    dst = Path(args.output)
    if not src.exists():
        sys.exit(f"error: no such path: {src}")
    if dst.exists() and not args.force:
        sys.exit(f"error: output exists (use -f to overwrite): {dst}")

    if args.hide_name and src.is_dir():
        sys.exit("error: --hide-name only applies to files, not directories")

    if not args.quiet:
        sys.stderr.write("deriving key (this takes about a second)...\n")
        if src.is_dir():
            sys.stderr.write(f"archiving directory {src}...\n")
        if args.hide_name:
            sys.stderr.write(f"hiding original name '{src.name}' inside payload...\n")

    try:
        result = encrypt_path(src, dst, password,
                              force=args.force, hide_name=args.hide_name)
    except Exception as e:
        sys.exit(f"error: {e}")

    if not args.quiet:
        kind_name = _KIND_NAMES[result["kind"]]
        sys.stderr.write(
            f"encrypted {result['bytes']} bytes ({kind_name}) → {dst}\n"
        )
    return 0


def cmd_decrypt(args) -> int:
    if not args.input:
        sys.exit("error: input path is required")

    streaming = args.input == "-" or (args.output is not None and args.output == "-")

    # For non-streaming mode, peek the kind to decide default output behavior.
    peeked_kind = None
    if not streaming and args.input != "-":
        try:
            peeked_kind = peek_info(args.input)["kind"]
        except (ValueError, OSError):
            peeked_kind = None  # let the real decrypt path surface the error

    if args.output is None:
        if args.input == "-":
            sys.exit("error: -o/--output is required when reading from stdin")
        if peeked_kind == KIND_FILE_NAMED:
            # Default: write into current directory; embedded name is used.
            args.output = "."
        else:
            args.output = _default_decrypt_output(args.input)

    password = get_password(args, confirm=False)

    if streaming:
        in_file = _open_input_file(args.input)
        out_file = _open_output_file(args.output, args.force)
        if not args.quiet and args.output != "-":
            sys.stderr.write("deriving key (this takes about a second)...\n")
        try:
            try:
                n, kind = decrypt_stream(in_file, out_file, password)
            except ValueError as e:
                _close_if_file(out_file)
                if args.output != "-":
                    _silent_unlink(Path(args.output))
                sys.exit(f"error: {e}")
            if kind != KIND_FILE:
                sys.stderr.write(
                    "warning: this SEAL file is a directory archive; "
                    "decrypted bytes are tar.gz data.\n"
                )
        finally:
            _close_if_file(in_file)
            _close_if_file(out_file)
        if not args.quiet and args.output != "-":
            sys.stderr.write(f"decrypted {n} bytes → {args.output}\n")
        return 0

    src = Path(args.input)
    dst = Path(args.output)
    if not src.is_file():
        sys.exit(f"error: not a file: {src}")

    if not args.quiet:
        sys.stderr.write("deriving key (this takes about a second)...\n")

    try:
        result = decrypt_path(src, dst, password, force=args.force)
    except Exception as e:
        sys.exit(f"error: {e}")

    if not args.quiet:
        kind_name = _KIND_NAMES[result["kind"]]
        if result["kind"] == KIND_DIR:
            sys.stderr.write(f"decrypted directory → {dst}/\n")
        elif result["kind"] == KIND_FILE_NAMED:
            sys.stderr.write(
                f"decrypted {result['bytes']} bytes (hidden name '{result['embedded_name']}') "
                f"→ {result['output_path']}\n"
            )
        else:
            sys.stderr.write(
                f"decrypted {result['bytes']} bytes ({kind_name}) → {dst}\n"
            )
    return 0


def cmd_info(args) -> int:
    if not args.input:
        sys.exit("error: input path is required")
    src = Path(args.input)
    if not src.is_file():
        sys.exit(f"error: not a file: {src}")
    try:
        info = peek_info(src)
    except ValueError as e:
        sys.exit(f"error: {e}")
    print(f"path:    {src}")
    print(f"format:  SEAL v{info['version']}")
    print(f"kind:    {info['kind_name']}")
    print(f"size:    {src.stat().st_size} bytes")
    return 0


def cmd_gen_password(args) -> int:
    if args.words < 1:
        sys.exit("error: --words must be at least 1")
    pw = generate_passphrase(words=args.words)
    print(pw)
    if not args.quiet:
        bits = passphrase_entropy_bits(args.words)
        sys.stderr.write(
            f"({args.words} words, ~{bits:.0f} bits of entropy)\n"
        )
    return 0


# ---------- CLI ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seal",
        description="Encrypt or decrypt files and folders with a password "
                    "(AES-256-GCM + scrypt).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
short-form aliases:
  -e is the same as `encrypt`
  -d is the same as `decrypt`

examples:
  seal encrypt notes.txt              # -> notes.txt.seal
  seal encrypt my-project/            # -> my-project.seal (folder)
  seal encrypt notes.txt --hide-name -o vault.seal   # original name hidden
  seal decrypt notes.txt.seal         # -> notes.txt
  seal decrypt vault.seal             # -> recovers original name
  seal decrypt my-project.seal        # -> my-project/
  seal info vault.seal                # show kind/version, no password
  seal gen-password                   # generate a strong random passphrase
""",
    )
    p.add_argument("command", choices=["encrypt", "decrypt", "info", "gen-password"],
                   help="action: encrypt, decrypt, info, or gen-password")
    p.add_argument("input", nargs="?",
                   help='input path. for encrypt: file or directory '
                        '(or "-" for stdin, file mode only). '
                        'for decrypt: a .seal file (or "-" for stdin). '
                        'omitted for gen-password.')
    p.add_argument("-o", "--output",
                   help='output path, or "-" for stdout (file mode only). '
                        "default: add/strip .seal")
    p.add_argument("-k", "--key-file",
                   help="read password from first line of this file")
    p.add_argument("-P", "--password-stdin", action="store_true",
                   help="read password from stdin (first line only)")
    p.add_argument("-f", "--force", action="store_true",
                   help="overwrite output if it exists")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress messages")
    p.add_argument("--hide-name", action="store_true",
                   help="(encrypt only) hide the original filename inside "
                        "the encrypted payload; the .seal output reveals "
                        "nothing about the original name")
    p.add_argument("--words", type=int, default=5,
                   help="(gen-password) number of words in the passphrase "
                        "(default: 5)")
    return p


def _expand_short_aliases(argv: list) -> list:
    out = list(argv)
    aliases = {"-e": "encrypt", "--encrypt": "encrypt",
               "-d": "decrypt", "--decrypt": "decrypt"}
    seen = False
    for i, a in enumerate(out):
        if a in aliases:
            if seen:
                sys.exit("error: specify -e/-d (or encrypt/decrypt) only once")
            out[i] = aliases[a]
            seen = True
    return out


def main(argv: Optional[list] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = _expand_short_aliases(argv)
    args = build_parser().parse_args(argv)

    if args.command == "encrypt":
        return cmd_encrypt(args)
    if args.command == "decrypt":
        return cmd_decrypt(args)
    if args.command == "info":
        return cmd_info(args)
    if args.command == "gen-password":
        return cmd_gen_password(args)
    return 2  # unreachable


if __name__ == "__main__":
    sys.exit(main())
