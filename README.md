# seal

> Simple, secure password-based encryption for **files and folders**.
> AES-256-GCM authenticated encryption, scrypt key derivation, streaming
> chunked design — works on inputs of any size.

`seal` ships in three flavors that share the same crypto core and file format:

- **`seal`** — command-line tool, also importable as a Python module.
- **`seal-gui`** — Tkinter desktop GUI for people who don't live in a terminal.
- **web app** — pure client-side site you can host on GitHub Pages and use
  from any browser, anywhere. Your files and password never leave your
  device.

A `.seal` file made with any of the three opens with any of the others.
Linux, macOS, and Windows (WSL or native) are all supported.

---

## Install

```bash
git clone https://github.com/MahmoudSherif/seal.git
cd seal
pip install .
```

That installs both commands: `seal` (CLI) and `seal-gui` (graphical).

For the GUI you'll also need Tkinter. It ships with Python on most systems;
on Debian/Ubuntu/WSL install it explicitly:

```bash
sudo apt install python3-tk
```

If `pip install` complains about PEP 668 on a system Python, use:

```bash
pip install --user --break-system-packages .
```

…or do the install inside a virtualenv (recommended).

---

## Usage — CLI

```bash
# Files
seal encrypt notes.txt              # → notes.txt.seal
seal decrypt notes.txt.seal         # → notes.txt

# Folders (no manual tar needed)
seal encrypt my-project/            # → my-project.seal
seal decrypt my-project.seal        # → my-project/

# Hide the original filename inside the encrypted payload
seal encrypt tax-return.pdf --hide-name -o vault.seal
#   The output 'vault.seal' reveals nothing about the input.
seal decrypt vault.seal -o restored/
#   Recovers tax-return.pdf in the restored/ directory.

# Generate a strong random passphrase
seal gen-password           # → e.g. "rain-solo-rent-scene-wagon" (50 bits entropy)
seal gen-password --words 7 # → 7 words, 70 bits entropy

# Inspect a .seal file without decrypting
seal info vault.seal
#   path:    vault.seal
#   format:  SEAL v2
#   kind:    file (hidden name)
#   size:    18934 bytes

# Custom output paths
seal encrypt secrets.tar -o vault.bin
seal decrypt vault.bin    -o secrets.tar

# Non-interactive (scripts, cron, etc.)
seal encrypt notes.txt -k /path/to/keyfile        # password = first line
echo "$MY_PW" | seal encrypt notes.txt -P         # password from stdin

# Short aliases
seal -e notes.txt            # = seal encrypt notes.txt
seal -d notes.txt.seal       # = seal decrypt notes.txt.seal
```

Useful flags: `-f` to overwrite an existing output, `-q` to suppress progress
messages, `-h` for full help.

For directory mode, `-f` replaces the entire destination directory with the
decrypted contents (the old contents are deleted only after the new ones have
been successfully extracted into a temp dir, so a failed decryption never
damages your existing data).

## Usage — GUI

```bash
seal-gui
```

Or, without installing, just run the script directly:

```bash
python3 seal_gui.py        # from the repo root
```

The GUI lets you queue any mix of files and folders, pick an output
location, and process the whole batch with a single password. Errors on
individual items are reported at the end so a single bad password or
corrupt file doesn't abort the run.

> **WSL note:** the GUI works out of the box on **Windows 11** (WSLg
> handles the display) and on **Windows 10** with an X server like
> VcXsrv or X410 — set `export DISPLAY=:0` first.

## Usage — Web app (runs in any browser)

The `web/` folder is a self-contained, fully **client-side** version of
seal. It runs on GitHub Pages — no backend, no account, no data ever
leaves your device. Encryption happens in your browser using the Web
Crypto API.

To deploy your own copy:

1. Push this repository to GitHub.
2. Open **Settings → Pages**, set **Source** to **GitHub Actions**.
3. Push any change to `main`. The included workflow
   ([`.github/workflows/pages.yml`](.github/workflows/pages.yml))
   publishes `web/` to:
   ```
   https://<your-username>.github.io/<repo-name>/
   ```

Now you can visit that URL from any device with a browser and encrypt
or decrypt files and folders. The same `.seal` files work seamlessly
with the CLI and GUI in either direction.

To run it locally without deploying:

```bash
python3 -m http.server -d web 8080
# open http://localhost:8080/
```

See [`web/README.md`](web/README.md) for more detail on the web app.

---

## What's inside

- **AES-256-GCM** authenticated encryption. Any single-bit change to
  the ciphertext is detected on decryption — you get a clear error
  rather than corrupted plaintext.
- **scrypt** key derivation (`N=2¹⁷, r=8, p=1`, ~128 MiB memory, ~1 second
  on a modern CPU). This is what makes a captured `.seal` file expensive
  to brute-force offline even if your password is mediocre.
- **Random 16-byte salt** per file — encrypting the same plaintext with
  the same password produces a different ciphertext every time.
- **Streaming, chunked** design (64 KiB chunks). Files of any size work
  without loading them into memory. Each chunk is individually
  authenticated, and the *last-chunk flag is bound into the AEAD nonce*
  — so truncation, extension, and chunk-reordering are all detected.
- **Native folder mode**: the directory is streamed as `tar.gz` through
  the same encryption pipeline. No temp files, no disk-space spikes.
  Extraction is done into a sibling temp directory and atomically
  renamed into place, so a failed decryption never leaves you with a
  half-extracted mess.

## What makes this different

Most browser-based encryption tools are a single web page. Most CLI
encryption tools are a single binary. seal is unusual in three ways:

- **One file format, three interfaces.** A `.seal` file made on the
  hosted website opens with the CLI, the desktop GUI, or another
  browser — and vice versa. There's no "import/export between tools."
- **scrypt instead of PBKDF2.** Most browser tools use PBKDF2 with
  10,000 to 600,000 iterations. PBKDF2 is fine but it's GPU-friendly,
  so cheap GPU farms can try billions of passwords per second. scrypt
  needs ~128 MiB of RAM per attempt, which makes GPU/ASIC attacks
  dramatically more expensive.
- **Hidden filename mode.** Add `--hide-name` (or tick the box in the
  web UI) and the output filename reveals nothing about the input —
  even the original name is encrypted inside the payload. The recipient
  gets it back on decryption. Almost no other tool does this.

The web app also includes:

- **Generated passphrases**: click *Generate* for a 5-word ~50-bit
  passphrase (`rain-solo-rent-scene-wagon`). Same wordlist as
  `seal gen-password` on the CLI.
- **Password strength meter**: live feedback on what you typed, with
  weak/fair/good/strong levels.
- **Self-destruct on success**: clears the password fields and
  attempts to wipe the clipboard after each successful operation.
- **Page integrity verification**: the page computes a SHA-256 of all
  the JavaScript it loaded and shows it in a footer badge. Compare
  it to the value in `web/INTEGRITY.txt` (or run `bash web/verify.sh`
  against the deployed URL) to confirm you're running unmodified code.

## What it doesn't do

- No public-key / multi-recipient mode — password only, by design.
- No filename or metadata hiding (the output reveals roughly the size
  of the input, within 16 bytes per 64 KiB chunk).
- No password recovery. Forget the password, lose the data. Use a
  password manager.
- Symlinks inside an encrypted directory are skipped during encryption
  rather than followed, so the tool can't be tricked into archiving
  files outside the source tree.

---

## File format

Brief summary; the full spec is in [`docs/FORMAT.md`](docs/FORMAT.md).

```
v2 header (30 bytes):
  4   magic                "SEAL"
  1   version              0x02
  1   kind                 0x00 = file, 0x01 = directory archive
  16  scrypt salt          random
  8   nonce prefix         random

body: stream of chunks, each = ciphertext(<=64 KiB) || GCM tag(16 B)
  chunk nonce = nonce_prefix(8) || counter_be32(4)
  high bit of counter set on the LAST chunk only
```

v1 (legacy) is identical except it has no `kind` byte and is therefore 29
bytes; v1 files are still decryptable.

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers round trips at every interesting chunk-boundary size,
wrong-password / tampered / truncated / appended-garbage rejection, v1
backward compatibility, native directory round trips (including empty
subdirs and multi-chunk files inside), and safe-extraction defenses
against malicious tarball entries (absolute paths, `..` traversal,
escaping symlinks).

CI runs the suite on Linux + macOS across Python 3.10 / 3.11 / 3.12
on every push — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Build a standalone executable (optional)

If you want a single-file binary you can copy onto another machine
without installing Python or `cryptography`:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name seal-gui seal_gui.py
pyinstaller --onefile             --name seal     seal.py
```

Output goes to `dist/`. **PyInstaller binaries are platform-specific**
— build separately on each OS you want to support. The Python source
itself is portable.

---

## License

MIT — see [`LICENSE`](LICENSE).
