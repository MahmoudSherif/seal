# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] — 2026

### Added
- **Hidden filename mode** (CLI `--hide-name`, web UI checkbox). The
  original filename is wrapped inside the encrypted payload using a new
  `kind` value `0x02`; the on-disk `.seal` output reveals nothing about
  the input. The recipient gets the real name back on decryption, with
  defensive sanitization (no path components, no `.`/`..`, no control
  chars) so a malicious sender can't write outside the recipient's
  chosen destination.
- **`seal gen-password`** CLI subcommand and **Generate** button in the
  web UI — produces a 5-word passphrase (~50 bits of entropy by default)
  from a 1024-word curated wordlist that's byte-identical between the
  Python and JavaScript implementations.
- **Live password strength meter** in the web UI. Estimates entropy in
  bits and shows a colored weak/fair/good/strong indicator as you type.
- **Self-destruct on success** option in the web UI (on by default).
  After a successful encrypt or decrypt, the password fields are wiped
  and a best-effort clipboard clear is attempted.
- **Page integrity verification.** The deployed page computes a SHA-256
  of all loaded JavaScript and displays it in a footer badge. Users can
  compare it to `web/INTEGRITY.txt` (or run `bash web/verify.sh
  <url>`) to confirm they're running unmodified code. The Pages
  deployment workflow now refuses to deploy if `INTEGRITY.txt` is
  stale, preventing a forgotten regeneration from breaking the
  verification chain.
- 17 new pytest tests covering hidden-name round trips, filename
  sanitization, malicious-payload rejection, and passphrase generation.

### Changed
- File format spec ([`docs/FORMAT.md`](docs/FORMAT.md)) documents the
  new `kind = 0x02` and the `[u16-be name_len][name][content]`
  payload layout.
- Format itself is unchanged for `KIND_FILE` and `KIND_DIR`; v1 and
  v2 files keep working without any flags.

### Security
- Hidden-name files are subject to the same chunk-level authentication
  as regular files. The embedded filename is part of the authenticated
  plaintext, so an attacker who modifies it gets a tag-verification
  failure, not a successful decrypt with a swapped name.

## [3.0.0] — 2026

### Added
- **Web app** (`web/` folder): a fully client-side version of seal that
  runs in any modern browser. Encryption happens locally — passwords
  and files never leave the device. Built to be hosted on GitHub Pages
  with zero configuration.
- **`.github/workflows/pages.yml`**: GitHub Actions workflow that
  publishes `web/` to GitHub Pages on every push to `main`.
- **JS implementation of the SEAL v2 format** (`web/seal.js`): mirrors
  `seal.py` exactly. AES-256-GCM via the Web Crypto API, scrypt via
  vendored scrypt-js, same chunking and nonce scheme.
- **Minimal in-browser tar reader/writer** (`web/tar.js`) and
  **store-only ZIP writer** (`web/zip.js`) for folder mode. Tar
  output is consumed by Python's `tarfile`; tar input handles GNU
  `@LongLink` records produced by Python's writer.
- **Cross-compatibility tests** verifying that files made with the JS
  implementation decrypt with the Python CLI and vice versa, including
  multi-chunk inputs, exact-chunk-boundary edge cases, empty files,
  and tamper/wrong-password rejection.

### Changed
- The `README.md` now describes seal as a single tool with three
  interchangeable interfaces (CLI, GUI, web).

### Backward compatibility
- Format unchanged. Web app produces and consumes SEAL v2 files
  identical to those from the CLI/GUI.

## [2.0.0] — 2026

### Added
- **Native folder encryption.** `seal encrypt mydir/` now produces a single
  `mydir.seal` containing a streamed tar.gz of the directory, and
  `seal decrypt mydir.seal` recreates the directory tree. No more manual
  `tar | seal` piping.
- **`seal info FILE`** subcommand: shows the format version and whether the
  payload is a file or directory, without asking for a password.
- **GUI folder support**: an "Add folder..." button alongside "Add files..."
  lets you queue directories for encryption. The list view now shows the
  kind (file/folder) of each entry.
- **Proper Python packaging.** `pip install .` installs the `seal` and
  `seal-gui` entry-point commands.
- **Pytest test suite** (`tests/test_seal.py`) covering round trips for
  files and directories, tamper/truncation/wrong-password rejection, v1
  backward compatibility, and safe-extraction defenses against malicious
  tarballs.
- **GitHub Actions CI** workflow running tests on Linux + macOS across
  Python 3.10, 3.11, and 3.12.

### Changed
- **File format bumped to v2.** The header now includes a 1-byte `kind`
  field after the version byte (0 = file, 1 = directory archive). Total
  header is 30 bytes (was 29 in v1). See `docs/FORMAT.md`.
- The streaming GUI module is now `seal_gui.py` (was `seal-gui.py`) so
  it can be imported as a Python module by the packaging system. The
  user-facing command name is unchanged: `seal-gui`.

### Backward compatibility
- v1 SEAL files (produced by 1.x) decrypt correctly with no flag changes;
  they're treated as the file kind.

### Security
- Tarball extraction uses a hand-written safe-extract function that
  rejects absolute paths, `..` traversal, device/FIFO entries, and
  symlinks/hardlinks whose targets escape the destination. On Python
  3.12+ we additionally pass `filter='data'` for defense in depth.
- Symlinks are not followed during directory encryption — the contents
  of symlink-pointed-to files are *not* included in the archive, so the
  tool cannot be tricked into reading sensitive files outside the source
  tree.
- Failed directory decryption never modifies the destination: extraction
  happens into a sibling temp directory and is atomically renamed into
  place only on success.

## [1.1.0] — 2026

### Added
- Tkinter desktop GUI (`seal_gui.py`) for queuing multiple files,
  picking an output folder, and running encryption/decryption with a
  progress bar. Errors per file are reported at the end.
- README section on building a standalone executable with PyInstaller.

## [1.0.0] — 2026

### Added
- Initial command-line tool: AES-256-GCM authenticated encryption,
  scrypt key derivation, 64 KB streaming chunks, last-chunk flag bound
  into the AEAD nonce so truncation/extension is detected.
- File-only encryption; directories had to be tarred manually.
