# seal — web app

A fully **client-side** version of the seal encryption tool that runs in your
browser. Drop a file or folder, type a password, get a `.seal` file back.
Open `.seal` files made on the website with the CLI/GUI and vice versa —
it's all the same format.

## Features

- **Files and folders** — drag-drop a single file or a whole folder; the
  folder gets packed as `tar.gz` in the browser before encryption.
- **Hide original filename** — checkbox option that wraps the original
  filename inside the encrypted payload. The output reveals nothing
  about the input; the recipient gets the real name back on decryption.
- **Generate passphrase** — click the *Generate* button for a 5-word
  random passphrase (~50 bits of entropy) drawn from a 1024-word
  curated list. Same wordlist as `seal gen-password` on the CLI.
- **Live strength meter** — colored bar showing the estimated entropy
  of whatever you typed (weak / fair / good / strong).
- **Self-destruct on success** — clears the password fields and
  best-effort wipes the clipboard after each successful operation.
  On by default.
- **Page integrity verification** — the page computes a SHA-256 of all
  the JavaScript it loaded and shows it in a footer badge. Compare to
  `web/INTEGRITY.txt` to confirm the deployed bytes match the source.

## Privacy

Everything happens in your browser. Your files and password **never leave
your device**. There is no server to send them to — GitHub Pages only
serves static files. Open the page once, then disconnect from the
network: encryption and decryption still work.

You can verify this yourself:

1. Open the deployed site, then open your browser's developer tools.
2. Watch the Network tab while encrypting. After the initial page load
   (HTML, CSS, JS, fonts), no requests are made.

## Verifying the page hasn't been tampered with

The deployed site shows a SHA-256 hash of all loaded JavaScript at the
bottom of the page (the "Verify this page" badge). To check it matches
the source:

```bash
# Verify the published deployment matches the repo:
bash web/verify.sh https://your-username.github.io/seal/

# Or verify your local copy:
bash web/verify.sh
```

The hash should match what's at the top of `INTEGRITY.txt` and what the
deployed page displays. If anything differs, something has changed —
either the repo was updated (regenerate `INTEGRITY.txt`), or someone
modified the deployed code.

The Pages deployment workflow refuses to deploy if `INTEGRITY.txt` is
stale, so a forgotten regeneration can never break this verification.

## Deploying to GitHub Pages

The repository ships with a workflow at `.github/workflows/pages.yml`
that automatically publishes this folder to GitHub Pages on every push
to `main`.

To enable it once after forking/cloning:

1. Go to your repository's **Settings → Pages**.
2. Under **Source**, choose **GitHub Actions**.
3. Push any change. The workflow runs and publishes to:
   ```
   https://<your-username>.github.io/<repo-name>/
   ```

That's it — no build step, no backend, no environment variables.

## Running locally

The page can be opened straight from the filesystem in some browsers,
but Web Crypto requires a "secure context", so the most reliable way is
to serve it on `localhost`:

```bash
python3 -m http.server -d web 8080
# open http://localhost:8080/
```

Or with Node:

```bash
npx serve web
```

## What's in this folder

```
web/
├── index.html          Single-page UI
├── app.js              UI controller (drag/drop, mode switching, downloads)
├── seal.js             SEAL v2 format implementation in JavaScript
├── tar.js              Minimal tar reader/writer for folder mode
├── zip.js              Store-only ZIP writer for delivering decrypted folders
├── verify.sh           Recompute the page integrity hash from any URL or folder
├── INTEGRITY.txt       Expected SHA-256 of the JS bundle (updated by CI)
├── vendor/
│   ├── scrypt.js       scrypt-js@3 (MIT) — for KDF
│   ├── pako.min.js     pako@2 (MIT and Zlib) — for gzip
│   └── scrypt.LICENSE.txt
└── tests/              Node-based cross-compat tests vs. the Python tool
```

## Format compatibility

A `.seal` file made by this web app is **byte-compatible** with a file
made by the `seal` CLI or GUI. The same crypto stack is used end to end:

- AES-256-GCM with 64 KiB chunks, individually authenticated
- The "last chunk" flag is bound into the AEAD nonce, so truncation
  and extension are detected
- scrypt with `N=2¹⁷, r=8, p=1` for key derivation
- Same magic, header layout, and chunk format described in
  [`docs/FORMAT.md`](../docs/FORMAT.md)
- Three kinds of payload: `file` (0x00), `directory` (0x01),
  `file with hidden name` (0x02)

## Limitations

- **In-memory operation.** The whole input is held in the browser while
  encrypting/decrypting. For files larger than a few hundred MB, prefer
  the CLI.
- **Folder paths must be ≤99 bytes** when encrypting in the browser.
  Longer paths require GNU tar extensions; the CLI handles them
  automatically. Decrypting Python-made folders with long paths *does*
  work — the JS reader handles GNU `@LongLink` records.
- **Folder decryption returns a `.zip`.** Browsers can't write a folder
  tree to disk reliably across all platforms, so we deliver the decoded
  contents in a ZIP file you can extract with your OS's built-in
  unzipper. (The original tar.gz format is preserved internally, so
  decrypting on the CLI gives you the directory directly.)
- **Web Crypto needs HTTPS or localhost.** GitHub Pages always serves
  over HTTPS, so this is automatic for the deployed site. If you copy
  the files elsewhere, serve them via HTTPS or `http://localhost`.

## Browser support

Tested on current versions of Chrome, Edge, Firefox, and Safari.
Requires:
- Web Crypto API (universal since ~2017)
- `Blob` and `File.slice` (universal)
- `webkitGetAsEntry` for dropped folders (Chrome, Edge, Firefox; Safari
  14+) — drag/drop of single files works everywhere

## Running the cross-compatibility tests

The `tests/` folder contains Node scripts that verify the JS
implementation produces and consumes the exact same bytes as the Python
tool. Single-shot helpers:

```bash
# JS encrypts a file; CLI decrypts.
node tests/js_encrypt.mjs input.bin out.seal "my password"
python3 ../seal.py decrypt out.seal -o roundtrip.bin -P -q -f <<< "my password"
diff input.bin roundtrip.bin     # should produce no output

# CLI encrypts a file; JS decrypts.
python3 ../seal.py encrypt input.bin -o encrypted.seal -P -q -f <<< "my password"
node tests/js_decrypt.mjs encrypted.seal roundtrip.bin "my password"
```

These succeed for files of any size and verify that "the same tool" is
really the same tool in all three forms.
