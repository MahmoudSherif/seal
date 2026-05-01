// Cross-compatibility test for the JS implementation against seal.py.
// Run with:  node tests/test_crosscompat.mjs

import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const exec = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');         // web/
const REPO = resolve(ROOT, '..');               // seal-repo/

// Load the vendored libs into a fake "window" + import seal.js.
// Node 18+ has Web Crypto on globalThis.crypto.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
globalThis.window = globalThis;     // make seal.js happy
// scrypt-js's UMD shim exports via CommonJS under Node, so we have to
// attach it to the global ourselves to mimic the browser environment.
const scryptLib = require(resolve(ROOT, 'node_modules/scrypt-js/scrypt.js'));
globalThis.scrypt = scryptLib;
require(resolve(ROOT, 'seal.js'));
const seal = globalThis.seal;

let pass = 0, fail = 0;
function check(label, ok, details = '') {
    if (ok) { console.log('  ✓ ' + label); pass++; }
    else    { console.log('  ✗ ' + label + (details ? '\n      ' + details : '')); fail++; }
}

function blobFromBytes(bytes) {
    return new Blob([bytes]);
}
async function blobToBytes(blob) {
    return new Uint8Array(await blob.arrayBuffer());
}
function randomBytes(n) {
    const out = new Uint8Array(n);
    // crypto.getRandomValues is limited to 65536 bytes per call.
    for (let off = 0; off < n; off += 65536) {
        crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
    }
    return out;
}

const PASSWORD = 'correct horse battery staple';
const PW_BYTES = new TextEncoder().encode(PASSWORD);

const tmp = join(tmpdir(), 'seal-crosscompat-' + Date.now());
await mkdir(tmp, { recursive: true });

console.log('\n=== JS encrypt → Python decrypt ===');

for (const [size, label] of [
    [0, 'empty'],
    [1, 'one byte'],
    [1024, '1 KiB'],
    [seal.CHUNK_SIZE - 1, 'just under one chunk'],
    [seal.CHUNK_SIZE, 'exact chunk boundary'],
    [seal.CHUNK_SIZE + 1, 'just over one chunk'],
    [3 * seal.CHUNK_SIZE + 17, 'multi-chunk + remainder'],
]) {
    // Random plaintext of `size` bytes.
    const plaintext = randomBytes(size);
    /* set below */

    // 1. Encrypt with JS.
    const encBlob = await seal.encryptBlob(blobFromBytes(plaintext), PW_BYTES, {
        kind: seal.KIND_FILE,
    });
    const encBytes = await blobToBytes(encBlob);

    // 2. Write the .seal to disk and decrypt with Python.
    const sealPath = join(tmp, `js2py_${label.replace(/\W+/g, '_')}.seal`);
    const outPath = sealPath + '.out';
    await writeFile(sealPath, encBytes);

    try {
        await exec('python3', [
            resolve(REPO, 'seal.py'), 'decrypt', sealPath,
            '-o', outPath, '-P', '-q', '-f',
        ], { input: PASSWORD + '\n' });
    } catch (e) {
        check(label, false, 'python decrypt failed: ' + (e.stderr || e.message));
        continue;
    }

    const decrypted = await readFile(outPath);
    const same = decrypted.length === plaintext.length &&
        decrypted.every((b, i) => b === plaintext[i]);
    check(label, same,
        `expected ${plaintext.length} bytes, got ${decrypted.length}`);
}

console.log('\n=== Python encrypt → JS decrypt ===');

for (const [size, label] of [
    [0, 'empty'],
    [1, 'one byte'],
    [1024, '1 KiB'],
    [seal.CHUNK_SIZE - 1, 'just under one chunk'],
    [seal.CHUNK_SIZE, 'exact chunk boundary'],
    [seal.CHUNK_SIZE + 1, 'just over one chunk'],
    [3 * seal.CHUNK_SIZE + 17, 'multi-chunk + remainder'],
]) {
    const plaintext = randomBytes(size);
    /* set below */

    // 1. Write plaintext to disk, encrypt with Python.
    const ptPath  = join(tmp, `py2js_${label.replace(/\W+/g, '_')}.bin`);
    const encPath = ptPath + '.seal';
    await writeFile(ptPath, plaintext);

    try {
        await exec('python3', [
            resolve(REPO, 'seal.py'), 'encrypt', ptPath,
            '-o', encPath, '-P', '-q', '-f',
        ], { input: PASSWORD + '\n' });
    } catch (e) {
        check(label, false, 'python encrypt failed: ' + (e.stderr || e.message));
        continue;
    }

    // 2. Decrypt with JS.
    const encBytes = await readFile(encPath);
    let result;
    try {
        result = await seal.decryptBlob(blobFromBytes(encBytes), PW_BYTES);
    } catch (e) {
        check(label, false, 'js decrypt threw: ' + e.message);
        continue;
    }
    const out = await blobToBytes(result.blob);
    const same = out.length === plaintext.length &&
        out.every((b, i) => b === plaintext[i]);
    check(label + ` (kind=${result.kindName})`, same,
        `expected ${plaintext.length} bytes, got ${out.length}`);
}

console.log('\n=== Tamper / wrong-password rejection ===');
{
    const pt = randomBytes(50_000);
    
    const enc = await blobToBytes(
        await seal.encryptBlob(blobFromBytes(pt), PW_BYTES, { kind: seal.KIND_FILE })
    );

    // Wrong password
    let threw = false;
    try {
        await seal.decryptBlob(blobFromBytes(enc), new TextEncoder().encode('wrong'));
    } catch (e) { threw = e.message.includes('wrong password') || e.message.includes('corrupted'); }
    check('wrong password rejected', threw);

    // Flipped byte inside ciphertext
    const tampered = enc.slice();
    tampered[100] ^= 1;
    threw = false;
    try { await seal.decryptBlob(blobFromBytes(tampered), PW_BYTES); }
    catch (e) { threw = true; }
    check('tampered ciphertext rejected', threw);

    // Truncation
    const truncated = enc.slice(0, enc.length - 100);
    threw = false;
    try { await seal.decryptBlob(blobFromBytes(truncated), PW_BYTES); }
    catch (e) { threw = true; }
    check('truncated file rejected', threw);

    // Appended garbage
    const padded = new Uint8Array(enc.length + 50);
    padded.set(enc, 0);
    padded.set(randomBytes(50), enc.length);
    threw = false;
    try { await seal.decryptBlob(blobFromBytes(padded), PW_BYTES); }
    catch (e) { threw = true; }
    check('appended-garbage rejected', threw);
}

console.log('\n=== peekInfo ===');
{
    const enc = await seal.encryptBlob(
        blobFromBytes(new Uint8Array([1, 2, 3])), PW_BYTES, { kind: seal.KIND_FILE });
    const info = await seal.peekInfo(enc);
    check('peekInfo reports v2 file',
        info.version === 2 && info.kind === seal.KIND_FILE && info.kindName === 'file');

    const encDir = await seal.encryptBlob(
        blobFromBytes(new Uint8Array([1, 2, 3])), PW_BYTES, { kind: seal.KIND_DIR });
    const info2 = await seal.peekInfo(encDir);
    check('peekInfo reports v2 directory',
        info2.version === 2 && info2.kind === seal.KIND_DIR && info2.kindName === 'directory');
}

await rm(tmp, { recursive: true, force: true });

console.log(`\n${pass} passed, ${fail} failed.`);
process.exit(fail === 0 ? 0 : 1);
