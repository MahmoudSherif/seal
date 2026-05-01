// Usage: node js_encrypt.mjs <input> <output> <password> [<kind>]
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const require = createRequire(import.meta.url);

globalThis.window = globalThis;
globalThis.scrypt = require(resolve(ROOT, 'node_modules/scrypt-js/scrypt.js'));
require(resolve(ROOT, 'seal.js'));
const seal = globalThis.seal;

const [,, inPath, outPath, pw, kindStr] = process.argv;
const kind = kindStr === 'dir' ? seal.KIND_DIR : seal.KIND_FILE;
const data = await readFile(inPath);
const enc = await seal.encryptBlob(new Blob([data]), new TextEncoder().encode(pw), { kind });
await writeFile(outPath, new Uint8Array(await enc.arrayBuffer()));
console.log(`encrypted ${data.length} → ${(await readFile(outPath)).length} bytes (kind=${kind})`);
