// Usage: node js_decrypt.mjs <input.seal> <out> <password>
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

const [,, inPath, outPath, pw] = process.argv;
const data = await readFile(inPath);
const res = await seal.decryptBlob(new Blob([data]), new TextEncoder().encode(pw));
const out = new Uint8Array(await res.blob.arrayBuffer());
await writeFile(outPath, out);
console.log(`decrypted ${data.length} → ${out.length} bytes (kind=${res.kindName}, version=${res.version})`);
