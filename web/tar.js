// tar.js — minimal tar reader & writer compatible with Python tarfile.
//
// Only supports what `seal` actually produces & consumes:
//   - regular files       (typeflag '0' or NUL)
//   - directories         (typeflag '5')
//   - GNU long names      (typeflag 'L')   — read only, for compat with
//                                            Python tarfile's automatic
//                                            handling of paths > 99 bytes.
// We never write long-name records; on encrypt we reject paths > 99 chars
// with a clear error message.

(function (global) {
    'use strict';

    const BLOCK = 512;
    const TYPE_FILE = 0x30;     // '0'
    const TYPE_DIR  = 0x35;     // '5'
    const TYPE_LONG = 0x4C;     // 'L'  (GNU @LongLink)

    const enc = new TextEncoder();
    const dec = new TextDecoder();

    function writeAscii(buf, off, str, fieldLen) {
        const bytes = enc.encode(str);
        if (bytes.length > fieldLen) {
            throw new Error(`tar field overflow at offset ${off}`);
        }
        buf.set(bytes, off);
    }

    /** Write zero-padded octal string of fieldLen-1 digits + trailing NUL. */
    function writeOctal(buf, off, value, fieldLen) {
        const s = value.toString(8).padStart(fieldLen - 1, '0');
        if (s.length > fieldLen - 1) {
            throw new Error(`tar octal field overflow: ${value}`);
        }
        buf.set(enc.encode(s), off);
        buf[off + fieldLen - 1] = 0;
    }

    function readCString(buf, off, fieldLen) {
        let end = off;
        const stop = off + fieldLen;
        while (end < stop && buf[end] !== 0) end++;
        return dec.decode(buf.subarray(off, end));
    }

    function readOctal(buf, off, fieldLen) {
        // Tar octal fields can be terminated by NUL or space; Python writes
        // either depending on the field. Take everything up to first non-octal.
        const s = readCString(buf, off, fieldLen).trim();
        return s ? parseInt(s, 8) : 0;
    }

    /**
     * Build a tar archive from an array of entries.
     * @param {Array<{path: string, data?: Uint8Array, isDirectory?: boolean}>} entries
     * @returns {Uint8Array} the tar archive
     */
    function tarPack(entries) {
        // Sort by path for determinism (matches what seal.py does too).
        entries = entries.slice().sort((a, b) => a.path.localeCompare(b.path));

        const parts = [];
        const mtime = Math.floor(Date.now() / 1000);

        for (const e of entries) {
            const isDir = !!e.isDirectory;
            const data = isDir ? new Uint8Array(0) : (e.data || new Uint8Array(0));

            // Path normalisation: strip leading slashes, never include "./".
            let name = e.path.replace(/^\/+/, '');
            if (isDir && !name.endsWith('/')) name += '/';

            const nameBytes = enc.encode(name);
            if (nameBytes.length > 99) {
                throw new Error(
                    `path is too long for the in-browser tar writer (>99 bytes): ${name}\n` +
                    `Encrypt this folder with the seal CLI instead, or shorten the paths.`
                );
            }

            const header = new Uint8Array(BLOCK);
            writeAscii(header, 0, name, 100);
            writeOctal(header, 100, isDir ? 0o755 : 0o644, 8);   // mode
            writeOctal(header, 108, 0, 8);                        // uid
            writeOctal(header, 116, 0, 8);                        // gid
            writeOctal(header, 124, data.length, 12);             // size
            writeOctal(header, 136, mtime, 12);                   // mtime
            // Checksum: 8 spaces while computing.
            for (let i = 148; i < 156; i++) header[i] = 0x20;
            header[156] = isDir ? TYPE_DIR : TYPE_FILE;          // typeflag
            writeAscii(header, 257, 'ustar', 6);                  // magic
            header[263] = 0x30; header[264] = 0x30;               // version "00"

            // Compute checksum over the whole 512-byte block.
            let sum = 0;
            for (let i = 0; i < BLOCK; i++) sum += header[i];
            // Format: 6 octal digits + NUL + space (Python's tarfile convention).
            writeAscii(header, 148, sum.toString(8).padStart(6, '0'), 6);
            header[154] = 0;
            header[155] = 0x20;

            parts.push(header);

            if (data.length > 0) {
                parts.push(data);
                const pad = (BLOCK - (data.length % BLOCK)) % BLOCK;
                if (pad > 0) parts.push(new Uint8Array(pad));
            }
        }

        // End-of-archive marker: two zero blocks.
        parts.push(new Uint8Array(BLOCK * 2));

        // Concatenate.
        let total = 0;
        for (const p of parts) total += p.length;
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    }

    /**
     * Parse a tar archive into entries.
     * @param {Uint8Array} bytes
     * @returns {Array<{path: string, data: Uint8Array|null, isDirectory: boolean, isFile: boolean}>}
     */
    function tarUnpack(bytes) {
        const entries = [];
        let off = 0;
        let pendingLongName = null;

        while (off + BLOCK <= bytes.length) {
            const block = bytes.subarray(off, off + BLOCK);

            // End-of-archive marker: a block of all zeros.
            let allZero = true;
            for (let i = 0; i < BLOCK; i++) {
                if (block[i] !== 0) { allZero = false; break; }
            }
            if (allZero) break;

            let name = readCString(block, 0, 100);
            const size = readOctal(block, 124, 12);
            const typeflag = block[156];
            const prefix = readCString(block, 345, 155);
            if (prefix && (typeflag === TYPE_FILE || typeflag === TYPE_DIR ||
                           typeflag === 0)) {
                name = prefix + '/' + name;
            }

            off += BLOCK;
            const padded = Math.ceil(size / BLOCK) * BLOCK;

            if (typeflag === TYPE_LONG) {
                // GNU @LongLink: next entry's name is the data of this one.
                pendingLongName = readCString(bytes, off, size);
                off += padded;
                continue;
            }

            if (pendingLongName !== null) {
                name = pendingLongName;
                pendingLongName = null;
            }

            const isFile = (typeflag === TYPE_FILE || typeflag === 0);
            const isDir  = (typeflag === TYPE_DIR);
            const data   = isFile ? bytes.slice(off, off + size) : null;

            // Skip device files, symlinks, etc.
            if (isFile || isDir) {
                entries.push({ path: name, data, isFile, isDirectory: isDir });
            }

            off += padded;
        }

        return entries;
    }

    global.tar = { pack: tarPack, unpack: tarUnpack };

})(typeof window !== 'undefined' ? window : globalThis);
