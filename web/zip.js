// zip.js — minimal "store" mode (no compression) ZIP writer.
//
// Used to package a decrypted folder as a single file the user can
// download and extract with their OS's built-in ZIP support. Stored
// mode is fine here: the input is already user data of mixed
// compressibility, and we want fast in-browser packaging more than
// minimum size.

(function (global) {
    'use strict';

    const enc = new TextEncoder();

    // -------- CRC-32 --------
    let CRC_TABLE = null;
    function makeCrcTable() {
        const t = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            t[i] = c >>> 0;
        }
        return t;
    }
    function crc32(bytes) {
        if (!CRC_TABLE) CRC_TABLE = makeCrcTable();
        let c = 0xFFFFFFFF;
        for (let i = 0; i < bytes.length; i++) {
            c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
        }
        return (c ^ 0xFFFFFFFF) >>> 0;
    }

    // -------- byte helpers --------
    function u16(buf, off, v) { buf[off] = v & 0xff; buf[off+1] = (v >>> 8) & 0xff; }
    function u32(buf, off, v) {
        buf[off]   =  v         & 0xff;
        buf[off+1] = (v >>> 8)  & 0xff;
        buf[off+2] = (v >>> 16) & 0xff;
        buf[off+3] = (v >>> 24) & 0xff;
    }

    /**
     * Build a ZIP archive (store mode) from an array of file entries.
     *
     * @param {Array<{path:string, data:Uint8Array}>} entries
     * @returns {Blob}
     */
    function zipBuild(entries) {
        // DOS time/date for "now". Resolution is 2 seconds; good enough.
        const now = new Date();
        const dosTime = ((now.getHours() & 0x1f) << 11) |
                        ((now.getMinutes() & 0x3f) << 5) |
                        ((Math.floor(now.getSeconds() / 2)) & 0x1f);
        const dosDate = (((now.getFullYear() - 1980) & 0x7f) << 9) |
                        (((now.getMonth() + 1) & 0x0f) << 5) |
                        (now.getDate() & 0x1f);

        const localParts = [];
        const central = [];
        let offset = 0;

        for (const e of entries) {
            const nameBytes = enc.encode(e.path.replace(/^\/+/, ''));
            const data = e.data;
            const crc = crc32(data);

            // ---- local file header (30 bytes + name) ----
            const lh = new Uint8Array(30 + nameBytes.length);
            u32(lh, 0,  0x04034b50);          // signature
            u16(lh, 4,  20);                  // version needed (2.0)
            u16(lh, 6,  0x0800);              // gp flag: UTF-8 filename
            u16(lh, 8,  0);                   // method: 0 = stored
            u16(lh, 10, dosTime);
            u16(lh, 12, dosDate);
            u32(lh, 14, crc);
            u32(lh, 18, data.length);         // compressed size
            u32(lh, 22, data.length);         // uncompressed size
            u16(lh, 26, nameBytes.length);
            u16(lh, 28, 0);                   // extra field length
            lh.set(nameBytes, 30);

            localParts.push(lh);
            localParts.push(data);

            // ---- central directory record (46 bytes + name) ----
            const cd = new Uint8Array(46 + nameBytes.length);
            u32(cd, 0,  0x02014b50);
            u16(cd, 4,  20);                  // version made by
            u16(cd, 6,  20);                  // version needed
            u16(cd, 8,  0x0800);
            u16(cd, 10, 0);
            u16(cd, 12, dosTime);
            u16(cd, 14, dosDate);
            u32(cd, 16, crc);
            u32(cd, 20, data.length);
            u32(cd, 24, data.length);
            u16(cd, 28, nameBytes.length);
            u16(cd, 30, 0);                   // extra
            u16(cd, 32, 0);                   // comment
            u16(cd, 34, 0);                   // disk
            u16(cd, 36, 0);                   // internal attrs
            u32(cd, 38, 0);                   // external attrs
            u32(cd, 42, offset);              // relative offset of local header
            cd.set(nameBytes, 46);
            central.push(cd);

            offset += lh.length + data.length;
        }

        // End of central directory record.
        let cdSize = 0;
        for (const c of central) cdSize += c.length;
        const cdOffset = offset;

        const eocd = new Uint8Array(22);
        u32(eocd, 0,  0x06054b50);
        u16(eocd, 4,  0);                     // disk number
        u16(eocd, 6,  0);                     // disk where CD starts
        u16(eocd, 8,  entries.length);        // entries on this disk
        u16(eocd, 10, entries.length);        // total entries
        u32(eocd, 12, cdSize);
        u32(eocd, 16, cdOffset);
        u16(eocd, 20, 0);                     // comment length

        const all = [].concat(localParts, central, [eocd]);
        return new Blob(all, { type: 'application/zip' });
    }

    global.zip = { build: zipBuild };

})(typeof window !== 'undefined' ? window : globalThis);
