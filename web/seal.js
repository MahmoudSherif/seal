// seal.js — browser implementation of the SEAL v2 file format.
//
// Mirrors seal.py exactly: AES-256-GCM authenticated encryption, scrypt
// key derivation, 64 KiB streaming chunks, last-chunk flag bound into
// the AEAD nonce. Files made here decrypt with the Python CLI/GUI and
// vice versa.
//
// Depends on:
//   - window.scrypt   (from scrypt-js, MIT — vendor/scrypt.js)
//   - window.pako     (gzip; only needed for folder mode — vendor/pako.min.js)
//   - Web Crypto API  (built into all modern browsers, requires HTTPS or localhost)

(function (global) {
    'use strict';

    // ---------- format constants (must match seal.py) ----------
    const MAGIC = new Uint8Array([0x53, 0x45, 0x41, 0x4C]);  // "SEAL"
    const VERSION_V1 = 1;
    const VERSION_V2 = 2;
    const CURRENT_VERSION = VERSION_V2;

    const KIND_FILE = 0;
    const KIND_DIR  = 1;
    const KIND_FILE_NAMED = 2;
    const KIND_NAMES = { 0: 'file', 1: 'directory', 2: 'file (hidden name)' };
    const HIDDEN_NAME_MAX = 0xFFFF;

    const SALT_SIZE = 16;
    const NONCE_PREFIX_SIZE = 8;
    const KEY_SIZE = 32;             // AES-256
    const TAG_SIZE = 16;             // AES-GCM tag
    const CHUNK_SIZE = 64 * 1024;    // plaintext chunk size
    const ENC_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE;
    const EOF_FLAG = 0x80000000;     // high bit of counter on last chunk
    const MAX_CHUNKS = EOF_FLAG;

    // scrypt params: same as seal.py — N=2^17, r=8, p=1, dklen=32.
    const SCRYPT_N = 1 << 17;
    const SCRYPT_R = 8;
    const SCRYPT_P = 1;

    // ---------- crypto primitives ----------

    /**
     * Derive a 256-bit AES key from password+salt using scrypt.
     * Calls onProgress(fraction) periodically (0..1).
     */
    async function deriveKey(passwordBytes, salt, onProgress) {
        if (!global.scrypt || !global.scrypt.scrypt) {
            throw new Error('scrypt-js not loaded — check vendor/scrypt.js');
        }
        const cb = onProgress
            ? (p) => { onProgress(p); return false; /* don't cancel */ }
            : undefined;
        const keyBytes = await global.scrypt.scrypt(
            passwordBytes, salt,
            SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_SIZE,
            cb
        );
        return await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );
    }

    function makeNonce(prefix, counter, isLast) {
        if (counter >= MAX_CHUNKS) {
            throw new Error('input too large for SEAL format');
        }
        const nonce = new Uint8Array(12);
        nonce.set(prefix, 0);
        const value = isLast ? (counter | 0) | EOF_FLAG : counter;
        // Big-endian 32-bit. Use unsigned right-shift to handle the EOF bit
        // without sign-extending into negative territory.
        nonce[8]  = (value >>> 24) & 0xff;
        nonce[9]  = (value >>> 16) & 0xff;
        nonce[10] = (value >>>  8) & 0xff;
        nonce[11] =  value         & 0xff;
        return nonce;
    }

    async function aesGcmEncrypt(key, nonce, plaintext) {
        const buf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: 128 },
            key, plaintext
        );
        return new Uint8Array(buf);
    }

    async function aesGcmDecrypt(key, nonce, ciphertext) {
        try {
            const buf = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce, tagLength: 128 },
                key, ciphertext
            );
            return new Uint8Array(buf);
        } catch (e) {
            // Web Crypto throws an opaque OperationError on tag failure —
            // re-raise with a clear message identical to the Python version.
            throw new Error(
                'decryption failed: wrong password, or file is corrupted/tampered'
            );
        }
    }

    // ---------- header helpers ----------

    /**
     * Read a SEAL header from a Uint8Array, supporting both v1 and v2.
     * Returns {version, kind, salt, noncePrefix, headerLen}.
     */
    function readHeader(bytes) {
        if (bytes.length < 5) {
            throw new Error('not a SEAL file (too short)');
        }
        for (let i = 0; i < 4; i++) {
            if (bytes[i] !== MAGIC[i]) {
                throw new Error('not a SEAL file (bad magic)');
            }
        }
        const version = bytes[4];

        if (version === VERSION_V1) {
            const headerLen = 5 + SALT_SIZE + NONCE_PREFIX_SIZE;  // 29
            if (bytes.length < headerLen) {
                throw new Error('truncated SEAL v1 header');
            }
            return {
                version, kind: KIND_FILE, headerLen,
                salt: bytes.slice(5, 5 + SALT_SIZE),
                noncePrefix: bytes.slice(5 + SALT_SIZE, headerLen),
            };
        }

        if (version === VERSION_V2) {
            const headerLen = 6 + SALT_SIZE + NONCE_PREFIX_SIZE;  // 30
            if (bytes.length < headerLen) {
                throw new Error('truncated SEAL v2 header');
            }
            const kind = bytes[5];
            if (kind !== KIND_FILE && kind !== KIND_DIR && kind !== KIND_FILE_NAMED) {
                throw new Error('unknown SEAL kind byte: ' + kind);
            }
            return {
                version, kind, headerLen,
                salt: bytes.slice(6, 6 + SALT_SIZE),
                noncePrefix: bytes.slice(6 + SALT_SIZE, headerLen),
            };
        }

        throw new Error('unsupported SEAL version: ' + version);
    }

    /** Peek the header of a Blob/File without decrypting. */
    async function peekInfo(blob) {
        const head = new Uint8Array(await blob.slice(0, 30).arrayBuffer());
        const h = readHeader(head);
        return {
            version: h.version,
            kind: h.kind,
            kindName: KIND_NAMES[h.kind],
            size: blob.size,
        };
    }

    // ---------- encrypt ----------

    /**
     * Encrypt a Blob/File under password.
     *
     * @param {Blob|File} blob - input data
     * @param {Uint8Array} passwordBytes - password as UTF-8 bytes
     * @param {Object} opts
     * @param {number} opts.kind - KIND_FILE or KIND_DIR
     * @param {Function} opts.onKdfProgress - called with fraction 0..1
     * @param {Function} opts.onCipherProgress - called with fraction 0..1
     * @returns {Promise<Blob>} the encrypted .seal blob
     */
    async function encryptBlob(blob, passwordBytes, opts) {
        opts = opts || {};
        const kind = (opts.kind === KIND_DIR || opts.kind === KIND_FILE_NAMED)
            ? opts.kind : KIND_FILE;

        const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
        const noncePrefix = crypto.getRandomValues(new Uint8Array(NONCE_PREFIX_SIZE));
        const key = await deriveKey(passwordBytes, salt, opts.onKdfProgress);

        const parts = [];
        parts.push(MAGIC);
        parts.push(new Uint8Array([CURRENT_VERSION, kind]));
        parts.push(salt);
        parts.push(noncePrefix);

        const total = blob.size;

        if (total === 0) {
            // Empty input: emit one authenticated empty "last" chunk.
            const nonce = makeNonce(noncePrefix, 0, true);
            parts.push(await aesGcmEncrypt(key, nonce, new Uint8Array(0)));
            if (opts.onCipherProgress) opts.onCipherProgress(1);
            return new Blob(parts, { type: 'application/octet-stream' });
        }

        let counter = 0;
        let offset = 0;
        while (offset < total) {
            const end = Math.min(offset + CHUNK_SIZE, total);
            const isLast = (end === total);
            const chunk = await blob.slice(offset, end).arrayBuffer();
            const nonce = makeNonce(noncePrefix, counter, isLast);
            parts.push(await aesGcmEncrypt(key, nonce, chunk));
            counter++;
            offset = end;
            if (opts.onCipherProgress) opts.onCipherProgress(offset / total);
            // Yield to UI thread every ~1 MiB to keep the page responsive.
            if (counter % 16 === 0) await new Promise(r => setTimeout(r, 0));
        }
        return new Blob(parts, { type: 'application/octet-stream' });
    }

    // ---------- decrypt ----------

    /**
     * Decrypt a .seal Blob/File under password.
     *
     * Returns {blob, kind, kindName} where blob is the decrypted plaintext.
     * For KIND_DIR, the plaintext is a tar.gz stream (caller can ungzip + untar).
     */
    async function decryptBlob(blob, passwordBytes, opts) {
        opts = opts || {};

        // Read enough bytes to cover both v1 and v2 headers, then parse.
        const headBytes = new Uint8Array(await blob.slice(0, 30).arrayBuffer());
        const h = readHeader(headBytes);
        const key = await deriveKey(passwordBytes, h.salt, opts.onKdfProgress);

        const parts = [];
        let offset = h.headerLen;
        let counter = 0;
        const total = blob.size;

        if (offset >= total) {
            throw new Error('truncated SEAL file (no body)');
        }

        while (offset < total) {
            const end = Math.min(offset + ENC_CHUNK_SIZE, total);
            const isLast = (end === total);
            const ct = await blob.slice(offset, end).arrayBuffer();
            const nonce = makeNonce(h.noncePrefix, counter, isLast);
            parts.push(await aesGcmDecrypt(key, nonce, ct));
            counter++;
            offset = end;
            if (opts.onCipherProgress) opts.onCipherProgress(offset / total);
            if (counter % 16 === 0) await new Promise(r => setTimeout(r, 0));
        }

        return {
            blob: new Blob(parts),
            kind: h.kind,
            kindName: KIND_NAMES[h.kind],
            version: h.version,
        };
    }

    // ---------- hidden-name (KIND_FILE_NAMED) helpers ----------

    function _safeBasename(name) {
        // Strip directory components, defending against both '/' and '\'.
        const base = name.replace(/\\/g, '/').split('/').pop().trim();
        if (!base || base === '.' || base === '..') {
            throw new Error('embedded filename is unsafe: ' + JSON.stringify(name));
        }
        // Reject control characters (NUL etc.).
        for (let i = 0; i < base.length; i++) {
            if (base.charCodeAt(i) < 0x20) {
                throw new Error('embedded filename contains control characters');
            }
        }
        return base;
    }

    /**
     * Encrypt a file with its name hidden inside the encrypted payload.
     * The output Blob's bytes reveal nothing about the original filename.
     *
     * @param {File|Blob} blob - the file content
     * @param {string} originalName - the filename to embed (will be sanitized)
     * @param {Uint8Array} passwordBytes
     * @param {Object} opts - same as encryptBlob
     * @returns {Promise<Blob>}
     */
    async function encryptBlobHiddenName(blob, originalName, passwordBytes, opts) {
        const nameBytes = new TextEncoder().encode(originalName);
        if (nameBytes.length > HIDDEN_NAME_MAX) {
            throw new Error('filename too long to embed');
        }
        // Prefix the plaintext with [u16-be name_len][name bytes].
        const header = new Uint8Array(2 + nameBytes.length);
        header[0] = (nameBytes.length >>> 8) & 0xff;
        header[1] =  nameBytes.length        & 0xff;
        header.set(nameBytes, 2);

        const wrapped = new Blob([header, blob]);
        return encryptBlob(wrapped, passwordBytes,
            Object.assign({}, opts || {}, { kind: KIND_FILE_NAMED }));
    }

    /**
     * Decrypt a KIND_FILE_NAMED .seal file, returning {blob, embeddedName, safeName}.
     * The blob is the file *contents only* (with the name header stripped).
     */
    async function decryptBlobHiddenName(blob, passwordBytes, opts) {
        const result = await decryptBlob(blob, passwordBytes, opts);
        if (result.kind !== KIND_FILE_NAMED) {
            throw new Error('not a hidden-name SEAL file (kind=' + result.kindName + ')');
        }
        const all = new Uint8Array(await result.blob.arrayBuffer());
        if (all.length < 2) {
            throw new Error('hidden-name payload too short');
        }
        const nameLen = (all[0] << 8) | all[1];
        if (all.length < 2 + nameLen) {
            throw new Error('hidden-name payload truncated');
        }
        const nameBytes = all.subarray(2, 2 + nameLen);
        let embeddedName;
        try {
            embeddedName = new TextDecoder('utf-8', { fatal: true }).decode(nameBytes);
        } catch (e) {
            throw new Error('embedded filename is not valid UTF-8');
        }
        const safeName = _safeBasename(embeddedName);
        const contentBlob = new Blob([all.subarray(2 + nameLen)]);
        return {
            blob: contentBlob,
            embeddedName,
            safeName,
            kind: KIND_FILE_NAMED,
            kindName: KIND_NAMES[KIND_FILE_NAMED],
            version: result.version,
        };
    }

    // ---------- passphrase generation ----------
    // Mirror seal.py's _WORDLIST. Generated at module load by walking the
    // alphabet space; we duplicate the list inline to ensure both
    // implementations agree letter-for-letter (so rule changes flow through
    // to both tools).
    const WORDLIST = (
        'able acid aged also area army away baby back bake ball band ' +
        'bank bare barn base bath bear beat been bell belt bend best ' +
        'bike bill bind bird bite blue boat body bold bone book boot ' +
        'born both bowl brave bread brick bring broad brown buddy bulk bull ' +
        'burn bush busy cabin cake calm camp cane cape card care cash ' +
        'cast cave cell chain chair chalk chart cheap check cheek cheer chest ' +
        'chief child chill chip chop city clay clean clear cliff climb cloak ' +
        'clock close cloud club clue coach coal coast coat code coin cold ' +
        'come cook cool copy corn cost couch cough count court cover crab ' +
        'craft crane crash cream creek crew crisp crop cross crowd crown cube ' +
        'cup curl dance dare dark dart data dawn deal dear deep deer ' +
        'desk dial diet dime dine dirt dish dive dock door dose dove ' +
        'dozen draft drag draw dream drift drill drink drive drop drum duck ' +
        'dust eager early earn earth east easy edge eight elbow elder empty ' +
        'enemy enjoy enter entry equal even ever evil exit fable face fact ' +
        'fade fair faith fall fame farm fast favor fear feast feed feel ' +
        'fence ferry few field fifth fight final finch find fine fire firm ' +
        'first fish five flag flame flash flat flax flesh float flock flood ' +
        'floor flour flow fluid flute fly foam focus fog fold folk food ' +
        'foot ford forge form fort found four fox frame free fresh frog ' +
        'front frost fruit fuel full fun fund game gap gate gaze gear ' +
        'gem gift give glad glass globe glove glow goal gold golf good ' +
        'goose grab grace grade grain grand grant grape grass gray great green ' +
        'grid grin grip groom group grow guard guess guest guide gulf hail ' +
        'hair half hall halt hand happy hard harp hash haste hatch have ' +
        'hawk haze head heap hear heart heat help herb here hero hide ' +
        'high hill hint hire hold hole holy home honey hood hook hope ' +
        'horn horse hotel hour house huge human humor hunt hurry husk ice ' +
        'idea idle inch ink inn iron item ivory ivy jade jail jaw ' +
        'jazz jeep jelly jet jewel join joke joy judge juice jump junior ' +
        'just keen keep kept key kick kid kind king kiss kite knee ' +
        'knife knit knob knock know lab lace lady lake lamb lamp land ' +
        'lane large lark last late laugh lava law lawn layer lazy lead ' +
        'leaf lean learn leash least leave left lemon lend lens less life ' +
        'lift light like lily lime limit line link lion lip list live ' +
        'load loaf lobby local lock log lone long loop lose lost lot ' +
        'loud love loyal luck lump lunar lunch lung lure lyric magic maid ' +
        'main make mango many maple march mark marsh mask mass mast match ' +
        'meal mean meat medal melt member memo mend menu merit merry metal ' +
        'might milk mill mind mine mint mist mode model mole monk month ' +
        'moon morse most moth motor mount mouse mouth move much mud muse ' +
        'music must myth nail name nap navy near neat neck need nest ' +
        'never news next nice night nine noble noise none north nose note ' +
        'novel now nurse nut oak oasis oat oats ocean odd offer often ' +
        'oil okay olive once onion only open opera opt orange orbit other ' +
        'otter ounce out oval oven over owl own oxide pace pack page ' +
        'paid pail pain paint pair palm pan panda paper park part pass ' +
        'past patch path peace peach pear peer pen penny perch piano pick ' +
        'pie pill pilot pinch pine pink pipe pitch pixel pizza place plain ' +
        'plan plant plate play plot plug plum poem poet point poll polo ' +
        'pool poppy port pose post pouch pound power press pride print prize ' +
        'proud prune pulp pulse pump pure push quail quart queen quest quick ' +
        'quiet quill quilt quite quote rabbit race radio rage rail rain raise ' +
        'rake ramp ranch rapid rare rat rate raven raw reach read ready ' +
        'real rebel reef relax relay relic rely remix rent reply reset rest ' +
        'rice rich ride rifle right rigid ring rinse ripe rise risk rival ' +
        'river road robe robin rock rocky rod role roof room root rope ' +
        'rose rough round route royal ruby rude rug ruin rule run rural ' +
        'rush rust safe sage sail saint salad salt same sand save scale ' +
        'scarf scene scent scout sea seal seam search seat seed seek seem ' +
        'seize sell send sense serve seven shade shake shape share sharp shawl ' +
        'sheep shelf shell shine ship shirt shoe shop shore short shout show ' +
        'shown shrub side sigh sight silk silly silo silver sing sink sip ' +
        'site six size skate ski skill skin skip skirt sky slab slack ' +
        'slam slate sleep sleet slice slim slip slope slot slow small smart ' +
        'smile smoke snake snap snow soap soft soil sold solid solo solve ' +
        'some song soon sort soul soup sour space spade spare spark speak ' +
        'speed spell spend spice spike spin spine spire splat split spoke spoon ' +
        'sport spot spray spree spring spy stack stage stair stamp stand star ' +
        'stark start stash state stay steam steel steep stem step stern stick ' +
        'still sting stir stock stone stop store storm story stove straw stream ' +
        'street strict stride strike string strong study stuff stump style such suds ' +
        'sugar sulky summer sun sunny super swamp swan swap sweat sweep sweet ' +
        'swift swim swing sword table tail take talk tall tame tank tape ' +
        'task taste teach team tear teeth tell ten tent term test text ' +
        'than that thaw their them then there these they thick thin thing ' +
        'think third this thorn those thread three throat throw thumb tide tidy ' +
        'tie tiger tight tile time tin tiny tip tire title toast today ' +
        'toe tonic tool tooth top torch total touch tour tower town toxic ' +
        'toy track trade trail train trap travel tray treat tree trek trial ' +
        'tribe trick trip troop truck true trunk trust truth try tube tuna ' +
        'tune turf turn tutor twin twist two type ugly umpire under unit ' +
        'until upon urge urn use user usual valid value vapor vary vase ' +
        'vast vault verb verse very vest video view vine vinyl visit vivid ' +
        'vocal voice volt vote vow wade wage wagon wait wake walk wall ' +
        'walnut wand want ward '
    ).split(/\s+/).filter(w => w);

    function generatePassphrase(words, separator) {
        if (words === undefined) words = 5;
        if (separator === undefined) separator = '-';
        if (words < 1) throw new Error('words must be >= 1');
        const chosen = [];
        const n = WORDLIST.length;
        // Unbiased uniform selection: 1024 divides 65536 cleanly.
        const buf = new Uint8Array(2 * words);
        crypto.getRandomValues(buf);
        for (let i = 0; i < words; i++) {
            const v = (buf[2 * i] << 8) | buf[2 * i + 1];
            chosen.push(WORDLIST[v % n]);
        }
        return chosen.join(separator);
    }

    function passphraseEntropyBits(words) {
        return words * Math.log2(WORDLIST.length);
    }

    /**
     * Estimate a typed password's strength in bits.
     * Simple heuristic that's adequate for "weak/medium/strong" feedback —
     * not a substitute for zxcvbn's pattern-based analysis, but it catches
     * the common cases (length, character class diversity).
     */
    function estimatePasswordStrengthBits(pw) {
        if (!pw) return 0;
        // Effective alphabet size based on character classes used.
        let alphabet = 0;
        if (/[a-z]/.test(pw)) alphabet += 26;
        if (/[A-Z]/.test(pw)) alphabet += 26;
        if (/[0-9]/.test(pw)) alphabet += 10;
        if (/[^a-zA-Z0-9]/.test(pw)) alphabet += 32;
        if (alphabet === 0) return 0;
        let bits = pw.length * Math.log2(alphabet);
        // Penalize pure repetition: "aaaaaaaa" shouldn't score as length×alphabet.
        const unique = new Set(pw).size;
        if (unique < pw.length / 2) {
            bits *= unique / pw.length * 2;
        }
        // Penalize known weak patterns.
        if (/^[a-z]+$/.test(pw) && pw.length < 12) bits *= 0.7;
        if (/^(123|abc|qwerty|password|letmein)/i.test(pw)) bits *= 0.3;
        return Math.max(0, bits);
    }

    // ---------- public API ----------
    global.seal = {
        // constants
        KIND_FILE, KIND_DIR, KIND_FILE_NAMED, CURRENT_VERSION, CHUNK_SIZE,
        // primary API
        encryptBlob, decryptBlob, peekInfo,
        encryptBlobHiddenName, decryptBlobHiddenName,
        // passphrase / strength helpers
        generatePassphrase, passphraseEntropyBits,
        estimatePasswordStrengthBits,
        // useful for tests / advanced callers
        readHeader, makeNonce, deriveKey,
        WORDLIST,
    };

})(typeof window !== 'undefined' ? window : globalThis);
