// app.js — UI controller for the seal web app.

(function () {
    'use strict';

    // ---------- DOM lookups ----------
    const $ = (id) => document.getElementById(id);

    const tabs            = document.querySelectorAll('.mode-tab');
    const dropZone        = $('dropZone');
    const dropPrompt      = $('dropPrompt');
    const fileInput       = $('fileInput');
    const folderInput     = $('folderInput');
    const pickFileBtn     = $('pickFileBtn');
    const pickFolderBtn   = $('pickFolderBtn');
    const fileNameEl      = $('fileName');
    const fileMetaEl      = $('fileMeta');
    const clearBtn        = $('clearBtn');
    const infoPanel       = $('infoPanel');
    const infoFormat      = $('infoFormat');
    const infoKind        = $('infoKind');
    const infoSize        = $('infoSize');
    const passwordInput   = $('passwordInput');
    const confirmInput    = $('confirmInput');
    const confirmLabel    = $('confirmLabel');
    const showPwCheckbox  = $('showPwCheckbox');
    const generateBtn          = $('generateBtn');
    const strengthMeter        = $('strengthMeter');
    const strengthFill         = $('strengthFill');
    const strengthLabel        = $('strengthLabel');
    const strengthLevel        = $('strengthLevel');
    const strengthBits         = $('strengthBits');
    const hideNameOption       = $('hideNameOption');
    const hideNameCheckbox     = $('hideNameCheckbox');
    const selfDestructCheckbox = $('selfDestructCheckbox');
    const integrityText        = $('integrityText');
    const actionBtn       = $('actionBtn');
    const actionText      = $('actionText');
    const progressBar     = $('progressBar');
    const progressFill    = $('progressFill');
    const statusText      = $('statusText');

    // ---------- state ----------
    let mode = 'encrypt';
    let selection = null;   // { kind: 'file' | 'folder', file?, files? }
    let busy = false;

    // ---------- helpers ----------
    function fmtBytes(n) {
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
        return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    }

    function setStatus(text, kind) {
        statusText.textContent = text;
        statusText.classList.remove('error', 'success');
        if (kind) statusText.classList.add(kind);
    }

    function setProgress(fraction, label) {
        progressBar.classList.add('active');
        progressFill.style.width = Math.min(100, Math.max(0, fraction * 100)) + '%';
        if (label) setStatus(label);
    }

    function hideProgress() {
        progressBar.classList.remove('active');
        progressFill.style.width = '0%';
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Revoke after a delay so the download has time to start.
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }

    function setBusy(b) {
        busy = b;
        actionBtn.disabled = b;
        // Lock the form while a job is running.
        for (const el of [passwordInput, confirmInput, pickFileBtn, pickFolderBtn,
                          showPwCheckbox, clearBtn, generateBtn,
                          hideNameCheckbox, selfDestructCheckbox, ...tabs]) {
            el.disabled = b;
        }
    }

    // ---------- mode switching ----------
    function setMode(newMode) {
        if (busy || newMode === mode) return;
        mode = newMode;
        for (const t of tabs) {
            t.setAttribute('aria-selected', t.dataset.mode === mode ? 'true' : 'false');
        }

        if (mode === 'encrypt') {
            dropPrompt.textContent = 'Drop a file or folder here to encrypt it.';
            actionText.textContent = 'Encrypt & download';
            confirmInput.parentElement.style.display = '';
            confirmLabel.style.display = '';
            confirmInput.style.display = '';
            pickFolderBtn.disabled = false;
            hideNameOption.style.display = '';
            strengthMeter.classList.add('visible');
        } else {
            dropPrompt.textContent = 'Drop a .seal file here to decrypt it.';
            actionText.textContent = 'Decrypt & download';
            confirmInput.style.display = 'none';
            confirmLabel.style.display = 'none';
            confirmInput.value = '';
            pickFolderBtn.disabled = true;
            // Hide-name only applies when encrypting; the decrypt side
            // detects the kind from the header automatically.
            hideNameOption.style.display = 'none';
            hideNameCheckbox.checked = false;
            // Strength meter doesn't make sense for decrypt — they're
            // entering an existing password, not creating one.
            strengthMeter.classList.remove('visible');
        }
        clearSelection();
        updateStrengthMeter();
        setStatus('Ready.');
    }

    for (const t of tabs) {
        t.addEventListener('click', () => setMode(t.dataset.mode));
    }

    // ---------- selection handling ----------
    function clearSelection() {
        selection = null;
        dropZone.classList.remove('has-file');
        infoPanel.classList.remove('show');
        fileInput.value = '';
        folderInput.value = '';
    }

    function setSingleFile(file) {
        selection = { kind: 'file', file };
        dropZone.classList.add('has-file');
        fileNameEl.textContent = file.name;
        fileMetaEl.textContent = fmtBytes(file.size);
        hideNameCheckbox.disabled = false;

        // If we're in decrypt mode and this looks like a .seal, peek the header
        // and show its kind/version. If it's not a SEAL file, surface that now
        // rather than after the user types a password.
        if (mode === 'decrypt') {
            window.seal.peekInfo(file).then((info) => {
                infoFormat.textContent = `SEAL v${info.version}`;
                infoKind.textContent   = info.kindName;
                infoSize.textContent   = fmtBytes(info.size);
                infoPanel.classList.add('show');
                setStatus('Ready to decrypt.');
            }).catch((err) => {
                infoPanel.classList.remove('show');
                setStatus(`Not a SEAL file: ${err.message}`, 'error');
            });
        } else {
            infoPanel.classList.remove('show');
            setStatus(`Selected: ${file.name}`);
        }
    }

    function setFolder(files) {
        // files: FileList from <input webkitdirectory>
        if (!files || files.length === 0) return;
        // Derive a folder name from the first entry's path.
        const firstPath = files[0].webkitRelativePath || files[0].name;
        const folderName = firstPath.split('/')[0];
        let total = 0;
        for (const f of files) total += f.size;

        selection = { kind: 'folder', files: Array.from(files), folderName };
        dropZone.classList.add('has-file');
        fileNameEl.textContent = `📁 ${folderName}/`;
        fileMetaEl.textContent = `${files.length} file${files.length === 1 ? '' : 's'} · ${fmtBytes(total)}`;
        infoPanel.classList.remove('show');
        // Hide-name doesn't apply to folders.
        hideNameCheckbox.checked = false;
        hideNameCheckbox.disabled = true;
        setStatus(`Selected folder: ${folderName}`);
    }

    pickFileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });
    pickFolderBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        folderInput.click();
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) setSingleFile(fileInput.files[0]);
    });
    folderInput.addEventListener('change', () => {
        if (folderInput.files.length > 0) setFolder(folderInput.files);
    });
    clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearSelection();
        setStatus('Ready.');
    });
    dropZone.addEventListener('click', () => {
        if (busy || selection) return;
        fileInput.click();
    });
    dropZone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            if (!busy && !selection) fileInput.click();
        }
    });

    // ---------- drag & drop ----------
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    for (const ev of ['dragenter', 'dragover', 'dragleave', 'drop']) {
        dropZone.addEventListener(ev, preventDefaults);
    }
    dropZone.addEventListener('dragenter', () => dropZone.classList.add('dragover'));
    dropZone.addEventListener('dragover',  () => dropZone.classList.add('dragover'));
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', async (e) => {
        dropZone.classList.remove('dragover');
        if (busy) return;

        const items = e.dataTransfer.items;
        const files = e.dataTransfer.files;

        // Try to detect a dropped folder via webkitGetAsEntry.
        if (items && items.length > 0 && mode === 'encrypt') {
            const entry = items[0].webkitGetAsEntry && items[0].webkitGetAsEntry();
            if (entry && entry.isDirectory) {
                try {
                    const collected = await readDirEntry(entry);
                    if (collected.length > 0) {
                        selection = { kind: 'folder', files: collected, folderName: entry.name };
                        dropZone.classList.add('has-file');
                        fileNameEl.textContent = `📁 ${entry.name}/`;
                        let total = 0;
                        for (const f of collected) total += f.size;
                        fileMetaEl.textContent = `${collected.length} file${collected.length === 1 ? '' : 's'} · ${fmtBytes(total)}`;
                        infoPanel.classList.remove('show');
                        setStatus(`Selected folder: ${entry.name}`);
                        return;
                    }
                } catch (err) {
                    setStatus(`Could not read dropped folder: ${err.message}`, 'error');
                    return;
                }
            }
        }

        if (files && files.length > 0) {
            setSingleFile(files[0]);
        }
    });

    // Walk a DirectoryEntry and return all its files with relative paths.
    async function readDirEntry(dirEntry) {
        const out = [];
        async function walk(entry, pathPrefix) {
            if (entry.isFile) {
                const file = await new Promise((res, rej) => entry.file(res, rej));
                // Patch in webkitRelativePath so the rest of the code is uniform.
                Object.defineProperty(file, 'webkitRelativePath', {
                    value: pathPrefix + entry.name,
                });
                out.push(file);
            } else if (entry.isDirectory) {
                const reader = entry.createReader();
                let entries;
                do {
                    entries = await new Promise((res, rej) => reader.readEntries(res, rej));
                    for (const child of entries) {
                        await walk(child, pathPrefix + entry.name + '/');
                    }
                } while (entries.length > 0);
            }
        }
        await walk(dirEntry, '');
        return out;
    }

    // ---------- show / hide password ----------
    showPwCheckbox.addEventListener('change', () => {
        const t = showPwCheckbox.checked ? 'text' : 'password';
        passwordInput.type = t;
        confirmInput.type  = t;
    });

    // ---------- strength meter ----------
    function updateStrengthMeter() {
        if (mode !== 'encrypt') {
            strengthMeter.classList.remove('visible');
            return;
        }
        strengthMeter.classList.add('visible');
        const pw = passwordInput.value;
        if (!pw) {
            strengthFill.style.width = '0%';
            strengthFill.className = 'strength-bar-fill';
            strengthLabel.className = 'strength-label';
            strengthLevel.textContent = '—';
            strengthBits.textContent = '';
            return;
        }
        const bits = window.seal.estimatePasswordStrengthBits(pw);
        // Cap at 128 bits for the bar; anything stronger is "off the chart".
        const pct = Math.min(100, (bits / 80) * 100);
        let level, klass;
        if (bits < 30)      { level = 'weak';   klass = 'weak'; }
        else if (bits < 50) { level = 'fair';   klass = 'fair'; }
        else if (bits < 70) { level = 'good';   klass = 'good'; }
        else                { level = 'strong'; klass = 'strong'; }
        strengthFill.style.width = pct + '%';
        strengthFill.className = 'strength-bar-fill ' + klass;
        strengthLabel.className = 'strength-label ' + klass;
        strengthLevel.textContent = level;
        strengthBits.textContent = `  ·  ~${Math.round(bits)} bits`;
    }
    passwordInput.addEventListener('input', updateStrengthMeter);

    // ---------- generate passphrase ----------
    generateBtn.addEventListener('click', () => {
        if (busy) return;
        const pw = window.seal.generatePassphrase(5);
        passwordInput.value = pw;
        confirmInput.value = pw;
        // Make it visible so the user can read what was generated.
        showPwCheckbox.checked = true;
        passwordInput.type = 'text';
        confirmInput.type  = 'text';
        updateStrengthMeter();
        setStatus(`Generated a 5-word passphrase (~50 bits of entropy). Save it before closing this page.`);
        // Brief flash on the password field to draw attention.
        passwordInput.focus();
        passwordInput.select();
    });

    // ---------- self-destruct ----------
    async function selfDestruct() {
        passwordInput.value = '';
        confirmInput.value  = '';
        updateStrengthMeter();
        // Best-effort clipboard wipe. Will silently fail if the user hasn't
        // granted clipboard permission, which is fine — they may not have
        // copied anything.
        if (navigator.clipboard && navigator.clipboard.writeText) {
            try { await navigator.clipboard.writeText(''); }
            catch (e) { /* permission denied — that's OK */ }
        }
    }

    // ---------- page integrity verification ----------
    // Hash all the JS files we loaded (vendor + ours) and concat them. If the
    // user has the published "expected" hash from the README/repo, they can
    // compare. We can't hash the page automatically because that would
    // require fetching ourselves and the result depends on cache state — but
    // hashing the script bundle gives a meaningful integrity check.
    async function computePageIntegrity() {
        try {
            const scripts = [
                'vendor/scrypt.js', 'vendor/pako.min.js',
                'tar.js', 'zip.js', 'seal.js', 'app.js',
            ];
            const buffers = [];
            let total = 0;
            for (const url of scripts) {
                const r = await fetch(url, { cache: 'force-cache' });
                if (!r.ok) throw new Error(`${url}: ${r.status}`);
                const buf = await r.arrayBuffer();
                buffers.push({ url, buf });
                total += buf.byteLength;
            }
            // Concat all buffers and hash.
            const all = new Uint8Array(total);
            let off = 0;
            for (const { buf } of buffers) {
                all.set(new Uint8Array(buf), off);
                off += buf.byteLength;
            }
            const hash = await crypto.subtle.digest('SHA-256', all);
            const hex = Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            integrityText.innerHTML =
                'SHA-256 of the loaded scripts (vendor + app):<br>' +
                `<code>${hex}</code><br>` +
                'Compare against the value in <code>web/INTEGRITY.txt</code> in ' +
                'the source repo to confirm this page is running unmodified ' +
                'code. If they match, the bytes you\'re running are exactly ' +
                'what\'s in the repo.';
        } catch (err) {
            integrityText.textContent =
                'Could not compute page integrity hash: ' + err.message +
                '. (This usually means you opened the file directly without a server.)';
        }
    }
    // Defer until after the page is interactive so it doesn't block first paint.
    if (window.requestIdleCallback) {
        requestIdleCallback(computePageIntegrity, { timeout: 2000 });
    } else {
        setTimeout(computePageIntegrity, 500);
    }

    // ---------- main action ----------
    actionBtn.addEventListener('click', async () => {
        if (busy) return;
        if (!selection) {
            setStatus('Choose a file or folder first.', 'error');
            return;
        }

        const pw = passwordInput.value;
        if (!pw) {
            setStatus('Password cannot be empty.', 'error');
            passwordInput.focus();
            return;
        }
        if (mode === 'encrypt' && pw !== confirmInput.value) {
            setStatus('Passwords do not match.', 'error');
            confirmInput.focus();
            return;
        }

        const pwBytes = new TextEncoder().encode(pw);
        const hideName = hideNameCheckbox.checked && selection.kind === 'file';
        const shouldSelfDestruct = selfDestructCheckbox.checked;
        setBusy(true);
        let success = false;
        try {
            if (mode === 'encrypt') {
                if (selection.kind === 'file') {
                    await encryptFileFlow(selection.file, pwBytes, hideName);
                } else {
                    await encryptFolderFlow(selection, pwBytes);
                }
            } else {
                await decryptFlow(selection.file, pwBytes);
            }
            success = true;
        } catch (err) {
            console.error(err);
            setStatus(err.message || String(err), 'error');
            hideProgress();
        } finally {
            setBusy(false);
            if (success && shouldSelfDestruct) {
                await selfDestruct();
            }
        }
    });

    // ---------- encrypt: single file ----------
    async function encryptFileFlow(file, pwBytes, hideName) {
        setProgress(0, 'Deriving encryption key (~1 second)...');
        const opts = {
            onKdfProgress: (p) => setProgress(p * 0.3, 'Deriving encryption key...'),
            onCipherProgress: (p) => setProgress(0.3 + p * 0.7, 'Encrypting...'),
        };

        let blob, outName;
        if (hideName) {
            blob = await window.seal.encryptBlobHiddenName(
                file, file.name, pwBytes, opts);
            // Generate a non-revealing output name. Use a short random suffix
            // so two simultaneous downloads don't collide.
            const tag = Array.from(crypto.getRandomValues(new Uint8Array(3)))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            outName = `vault-${tag}.seal`;
        } else {
            blob = await window.seal.encryptBlob(file, pwBytes, Object.assign(
                { kind: window.seal.KIND_FILE }, opts));
            outName = file.name + '.seal';
        }
        downloadBlob(blob, outName);
        setProgress(1, 'Done.');
        const detail = hideName
            ? ` (original name '${file.name}' hidden inside)`
            : '';
        setStatus(`Encrypted → ${outName}${detail}`, 'success');
        setTimeout(hideProgress, 600);
    }

    // ---------- encrypt: folder ----------
    async function encryptFolderFlow(sel, pwBytes) {
        const files = sel.files;
        const folderName = sel.folderName;

        setProgress(0, `Reading ${files.length} files...`);

        // Build tar entries with relative paths.
        const entries = [];
        const seenDirs = new Set();
        let totalSize = 0;
        for (let i = 0; i < files.length; i++) {
            const f = files[i];
            // webkitRelativePath looks like "folderName/sub/foo.txt".
            // Strip the leading folder so the archive contains relative paths.
            const rel = (f.webkitRelativePath || f.name).split('/').slice(1).join('/');
            if (!rel) continue;
            // Ensure each parent directory has a directory entry — keeps empty
            // dirs around and matches what seal.py does.
            const parts = rel.split('/');
            let acc = '';
            for (let j = 0; j < parts.length - 1; j++) {
                acc += parts[j] + '/';
                if (!seenDirs.has(acc)) {
                    seenDirs.add(acc);
                    entries.push({ path: acc, isDirectory: true });
                }
            }
            const data = new Uint8Array(await f.arrayBuffer());
            entries.push({ path: rel, data });
            totalSize += data.length;
            if (i % 8 === 0) {
                setProgress(0.05 + 0.15 * (i / files.length),
                            `Reading files... (${i + 1}/${files.length})`);
                await new Promise(r => setTimeout(r, 0));
            }
        }

        setProgress(0.2, 'Packing archive...');
        const tarBytes = window.tar.pack(entries);

        setProgress(0.3, 'Compressing...');
        const gz = window.pako.gzip(tarBytes);
        // Free the uncompressed tar.
        // eslint-disable-next-line no-unused-vars
        const _ = null;

        setProgress(0.4, 'Deriving encryption key (~1 second)...');
        const sealBlob = await window.seal.encryptBlob(new Blob([gz]), pwBytes, {
            kind: window.seal.KIND_DIR,
            onKdfProgress: (p) => setProgress(0.4 + p * 0.3, 'Deriving encryption key...'),
            onCipherProgress: (p) => setProgress(0.7 + p * 0.3, 'Encrypting...'),
        });

        downloadBlob(sealBlob, folderName + '.seal');
        setProgress(1, 'Done.');
        setStatus(`Encrypted ${files.length} files (${fmtBytes(totalSize)}) → ${folderName}.seal`, 'success');
        setTimeout(hideProgress, 600);
    }

    // ---------- decrypt ----------
    async function decryptFlow(file, pwBytes) {
        setProgress(0, 'Reading header...');
        const info = await window.seal.peekInfo(file);

        setProgress(0.05, 'Deriving encryption key (~1 second)...');
        const result = await window.seal.decryptBlob(file, pwBytes, {
            onKdfProgress: (p) => setProgress(0.05 + p * 0.45, 'Deriving encryption key...'),
            onCipherProgress: (p) => setProgress(0.5 + p * 0.4, 'Decrypting...'),
        });

        const baseName = file.name.endsWith('.seal')
            ? file.name.slice(0, -5)
            : file.name + '.dec';

        if (result.kind === window.seal.KIND_FILE) {
            downloadBlob(result.blob, baseName);
            setProgress(1, 'Done.');
            setStatus(`Decrypted → ${baseName}`, 'success');
        } else if (result.kind === window.seal.KIND_FILE_NAMED) {
            // Recover the original filename from the embedded payload.
            const all = new Uint8Array(await result.blob.arrayBuffer());
            if (all.length < 2) {
                throw new Error('hidden-name payload too short');
            }
            const nameLen = (all[0] << 8) | all[1];
            if (all.length < 2 + nameLen) {
                throw new Error('hidden-name payload truncated');
            }
            const nameBytes = all.subarray(2, 2 + nameLen);
            let embedded;
            try {
                embedded = new TextDecoder('utf-8', { fatal: true }).decode(nameBytes);
            } catch (e) {
                throw new Error('embedded filename is not valid UTF-8');
            }
            // Sanitize: strip any path components defensively.
            const safe = embedded.replace(/\\/g, '/').split('/').pop().trim();
            if (!safe || safe === '.' || safe === '..' ||
                /[\x00-\x1f]/.test(safe)) {
                throw new Error('embedded filename is unsafe: ' + JSON.stringify(embedded));
            }
            const contentBlob = new Blob([all.subarray(2 + nameLen)]);
            downloadBlob(contentBlob, safe);
            setProgress(1, 'Done.');
            setStatus(`Decrypted → ${safe} (recovered hidden name)`, 'success');
        } else {
            // Directory: ungzip → untar → repack as ZIP for download.
            setProgress(0.9, 'Decompressing archive...');
            const gz = new Uint8Array(await result.blob.arrayBuffer());
            const tarBytes = window.pako.ungzip(gz);
            const entries = window.tar.unpack(tarBytes);

            // Filter to actual files; safe-extract logic for browser too.
            const safeEntries = [];
            for (const e of entries) {
                if (!e.isFile || e.data === null) continue;
                const path = e.path;
                if (path.startsWith('/') || path.includes('..') || path === '') {
                    throw new Error(`unsafe path in archive: ${path}`);
                }
                safeEntries.push({ path, data: e.data });
            }

            setProgress(0.95, 'Building ZIP...');
            const zipBlob = window.zip.build(safeEntries);
            downloadBlob(zipBlob, baseName + '.zip');
            setProgress(1, 'Done.');
            setStatus(`Decrypted folder → ${baseName}.zip (${safeEntries.length} files)`, 'success');
        }
        setTimeout(hideProgress, 800);
    }

    // ---------- environment checks ----------
    if (!window.crypto || !window.crypto.subtle) {
        setStatus('Web Crypto is not available. Use a modern browser served over HTTPS or localhost.', 'error');
        actionBtn.disabled = true;
    }
    if (!window.seal) {
        setStatus('seal.js failed to load. Check the browser console.', 'error');
        actionBtn.disabled = true;
    }

    // Initial UI state: strength meter visible (we start in encrypt mode).
    strengthMeter.classList.add('visible');
    updateStrengthMeter();
    setStatus('Ready. Choose a file or folder.');
})();
