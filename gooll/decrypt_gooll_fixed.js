#!/usr/bin/env node
/**
 * Coruna iOS Exploit Framework — Payload Decryptor
 * 
 * Decryption pipeline:
 *   1. Base64 decode (from window["qbrdr"]("...") wrapper, or raw binary)
 *   2. ChaCha20 decrypt (DJB original: 64-bit counter, 64-bit nonce=0, 20 rounds)
 *   3. Strip 8-byte LZMA header (magic 0x0BEDF00D + uint32 decompressed_size)
 *   4. XZ/LZMA decompress
 *   5. Parse F00DBEEF container → extract Mach-O dylibs
 *
 * Usage:
 *   node decrypt_coruna.js                     # Decrypt all known files
 *   node decrypt_coruna.js 7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js         # Decrypt specific file
 *   node decrypt_coruna.js --manifest-only     # Only decrypt + parse manifest
 */

const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

// ============================================================================
// ChaCha20 (DJB original variant — NOT IETF RFC 8439)
//   - 64-bit block counter (starts at 0)
//   - 64-bit nonce (all zeros for this framework)
//   - 20 rounds (10 double-rounds)
//   - State layout: sigma[4] | key[8] | counter[2] | nonce[2]
// ============================================================================

function rotl32(v, n) {
    return ((v << n) | (v >>> (32 - n))) | 0;
}

function chacha20_quarterround(state, a, b, c, d) {
    state[a] = (state[a] + state[b]) | 0; state[d] = rotl32(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) | 0; state[b] = rotl32(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) | 0; state[d] = rotl32(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) | 0; state[b] = rotl32(state[b] ^ state[c], 7);
}

function chacha20_block(key, counter_lo, counter_hi, nonce_lo, nonce_hi) {
    // "expand 32-byte k" sigma constant
    const state = new Int32Array(16);
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) state[4 + i] = key[i];
    state[12] = counter_lo; state[13] = counter_hi;
    state[14] = nonce_lo;   state[15] = nonce_hi;

    const working = new Int32Array(state);
    for (let i = 0; i < 10; i++) {
        // Column rounds
        chacha20_quarterround(working, 0, 4, 8, 12);
        chacha20_quarterround(working, 1, 5, 9, 13);
        chacha20_quarterround(working, 2, 6, 10, 14);
        chacha20_quarterround(working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarterround(working, 0, 5, 10, 15);
        chacha20_quarterround(working, 1, 6, 11, 12);
        chacha20_quarterround(working, 2, 7, 8, 13);
        chacha20_quarterround(working, 3, 4, 9, 14);
    }

    const out = new Uint8Array(64);
    const view = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) {
        view.setUint32(i * 4, (working[i] + state[i]) | 0, true);
    }
    return out;
}

function chacha20_decrypt(keyBytes, data) {
    const key = new Int32Array(8);
    const kv = new DataView(keyBytes.buffer, keyBytes.byteOffset, 32);
    for (let i = 0; i < 8; i++) key[i] = kv.getInt32(i * 4, true);

    const output = new Uint8Array(data.length);
    let counter_lo = 0, counter_hi = 0;

    for (let offset = 0; offset < data.length; offset += 64) {
        const block = chacha20_block(key, counter_lo, counter_hi, 0, 0);
        const len = Math.min(64, data.length - offset);
        for (let i = 0; i < len; i++) {
            output[offset + i] = data[offset + i] ^ block[i];
        }
        counter_lo = (counter_lo + 1) | 0;
        if (counter_lo === 0) counter_hi = (counter_hi + 1) | 0;
    }
    return output;
}

// ============================================================================
// Key derivation: fqMaGkN4 decodes uint32[] → UTF-16LE string → raw bytes
// ============================================================================

function fqMaGkN4_to_key(arr) {
    // fqMaGkN4 encodes each uint32 as 2 UTF-16 chars; when stored as UTF-16LE,
    // the raw bytes are simply the uint32 written in little-endian order.
    const buf = Buffer.alloc(arr.length * 4);
    for (let i = 0; i < arr.length; i++) {
        buf.writeUInt32LE(arr[i] >>> 0, i * 4);
    }
    return buf;
}

// ============================================================================
// Master key (from group.html fqMaGkN4 call)
// ============================================================================

const MASTER_KEY = fqMaGkN4_to_key([
    3436285875, 2332907478, 2884495420, 233193687,
    1144711575, 1605576699, 1942246444, 1994816675
]);
// = b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676

// ============================================================================
// Decrypt + decompress pipeline
// ============================================================================

function extractBase64FromQbrdr(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const match = content.match(/window\["qbrdr"\]\("([^"]+)"\)/);
    if (match) return Buffer.from(match[1], 'base64');
    // If not qbrdr-wrapped, treat as raw binary
    return fs.readFileSync(filePath);
}

function decryptPayload(encryptedData, keyHex) {
    const keyBuf = Buffer.from(keyHex, 'hex');
    return chacha20_decrypt(new Uint8Array(keyBuf), new Uint8Array(encryptedData));
}

function decompressLZMA(decryptedData) {
    // Verify LZMA header: magic 0x0BEDF00D (LE)
    const magic = Buffer.from(decryptedData.slice(0, 4)).readUInt32LE(0);
    if (magic !== 0x0BEDF00D) {
        throw new Error(`Invalid LZMA header magic: 0x${magic.toString(16)} (expected 0x0BEDF00D)`);
    }
    const expectedSize = Buffer.from(decryptedData.slice(4, 8)).readUInt32LE(0);
    const xzData = Buffer.from(decryptedData.slice(8));

    // XZ magic check
    if (xzData[0] !== 0xFD || xzData[1] !== 0x37 || xzData[2] !== 0x7A) {
        throw new Error('XZ stream magic not found after LZMA header');
    }

    const tmpFile = `/tmp/coruna_dec_${Date.now()}`;
    fs.writeFileSync(tmpFile + '.xz', xzData);
    execSync(`xz -d -f "${tmpFile}.xz"`);
    const decompressed = fs.readFileSync(tmpFile);
    fs.unlinkSync(tmpFile);

    if (decompressed.length !== expectedSize) {
        console.warn(`  Warning: decompressed size ${decompressed.length} != expected ${expectedSize}`);
    }
    return decompressed;
}

function parseF00DBEEF(data) {
    const magic = data.readUInt32LE(0);
    if (magic !== 0xF00DBEEF) {
        throw new Error(`Not a F00DBEEF container: 0x${magic.toString(16)}`);
    }
    const entryCount = data.readUInt32LE(4);
    const entries = [];

    for (let i = 0; i < entryCount; i++) {
        const base = 8 + i * 16;
        const field1 = data.readUInt32LE(base);
        const type = (field1 >>> 16) & 0xFFFF;
        const flags = data.readUInt32LE(base + 4);
        const offset = data.readUInt32LE(base + 8);
        const size = data.readUInt32LE(base + 12);
        const entryData = data.slice(offset, offset + size);

        let format = 'unknown';
        if (entryData.length >= 4) {
            const m = entryData.readUInt32LE(0);
            if (m === 0xFEEDFACF) format = 'macho-64';
            else if (m === 0xFEEDFACE) format = 'macho-32';
            else if (m === 0xDEADD00F) format = 'deadd00f-config';
            else if (m === 0x12345678) format = 'metadata';
        }
        entries.push({ type, flags, offset, size, format, data: entryData });
    }
    return { entryCount, entries };
}

// ============================================================================
// Manifest parser
// ============================================================================

function parseManifest(manifestContainer) {
    // The manifest is a F00DBEEF with 1 entry (type 0x07) containing the module list
    const container = parseF00DBEEF(manifestContainer);
    const data = container.entries[0].data;

    // Find first filename to determine entry offset
    const firstFilenamePos = data.indexOf('min.js') - 47; // 40-char hash + ".min.js" starts 47 before "min.js" ends
    // Actually: find the first 40-char hex hash
    const hashRegex = /[0-9a-f]{40}\.min\.js/;
    let searchBuf = data.toString('ascii');
    let match = searchBuf.match(hashRegex);
    if (!match) throw new Error('No filenames found in manifest data');

    // Each entry is 100 bytes, filename at +0x28
    // Work backwards from filename position to find entry start
    const filenameInData = data.indexOf(match[0]);
    const entryStart = filenameInData - 0x28;

    const modules = [];
    let offset = entryStart;
    while (offset + 100 <= manifestContainer.length) {
        const flags = manifestContainer.readUInt16LE(offset + 6 + container.entries[0].offset);
        // Read from the container's data buffer
        const absOff = container.entries[0].offset + (offset - entryStart) + (entryStart - 0);
        // Simpler: just use the decompressed manifest directly
        const entryBuf = manifestContainer.slice(offset, offset + 100);
        const entryFlags = entryBuf.readUInt16LE(6);
        const key = entryBuf.slice(8, 40);
        const filename = entryBuf.slice(0x28, 0x28 + 48).toString('ascii').replace(/\x00.*/, '');

        if (filename.length < 5 || !filename.includes('.')) break;

        modules.push({
            flags: entryFlags,
            key: key.toString('hex'),
            filename
        });
        offset += 100;
    }
    return modules;
}

// ============================================================================
// Main
// ============================================================================

function main() {
    const args = process.argv.slice(2);
    const outDir = path.join(__dirname, 'decrypted');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    console.log('=== Coruna Payload Decryptor ===\n');
    console.log('Master Key:', MASTER_KEY.toString('hex'));
    console.log('Algorithm:  ChaCha20-DJB (64-bit counter, 64-bit nonce=0, 20 rounds)\n');

    // Step 1: Decrypt manifest (7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js)
    const manifestFile = path.join(__dirname, '7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js');
    if (!fs.existsSync(manifestFile)) {
        console.error('ERROR: 7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js not found');
        process.exit(1);
    }

    console.log('[1] Decrypting manifest: 7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js');
    const encManifest = extractBase64FromQbrdr(manifestFile);
    const decManifest = decryptPayload(encManifest, MASTER_KEY.toString('hex'));
    const manifest = decompressLZMA(decManifest);
    console.log(`    Decrypted: ${encManifest.length} bytes → ${manifest.length} bytes`);

    // Save decrypted manifest
    fs.writeFileSync(path.join(outDir, 'manifest.bin'), manifest);
    console.log(`    Saved: decrypted/manifest.bin`);

    // Parse manifest entries
    const container = parseF00DBEEF(manifest);
    const moduleData = container.entries[0].data;

    // Find entries manually (same logic as above)
    const hashRegex = /[0-9a-f]{40}\.min\.js/g;
    const searchStr = manifest.toString('ascii');
    let m;
    const firstMatch = searchStr.match(/[0-9a-f]{40}\.min\.js/);
    const firstPos = manifest.indexOf(firstMatch[0]);
    const baseOffset = firstPos - 0x28;

    console.log(`\n[2] Manifest entries (${Math.floor((manifest.length - baseOffset) / 100)} modules):\n`);
    console.log('    # | Flags  | Key (hex)                                                        | Filename');
    console.log('    --|--------|------------------------------------------------------------------|--------------------------------------------------');

    const modules = [];
    let off = baseOffset;
    let idx = 0;
    while (off + 100 <= manifest.length) {
        const flags = manifest.readUInt16LE(off + 6);
        const key = manifest.slice(off + 8, off + 8 + 32).toString('hex');
        const filename = manifest.slice(off + 0x28, off + 0x28 + 48).toString('ascii').replace(/\x00.*/g, '');
        if (filename.length < 5) break;

        modules.push({ flags, key, filename });
        console.log(`   ${String(idx).padStart(2)} | 0x${flags.toString(16).padStart(4,'0')} | ${key} | ${filename}`);
        off += 100;
        idx++;
    }

    if (args.includes('--manifest-only')) {
        console.log('\n[Done] Manifest-only mode.');
        return;
    }

    // Step 3: Decrypt payload files that exist locally
    console.log(`\n[3] Decrypting payload files...\n`);

    for (const mod of modules) {
        // Look for the file (with or without full hash name)
        const shortHash = mod.filename.replace('.min.js', '').substring(0, 8);
        let filePath = null;

        // Try exact filename
        const candidates = [
            path.join(__dirname, mod.filename),
            path.join(__dirname, shortHash + '.min.js'),
            path.join(__dirname, shortHash + '.js'),
        ];
        for (const c of candidates) {
            if (fs.existsSync(c)) { filePath = c; break; }
        }

        if (!filePath) {
            // Check if the reference_files has a matching file
            const localFiles = fs.readdirSync(__dirname);
            const matchFile = localFiles.find(f => f.startsWith(shortHash));
            if (matchFile) filePath = path.join(__dirname, matchFile);
        }

        if (!filePath) {
            console.log(`    SKIP: ${mod.filename} (not found locally)`);
            continue;
        }

        console.log(`    Decrypting: ${path.basename(filePath)}`);
        try {
            const enc = extractBase64FromQbrdr(filePath);
            const dec = decryptPayload(enc, mod.key);
            const decompressed = decompressLZMA(dec);
            const parsed = parseF00DBEEF(decompressed);

            const baseHash = mod.filename.replace('.min.js', '');
            const modDir = path.join(outDir, baseHash);
            if (!fs.existsSync(modDir)) fs.mkdirSync(modDir, { recursive: true });

            fs.writeFileSync(path.join(modDir, 'container.bin'), decompressed);

            for (let i = 0; i < parsed.entries.length; i++) {
                const e = parsed.entries[i];
                const ext = e.format.startsWith('macho') ? '.dylib' : '.bin';
                const entryFile = `entry${i}_type0x${e.type.toString(16).padStart(2,'0')}${ext}`;
                fs.writeFileSync(path.join(modDir, entryFile), e.data);
                console.log(`      → ${entryFile} (${e.size} bytes, ${e.format})`);
            }
        } catch (e) {
            console.log(`      ERROR: ${e.message}`);
        }
    }

    console.log('\n[Done] Decrypted payloads saved to: ' + outDir);
}

main();
