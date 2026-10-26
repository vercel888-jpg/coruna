#!/usr/bin/env node
/**
 * 快速解密 gooll 链的 4612（新版 228352B）
 * 复用 decrypt_coruna.js 的核心逻辑
 */

const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

// ChaCha20-DJB 实现（复制自 decrypt_coruna.js）
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
    const state = new Int32Array(16);
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) state[4 + i] = key[i];
    state[12] = counter_lo; state[13] = counter_hi;
    state[14] = nonce_lo;   state[15] = nonce_hi;

    const working = new Int32Array(state);
    for (let i = 0; i < 10; i++) {
        chacha20_quarterround(working, 0, 4, 8, 12);
        chacha20_quarterround(working, 1, 5, 9, 13);
        chacha20_quarterround(working, 2, 6, 10, 14);
        chacha20_quarterround(working, 3, 7, 11, 15);
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

function extractBase64FromQbrdr(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const match = content.match(/window\["qbrdr"\]\("([^"]+)"\)/);
    if (match) return Buffer.from(match[1], 'base64');
    return fs.readFileSync(filePath);
}

function decryptPayload(encryptedData, keyHex) {
    const keyBuf = Buffer.from(keyHex, 'hex');
    return chacha20_decrypt(new Uint8Array(keyBuf), new Uint8Array(encryptedData));
}

function decompressLZMA(decryptedData) {
    const magic = Buffer.from(decryptedData.slice(0, 4)).readUInt32LE(0);
    if (magic !== 0x0BEDF00D) {
        throw new Error(`Invalid LZMA header magic: 0x${magic.toString(16)}`);
    }
    const expectedSize = Buffer.from(decryptedData.slice(4, 8)).readUInt32LE(0);
    const xzData = Buffer.from(decryptedData.slice(8));

    const tmpFile = `/tmp/gooll_4612_${Date.now()}`;
    fs.writeFileSync(tmpFile + '.xz', xzData);
    execSync(`xz -d -f "${tmpFile}.xz"`);
    const decompressed = fs.readFileSync(tmpFile);
    fs.unlinkSync(tmpFile);

    if (decompressed.length !== expectedSize) {
        console.warn(`Warning: decompressed size ${decompressed.length} != expected ${expectedSize}`);
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
        entries.push({ type, flags, offset, size, data: data.slice(offset, offset + size) });
    }
    return { entryCount, entries };
}

// 主密钥
const MASTER_KEY = Buffer.from('b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676', 'hex');

console.log('=== 解密 gooll 链 4612 ===\n');

// 1. 解密 manifest
console.log('[1] 解密 manifest: 7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js');
const manifestFile = '7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js';
const encManifest = extractBase64FromQbrdr(manifestFile);
const decManifest = decryptPayload(encManifest, MASTER_KEY.toString('hex'));
const manifest = decompressLZMA(decManifest);
console.log(`    ${encManifest.length} bytes → ${manifest.length} bytes\n`);

// 2. 从 manifest 提取 4612 的 key
const hashRegex = /[0-9a-f]{40}\.min\.js/g;
const firstMatch = manifest.toString('ascii').match(/[0-9a-f]{40}\.min\.js/);
const firstPos = manifest.indexOf(firstMatch[0]);
const baseOffset = firstPos - 0x28;

console.log('[2] Manifest entries:\n');
const modules = [];
let off = baseOffset;
let idx = 0;
while (off + 100 <= manifest.length) {
    const flags = manifest.readUInt16LE(off + 6);
    const key = manifest.slice(off + 8, off + 8 + 32).toString('hex');
    const filename = manifest.slice(off + 0x28, off + 0x28 + 48).toString('ascii').replace(/\x00.*/g, '');
    if (filename.length < 5) break;
    modules.push({ flags, key, filename });
    
    if (filename.includes('4612aa65')) {
        console.log(`    [${idx}] 4612 key: ${key}`);
        console.log(`        File: ${filename}\n`);
    }
    off += 100;
    idx++;
}

// 3. 解密 4612
const mod4612 = modules.find(m => m.filename.includes('4612aa65'));
if (!mod4612) {
    console.error('ERROR: 4612 not found in manifest');
    process.exit(1);
}

console.log('[3] 解密 4612aa650e60e2974a9ec37bbf922c79635b493a.min.js');
const enc4612 = fs.readFileSync('4612aa650e60e2974a9ec37bbf922c79635b493a.min.js');
const dec4612 = decryptPayload(enc4612, mod4612.key);
const decompressed4612 = decompressLZMA(dec4612);
console.log(`    ${enc4612.length} bytes → ${decompressed4612.length} bytes`);

// 4. 解析 F00DBEEF 容器
const container = parseF00DBEEF(decompressed4612);
console.log(`    F00DBEEF container: ${container.entryCount} entries\n`);

// 5. 保存解密后的文件
fs.writeFileSync('4612_decrypted.bin', decompressed4612);
console.log('[4] 已保存: 4612_decrypted.bin');

// 6. 搜索 C2 host
console.log('\n[5] 搜索 C2 host (opd6v11tc1zdoo4.fit):\n');
const hostPos = decompressed4612.indexOf('opd6v11tc1zdoo4.fit');
if (hostPos >= 0) {
    console.log(`    找到! offset 0x${hostPos.toString(16)}`);
    const ctx = decompressed4612.slice(Math.max(0, hostPos - 32), hostPos + 80);
    console.log(`    上下文: ${ctx.toString('ascii').replace(/[^\x20-\x7E]/g, '.')}`);
} else {
    console.log('    未找到明文 opd6v11tc1zdoo4.fit');
    console.log('    可能在 entry Mach-O 内部，提取各 entry...\n');
    
    for (let i = 0; i < container.entries.length; i++) {
        const e = container.entries[i];
        const entryFile = `4612_entry${i}_type0x${e.type.toString(16).padStart(2,'0')}.bin`;
        fs.writeFileSync(entryFile, e.data);
        console.log(`    → ${entryFile} (${e.size} bytes)`);
        
        // 搜索 entry 内部
        const pos = e.data.indexOf('opd6v11tc1zdoo4.fit');
        if (pos >= 0) {
            console.log(`       ★ 找到 C2 host! offset 0x${pos.toString(16)}`);
        }
    }
}

console.log('\n[Done] 解密完成。下一步：修改 C2 host → 重新加密 → 部署');
