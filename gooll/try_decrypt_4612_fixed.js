const fs = require('fs');
const { execSync } = require('child_process');

// ChaCha20 实现
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
    return Buffer.from(output);
}

// 主密钥
const MASTER_KEY = Buffer.from('b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676', 'hex');

console.log('尝试用主密钥解密 4612...');
const enc = fs.readFileSync('4612aa650e60e2974a9ec37bbf922c79635b493a.min.js');
console.log(`加密文件: ${enc.length} bytes`);

const dec = chacha20_decrypt(MASTER_KEY, enc);
console.log('ChaCha20 解密完成');

// 检查 LZMA 头
const magic = dec.readUInt32LE(0);
console.log(`LZMA 头: 0x${magic.toString(16)}`);

if (magic === 0x0BEDF00D) {
    console.log('✓ LZMA 头正确！主密钥有效！');
    
    const expectedSize = dec.readUInt32LE(4);
    console.log(`预期解压后大小: ${expectedSize} bytes`);
    
    const xzData = dec.slice(8);
    const tmpFile = `/tmp/4612_new_${Date.now()}`;
    fs.writeFileSync(tmpFile + '.xz', xzData);
    
    try {
        execSync(`xz -d -f "${tmpFile}.xz" 2>&1`);
        const decompressed = fs.readFileSync(tmpFile);
        fs.unlinkSync(tmpFile);
        
        console.log(`解压成功: ${decompressed.length} bytes\n`);
        fs.writeFileSync('4612_NEW_decrypted.bin', decompressed);
        console.log('已保存: 4612_NEW_decrypted.bin\n');
        
        // 搜索 C2 host
        console.log('搜索 C2 host...');
        const hostPos = decompressed.indexOf('opd6v11tc1zdoo4.fit');
        if (hostPos >= 0) {
            console.log(`\n★★★ 找到 opd6v11tc1zdoo4.fit! offset 0x${hostPos.toString(16)} ★★★\n`);
            
            const ctx = decompressed.slice(Math.max(0, hostPos - 64), hostPos + 80);
            console.log('上下文:');
            console.log(ctx.toString('ascii').replace(/[^\x20-\x7E\n]/g, '.'));
            
            console.log('\n下一步：修改这个 host → 重新加密 → 部署');
        } else {
            console.log('未找到 opd6v11tc1zdoo4.fit');
            
            // 搜索其他域名
            const text = decompressed.toString('ascii', 0, Math.min(decompressed.length, 50000));
            const domains = text.match(/[a-z0-9-]+\.(fit|xyz|work|com|net)/gi);
            if (domains) {
                console.log('找到的域名:', [...new Set(domains)].slice(0, 20));
            }
        }
    } catch (e) {
        console.error('解压失败:', e.message);
    }
} else {
    console.log('× LZMA 头不正确（期望 0x0BEDF00D）');
    console.log('前64字节:', dec.slice(0, 64).toString('hex'));
    console.log('\n可能原因：4612 用的不是主密钥');
}
