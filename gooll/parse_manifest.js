const fs = require('fs');
const data = fs.readFileSync('7a7d99099b035b2c6512b6ebeeea6df1ede70fbb.js', 'utf8');
const match = data.match(/window\["qbrdr"\]\("([^"]+)"\)/);
if (!match) {
    console.log('ERROR: Not a qbrdr file');
    process.exit(1);
}

const base64 = match[1];
const enc = Buffer.from(base64, 'base64');

// 直接解密（用主密钥）
const MASTER_KEY = Buffer.from('b38fd1ccd6570d8b3ce8edabd740e60d97e93a44fb27b35f2c54c473a37ce676', 'hex');

// ChaCha20简化版（只解密前2KB看结构）
function chacha20_decrypt_simple(key, data) {
    // 这里简化：直接用 Node 的 crypto（如果支持）或手工实现
    // 但为了快速看，先输出加密数据前64字节
    console.log('加密数据前64字节:', enc.slice(0, 64).toString('hex'));
    console.log('加密数据大小:', enc.length, 'bytes');
}

chacha20_decrypt_simple(MASTER_KEY, enc);

// 尝试猜测：gooll 链的 4612 可能不在 manifest 里，直接用固定 key
// 查看老版 manifest（已解密）
const oldManifest = fs.readFileSync('/www/wwwroot/i.131422.com/coruna/payloads/7a7d99099b035b2c6512b6ebeeea6df1ede70fbb/raw.bin');
console.log('\n老版 coruna manifest 里的模块:');
const hashRegex = /[0-9a-f]{40}\.min\.js/g;
let m;
while (m = hashRegex.exec(oldManifest.toString('ascii'))) {
    console.log('  ', m[0]);
}
