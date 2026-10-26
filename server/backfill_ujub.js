const fs=require('fs'), path=require('path');
const { decryptReport } = require('/www/wwwroot/i.131422.com/server/decrypt_reports.js');
const UP='/www/wwwroot/i.131422.com/loot/unknown_posts';
const files=fs.readdirSync(UP).filter(f=>/^post_(uj|ub)_\d+\.bin$/.test(f));
let ok=0, fail=0;
for (const f of files) {
  const mp=path.join(UP,f.replace(/\.bin$/,'.meta.json'));
  let ip='unknown';
  try { ip=(JSON.parse(fs.readFileSync(mp,'utf8')).ip||'unknown').replace(/[^0-9a-f:.]/gi,'_'); } catch(e){}
  const devDir=path.join('/www/wwwroot/i.131422.com/loot', ip);
  fs.mkdirSync(devDir,{recursive:true});
  const base=f.replace(/^post_/,'report_');
  fs.copyFileSync(path.join(UP,f), path.join(devDir, base));
  if (fs.existsSync(mp)) fs.copyFileSync(mp, path.join(devDir, base.replace(/\.bin$/,'.meta.json')));
  const r=decryptReport(path.join(UP,f));
  if (r.success) {
    fs.writeFileSync(path.join(devDir, base.replace(/\.bin$/,'.dec.json')), JSON.stringify(r.data,null,2));
    console.log('[OK]  ', f, '-> loot/'+ip, ' x_ts='+r.x_ts); ok++;
  } else { console.log('[FAIL]', f, '-> loot/'+ip, r.error); fail++; }
}
console.log('\n补录完成: ok='+ok+' fail='+fail+'  (原文件保留在 unknown_posts/)');
