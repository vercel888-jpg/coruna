#!/usr/bin/env node
/**
 * DarkSword 客户端构建脚本
 * 
 * 功能：
 * 1. 从 .env 读取 DS_SHARED_SECRET
 * 2. 注入到 beacon.js 中
 * 3. 生成 client/beacon.build.js
 * 
 * 用法：
 *   node scripts/build_client.js
 *   或在部署前通过 package.json scripts 调用
 */

'use strict';
const fs = require('fs');
const path = require('path');

// 读取 .env 文件
function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) {
    console.error('错误: .env 文件不存在，请从 .env.example 复制并配置');
    console.error(`期望路径: ${envPath}`);
    process.exit(1);
  }
  
  const envContent = fs.readFileSync(envPath, 'utf-8');
  const env = {};
  
  envContent.split('\n').forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match) {
      env[match[1]] = match[2].trim();
    }
  });
  
  return env;
}

// 主构建流程
function buildClient() {
  console.log('[Build] DarkSword 客户端构建开始...\n');
  
  // 1. 加载环境变量
  const env = loadEnv();
  const SHARED_SECRET = env.DS_SHARED_SECRET || '';
  
  if (!SHARED_SECRET) {
    console.error('错误: DS_SHARED_SECRET 未在 .env 中设置');
    console.error('请运行: openssl rand -hex 32');
    console.error('并将结果设置到 .env 的 DS_SHARED_SECRET');
    process.exit(1);
  }
  
  console.log('[Build] ✓ DS_SHARED_SECRET 已加载 (长度: ' + SHARED_SECRET.length + ')');
  
  // 2. 读取 beacon.js 源文件
  const beaconSrcPath = path.join(__dirname, '..', 'client', 'beacon.js');
  if (!fs.existsSync(beaconSrcPath)) {
    console.error('错误: client/beacon.js 不存在');
    process.exit(1);
  }
  
  let beaconContent = fs.readFileSync(beaconSrcPath, 'utf-8');
  console.log('[Build] ✓ beacon.js 源文件已读取');
  
  // 3. 注入 DS_SHARED_SECRET
  // 在 IIFE 开头注入常量定义
  const injectionCode = `  // ── 构建时注入的共享密钥（由 scripts/build_client.js 生成）──
  const DS_SHARED_SECRET = '${SHARED_SECRET}';
`;
  
  // 在 (function() { 'use strict'; 之后注入
  const injectionPattern = /(\(function\(\)\s*\{\s*'use strict';)/;
  if (!injectionPattern.test(beaconContent)) {
    console.error('错误: beacon.js 格式不符合预期，无法注入 DS_SHARED_SECRET');
    console.error('期望找到: (function() { \'use strict\';');
    process.exit(1);
  }
  
  const beforeInjection = beaconContent;
  beaconContent = beaconContent.replace(injectionPattern, `$1\n${injectionCode}`);
  
  if (beaconContent === beforeInjection) {
    console.error('错误: DS_SHARED_SECRET 注入失败（正则替换未生效）');
    process.exit(1);
  }
  
  console.log('[Build] ✓ DS_SHARED_SECRET 已注入到 beacon.js');
  
  // 4. 写入构建产物
  const beaconBuildPath = path.join(__dirname, '..', 'client', 'beacon.build.js');
  fs.writeFileSync(beaconBuildPath, beaconContent, 'utf-8');
  console.log('[Build] ✓ 构建产物已写入: client/beacon.build.js');
  
  // 5. 创建符号链接指向说明
  const buildReadmePath = path.join(__dirname, '..', 'client', 'BUILD_README.txt');
  const buildReadme = `DarkSword 客户端构建产物说明
================================

beacon.build.js 是由 scripts/build_client.js 从 beacon.js 构建生成的，
已注入 DS_SHARED_SECRET 用于设备认证。

部署说明：
---------
1. 开发模式：直接使用 beacon.js（会从 globalThis 读取 SHARED_SECRET）
2. 生产模式：使用 beacon.build.js（已硬编码 SHARED_SECRET）

重新构建：
---------
  node scripts/build_client.js

注意事项：
---------
- 请勿将 beacon.build.js 提交到版本控制
- .gitignore 已配置忽略 *.build.js
- 每次修改 .env 中的 DS_SHARED_SECRET 后需重新构建

生成时间: ${new Date().toISOString()}
`;
  
  fs.writeFileSync(buildReadmePath, buildReadme, 'utf-8');
  console.log('[Build] ✓ 构建说明已写入: client/BUILD_README.txt');
  
  // 6. 验证注入结果
  const verifyContent = fs.readFileSync(beaconBuildPath, 'utf-8');
  if (!verifyContent.includes(`const DS_SHARED_SECRET = '${SHARED_SECRET}'`)) {
    console.error('错误: 注入验证失败，构建产物中未找到 DS_SHARED_SECRET');
    process.exit(1);
  }
  console.log('[Build] ✓ 注入验证通过');
  
  console.log('\n[Build] ═══════════════════════════════════════');
  console.log('[Build] 构建完成！');
  console.log('[Build] ═══════════════════════════════════════');
  console.log('[Build]');
  console.log('[Build] 开发模式：使用 client/beacon.js');
  console.log('[Build] 生产模式：使用 client/beacon.build.js');
  console.log('[Build]');
  console.log('[Build] 下一步：');
  console.log('[Build]   1. 在 rce_loader.js 中将 beacon.js 改为 beacon.build.js');
  console.log('[Build]   2. 或配置服务器根据环境变量动态选择');
  console.log('[Build]');
}

// 执行构建
try {
  buildClient();
} catch (error) {
  console.error('\n[Build] 构建失败:', error.message);
  console.error(error.stack);
  process.exit(1);
}