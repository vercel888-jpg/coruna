/**
 * module_integrity.js - 模块完整性验证
 * 
 * 为 DarkSword-RCE 提供基于哈希的模块完整性验证
 * 防止中间人攻击和代码注入
 */

(function() {
  'use strict';

  // 已知模块的 SHA-256 哈希值
  // 注意：这些哈希值需要在部署时通过构建脚本生成和注入
  const MODULE_HASHES = {
    // 核心模块（示例哈希，需要实际计算）
    'beacon.js': '',
    'rce_module.js': '',
    'rce_module_18.6.js': '',
    'rce_module_26.js': '',
    'exploit_selector.js': '',
    'fallback_executor.js': '',
    'exploit_registry.js': '',
    'metric_collector.js': '',
    'native_bridge.js': '',
    'ghostknife.js': '',
    'sbx0_main_18.4.js': '',
    'sbx1_main.js': '',
    'attack_chain_orchestrator.js': '',
    // 可以添加更多模块
  };

  /**
   * 计算字符串的 SHA-256 哈希
   */
  async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * 验证模块完整性
   */
  async function verifyModule(filename, code) {
    // 如果没有配置哈希值，跳过验证（开发模式）
    const expectedHash = MODULE_HASHES[filename];
    if (!expectedHash || expectedHash === '') {
      console.warn(`[Integrity] No hash configured for ${filename}, skipping verification`);
      return { valid: true, reason: 'no_hash_configured' };
    }

    try {
      const actualHash = await sha256(code);
      
      if (actualHash === expectedHash) {
        return { valid: true, hash: actualHash };
      } else {
        console.error(`[Integrity] Module integrity check FAILED for ${filename}`);
        console.error(`  Expected: ${expectedHash}`);
        console.error(`  Actual:   ${actualHash}`);
        return { 
          valid: false, 
          reason: 'hash_mismatch',
          expected: expectedHash,
          actual: actualHash
        };
      }
    } catch (e) {
      console.error(`[Integrity] Error verifying ${filename}:`, e);
      return { valid: false, reason: 'verification_error', error: e.message };
    }
  }

  /**
   * 安全加载并验证模块
   */
  async function loadAndVerifyModule(filename, code) {
    const result = await verifyModule(filename, code);
    
    if (!result.valid) {
      // 完整性验证失败
      const error = new Error(`Module integrity verification failed: ${filename} (${result.reason})`);
      error.filename = filename;
      error.verificationResult = result;
      throw error;
    }
    
    // 验证通过，执行代码
    console.log(`[Integrity] ✓ ${filename} verified (${result.hash ? result.hash.substring(0, 16) + '...' : 'skipped'})`);
    eval(code);
  }

  /**
   * 生成当前模块的哈希值（用于部署时计算哈希）
   */
  async function generateModuleHash(filename, code) {
    const hash = await sha256(code);
    console.log(`[Integrity] Hash for ${filename}:`);
    console.log(`  '${filename}': '${hash}',`);
    return hash;
  }

  // 导出到全局作用域
  globalThis.loadAndVerifyModule = loadAndVerifyModule;
  globalThis.verifyModule = verifyModule;
  globalThis.generateModuleHash = generateModuleHash;
  globalThis.MODULE_HASHES = MODULE_HASHES;

  console.log('[Integrity] Module integrity verification system loaded');
})();