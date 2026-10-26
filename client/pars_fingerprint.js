/**
 * PARS Defense - 设备指纹检测模块
 * 
 * 功能：
 * - Safari特征检测
 * - Apple Pay支持检测
 * - WebGL2检测
 * - 调试器检测
 * - 设备输入信息检测
 * 
 * 来源：iOS_Exploit_Code_Snippets.md 第147-189行
 */

/**
 * 检测是否支持Apple Pay
 * @returns {boolean}
 */
function canUseApplePay() {
  try {
    // 检查ApplePaySession是否存在
    if (typeof ApplePaySession === 'undefined') {
      return false;
    }
    
    // 检查设备是否支持Apple Pay
    return ApplePaySession.canMakePayments();
  } catch (e) {
    return false;
  }
}

/**
 * 检测是否支持WebGL2
 * @returns {boolean}
 */
function supportsWebGL2() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2');
    return gl !== null;
  } catch (e) {
    return false;
  }
}

/**
 * 获取设备输入信息（触摸屏检测）
 * @returns {boolean}
 */
function getDeviceInputInfo() {
  try {
    // 检测触摸事件支持
    const hasTouchScreen = ('ontouchstart' in window) || 
                          (navigator.maxTouchPoints > 0) || 
                          (navigator.msMaxTouchPoints > 0);
    
    return hasTouchScreen;
  } catch (e) {
    return false;
  }
}

/**
 * 调试器检测
 * @returns {boolean}
 */
function debuggerCheck() {
  try {
    // 简单的调试器检测
    const start = performance.now();
    debugger; // 如果有调试器会暂停
    const end = performance.now();
    
    // 如果时间差过大，说明可能有调试器
    return (end - start) < 100;
  } catch (e) {
    return true;
  }
}

/**
 * Safari特征检测
 * @returns {boolean}
 */
function isSafari() {
  try {
    // 检查是否为Safari（排除Chrome和Firefox）
    const isChrome = typeof window.chrome === "object" && window.chrome !== null;
    const isFirefox = 'InstallTrigger' in window;
    const hasStandalone = "standalone" in navigator;
    const hasBackdropFilter = CSS.supports("backdrop-filter: blur(10px)") || 
                              CSS.supports("-webkit-backdrop-filter: blur(10px)");
    const hasPiP = document.pictureInPictureEnabled;
    const noVibrate = !("vibrate" in navigator);
    
    return !isChrome && !isFirefox && hasStandalone && hasBackdropFilter && hasPiP && noVibrate;
  } catch (e) {
    return false;
  }
}

/**
 * iPhone设备检测
 * @returns {boolean}
 */
function isIPhone() {
  try {
    const ua = navigator.userAgent;
    return /iPhone/.test(ua) && !(/iPad/.test(ua) || /iPod/.test(ua));
  } catch (e) {
    return false;
  }
}

/**
 * 完整的设备指纹检测（PARS Defense标准）
 * @returns {boolean} - true表示通过所有检测，是合法的iPhone Safari环境
 */
function passDeviceFingerprint() {
  try {
    // 检查sessionStorage uid（避免重复触发）
    if (sessionStorage.getItem('uid')) {
      return false;
    }
    
    // 综合检测
    const checks = {
      applePay: canUseApplePay(),
      standalone: "standalone" in navigator,
      backdropFilter: CSS.supports("backdrop-filter: blur(10px)") || 
                     CSS.supports("-webkit-backdrop-filter: blur(10px)"),
      pip: document.pictureInPictureEnabled,
      notChrome: !(typeof window.chrome === "object" && window.chrome !== null),
      notFirefox: !('InstallTrigger' in window),
      webgl2: supportsWebGL2(),
      touchScreen: getDeviceInputInfo(),
      noVibrate: !("vibrate" in navigator),
      noDebugger: debuggerCheck()
    };
    
    // 打印检测结果（调试用）
    if (typeof print === 'function') {
      print('[Device Fingerprint] Check results:');
      for (const [key, value] of Object.entries(checks)) {
        print(`  ${key}: ${value}`);
      }
    }
    
    // 所有检测必须通过
    return Object.values(checks).every(v => v === true);
  } catch (e) {
    if (typeof print === 'function') {
      print('[Device Fingerprint] Error: ' + e.message);
    }
    return false;
  }
}

/**
 * 获取设备详细信息
 * @returns {Object}
 */
function getDeviceInfo() {
  const info = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    vendor: navigator.vendor,
    language: navigator.language,
    languages: navigator.languages,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    maxTouchPoints: navigator.maxTouchPoints,
    screenWidth: screen.width,
    screenHeight: screen.height,
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  };
  
  // 提取iOS版本
  const versionMatch = /iPhone OS ([0-9_]+)/g.exec(navigator.userAgent);
  if (versionMatch) {
    info.iosVersion = versionMatch[1].replace(/_/g, '.');
  }
  
  return info;
}

// 导出函数
if (typeof window !== 'undefined') {
  window.canUseApplePay = canUseApplePay;
  window.supportsWebGL2 = supportsWebGL2;
  window.getDeviceInputInfo = getDeviceInputInfo;
  window.debuggerCheck = debuggerCheck;
  window.isSafari = isSafari;
  window.isIPhone = isIPhone;
  window.passDeviceFingerprint = passDeviceFingerprint;
  window.getDeviceInfo = getDeviceInfo;
}

if (typeof print === 'function') {
  print('[PARS Defense] Device fingerprint module loaded');
  
  // 自动执行检测
  const passed = passDeviceFingerprint();
  print(`[Device Fingerprint] Result: ${passed ? 'PASS' : 'FAIL'}`);
  
  if (passed) {
    const info = getDeviceInfo();
    print(`[Device Info] iOS: ${info.iosVersion || 'unknown'}, Screen: ${info.screenWidth}x${info.screenHeight}`);
  }
}