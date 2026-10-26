/**
 * log_panel.js — 投递页实时日志面板
 *
 * 子模式（frame.html 内）：patch console.log/warn/error/info，把每一步日志
 *   显示在本页面板上，同时 postMessage 转发给父页面。
 * 父模式（index.html）：显示日志面板，监听 iframe 转发的日志。
 *
 * 用法：两个页面都引入本脚本即可自动区分模式。
 */
(function () {
  'use strict';

  var MAX_LINES = 500;
  var MAX_MSG = 800;
  var lines = 0;
  var panel = null;
  var bodyEl = null;
  var isChild = false;

  try { isChild = window.top !== window.self; } catch (e) { isChild = true; }

  function ensurePanel() {
    if (panel) return;
    bodyEl = document.body || document.documentElement;
    var style = document.createElement('style');
    style.textContent = [
      '#dslog{position:fixed;left:0;right:0;bottom:0;z-index:999999;',
      'background:rgba(8,10,16,.92);color:#d4ffd4;font:11px/1.5 Menlo,Consolas,monospace;',
      'max-height:45vh;overflow-y:auto;padding:6px 8px;border-top:2px solid #22c55e;',
      'text-align:left;word-break:break-all;white-space:pre-wrap;pointer-events:auto}',
      '#dslog .dslog-head{position:sticky;top:0;background:#111827;color:#fff;',
      'font-weight:700;font-size:11px;padding:4px 6px;margin:-6px -8px 4px;',
      'display:flex;justify-content:space-between;align-items:center;cursor:pointer}',
      '#dslog .dslog-head b{color:#22c55e}',
      '#dslog .dslog-clear{background:#374151;border:none;color:#fff;font-size:10px;',
      'padding:2px 8px;border-radius:3px;cursor:pointer}',
      '#dslog .dslog-line{color:#9ca3af}#dslog .dslog-line.ok{color:#86efac}',
      '#dslog .dslog-line.err{color:#f87171}#dslog .dslog-line.warn{color:#fbbf24}',
      '@media(max-width:600px){#dslog{font-size:10px;max-height:50vh}}'
    ].join('');
    document.head.appendChild(style);

    panel = document.createElement('div');
    panel.id = 'dslog';
    panel.innerHTML =
      '<div class="dslog-head"><span>DarkSword <b>投递日志</b></span>' +
      '<button class="dslog-clear">清空/收起</button></div>';
    panel.addEventListener('click', function (e) {
      if (e.target && e.target.className === 'dslog-clear') {
        var body = panel.querySelector('.dslog-body');
        if (body && body.children.length > 0) {
          body.innerHTML = '';
          lines = 0;
        } else {
          panel.style.display = panel.style.display === 'none' ? '' : 'none';
        }
      }
    });
    var body = document.createElement('div');
    body.className = 'dslog-body';
    panel.appendChild(body);
    bodyEl.appendChild(panel);
  }

  function append(text, cls) {
    try {
      ensurePanel();
      var body = panel.querySelector('.dslog-body');
      var div = document.createElement('div');
      div.className = 'dslog-line' + (cls ? ' ' + cls : '');
      var t = String(text);
      if (t.length > MAX_MSG) t = t.slice(0, MAX_MSG) + '…';
      div.textContent = '[' + (Date.now() % 100000) + 'ms] ' + t;
      body.appendChild(div);
      if (++lines > MAX_LINES) {
        body.removeChild(body.firstChild);
        lines--;
      }
      panel.scrollTop = panel.scrollHeight;
    } catch (e) {}
  }

  function forward(text) {
    try {
      if (isChild) window.parent.postMessage({ type: 'dslog', text: String(text) }, '*');
    } catch (e) {}
  }

  function log(text, cls) {
    append(text, cls);
    forward(text);
  }

  function patchConsole() {
    var orig = {
      log: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console),
      info: console.info.bind(console)
    };
    console.log = function () {
      var args = Array.prototype.slice.call(arguments);
      orig.log.apply(console, args);
      log(args.map(function (a) {
        try { return typeof a === 'string' ? a : JSON.stringify(a); }
        catch (e) { return String(a); }
      }).join(' '));
    };
    console.warn = function () {
      var args = Array.prototype.slice.call(arguments);
      orig.warn.apply(console, args);
      log(args.map(String).join(' '), 'warn');
    };
    console.error = function () {
      var args = Array.prototype.slice.call(arguments);
      orig.error.apply(console, args);
      log(args.map(String).join(' '), 'err');
    };
    console.info = function () {
      var args = Array.prototype.slice.call(arguments);
      orig.info.apply(console, args);
      log(args.map(String).join(' '));
    };
    window.addEventListener('error', function (e) {
      var msg = (e.message || '') + (e.filename ? ' @ ' + e.filename.split('/').pop() : '');
      log('[page-error] ' + msg + (e.lineno ? ' L' + e.lineno : ''), 'err');
    }, true);
    window.addEventListener('unhandledrejection', function (e) {
      log('[promise-reject] ' + (e.reason && e.reason.message ? e.reason.message : String(e.reason)), 'err');
    });
  }

  if (isChild) {
    // 子模式：patch console 并把日志转发给父页面
    window.addEventListener('message', function (e) {
      if (e.data && e.data.type === 'dslog') append(e.data.text);
    });
    patchConsole();
    log('[log-panel] 日志面板已启用（子页面）');
  } else {
    // 父模式：显示面板，接收 iframe 转发的日志
    window.addEventListener('message', function (e) {
      if (e.data && e.data.type === 'dslog') append(e.data.text);
    });
    window.addEventListener('DOMContentLoaded', function () {
      ensurePanel();
      log('[log-panel] 投递日志面板已启用，等待目标访问…');
    });
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
      ensurePanel();
      log('[log-panel] 投递日志面板已启用，等待目标访问…');
    }
  }
})();
