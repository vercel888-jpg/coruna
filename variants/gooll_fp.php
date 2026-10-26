<?php
/**
 * gooll_fp.php - gooll.html 指纹种子（访问即记录同 IP 投递标记）
 * nginx: location = /gooll/gooll.html 改为 fastcgi 执行本文件（内部 readfile 原 gooll.html 内容）
 * 与 corefile.php 的 FP_WINDOW/FP_FILE 匹配
 */
define('FP_FILE', '/tmp/pl_cf_fp/');
$ip = $_SERVER['REMOTE_ADDR'];
@mkdir(FP_FILE, 0775, true);
@touch(FP_FILE . md5($ip));   // 刷新指纹时间戳
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Expires: -1');
readfile('/www/wwwroot/i.131422.com/gooll/gooll.html');
