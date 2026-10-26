<?php
// POST/GET /api/user/set —— 原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('set');
loot_json_ok();
