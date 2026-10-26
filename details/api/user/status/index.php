<?php
// POST/GET /api/user/status —— 原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('status');
loot_json_ok();
