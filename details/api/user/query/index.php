<?php
// POST/GET /api/user/query —— 原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('query');
loot_json_ok();
