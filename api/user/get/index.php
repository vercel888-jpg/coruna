<?php
// GET /api/user/get —— 用户信息：原始落盘 + 应答
require_once '/www/wwwroot/i.131422.com/api/loot_raw.php';
loot_store('user_get');
loot_json_ok();
