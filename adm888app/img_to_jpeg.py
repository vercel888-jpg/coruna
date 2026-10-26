#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""img_to_jpeg.py — 标准输入(图片字节) → 标准输出(JPEG)。

用途：面板照片展示（/api/user/user_photo/raw）遇到 HEIC 时调用 —— 浏览器无法解码 HEIC，
Node 侧无解码器，经本助手转 JPEG（最长边 2000，q88，保留查看清晰度）。
依赖：pillow + pillow_heif（/root/venv，与 DS 扫描器同环境）。
"""
import sys, io

def main():
    from PIL import Image
    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except Exception:
        pass
    raw = sys.stdin.buffer.read()
    im = Image.open(io.BytesIO(raw))
    im = im.convert('RGB')
    mx = max(im.size)
    if mx > 2000:
        r = 2000 / mx
        im = im.resize((max(1, int(im.size[0] * r)), max(1, int(im.size[1] * r))), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, 'JPEG', quality=88)
    sys.stdout.buffer.write(buf.getvalue())

if __name__ == '__main__':
    main()
