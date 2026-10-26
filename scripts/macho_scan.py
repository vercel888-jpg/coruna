#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""macho_scan.py — 在 core dylib（fat Mach-O）里定位某个导入符号的 stub 与全部调用点

用于 /t 解密工程：找 _CCCrypt 的调用位置，反推 key 派生链。
需要: pip install capstone

用法:
    macho_scan.py <dylib> sym  <符号名>     # 列出符号所在 stub 地址
    macho_scan.py <dylib> call <符号名>     # 列出所有 bl 到该符号 stub 的调用点
    macho_scan.py <dylib> info              # 打印切片/段/节概况
"""
import sys
import struct

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except Exception:
    print('!! 缺 capstone: pip install capstone')
    raise SystemExit(2)

MH_MAGIC_64 = 0xfeedfacf
FAT_MAGIC = 0xcafebabe
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
N_UNDF = 0x0
N_TYPE = 0x0e


def rd(f, off, n):
    f.seek(off)
    return f.read(n)


def parse_fat(f):
    magic = struct.unpack('>I', rd(f, 0, 4))[0]
    if magic != FAT_MAGIC:
        return None
    nfat = struct.unpack('>I', rd(f, 4, 4))[0]
    slices = []
    for i in range(nfat):
        base = 8 + i * 20
        cputype, cpusub, off, size, align = struct.unpack('>iiIII', rd(f, base, 20))
        slices.append({'cputype': cputype, 'cpusub': cpusub, 'off': off, 'size': size})
    return slices


def slice_name(cputype, cpusub):
    m = {0x0100000C: 'arm64', 0x0200000C: 'arm64e', 0x01000007: 'x86_64'}
    return m.get(cputype, hex(cputype))


class Slice:
    def __init__(self, f, base):
        self.f = f
        self.base = base
        magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = \
            struct.unpack('<8I', rd(f, base, 32))
        assert magic == MH_MAGIC_64, hex(magic)
        self.cputype, self.cpusub = cputype, cpusub
        self.sections = {}
        self.segments = []
        self.symoff = self.nsyms = self.stroff = 0
        self.indirectsymoff = 0
        p = base + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('<2I', rd(f, p, 8))
            if cmd == LC_SEGMENT_64:
                segname = rd(f, p + 8, 16).rstrip(b'\x00').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack('<4Q', rd(f, p + 24, 32))
                nsects = struct.unpack('<I', rd(f, p + 64, 4))[0]
                self.segments.append((segname, vmaddr, vmsize, fileoff, filesize))
                sp = p + 72
                for _s in range(nsects):
                    sname = rd(f, sp, 16).rstrip(b'\x00').decode()
                    segn = rd(f, sp + 16, 16).rstrip(b'\x00').decode()
                    addr, size = struct.unpack('<2Q', rd(f, sp + 32, 16))
                    offset = struct.unpack('<I', rd(f, sp + 48, 4))[0]
                    reserved1 = struct.unpack('<I', rd(f, sp + 60, 4))[0]
                    self.sections[(segn, sname)] = {
                        'addr': addr, 'size': size, 'offset': offset,
                        'reserved1': reserved1, 'seg': segn, 'sect': sname,
                    }
                    sp += 80
            elif cmd == LC_SYMTAB:
                self.symoff, self.nsyms, self.stroff, self.strsize = \
                    struct.unpack('<4I', rd(f, p + 8, 16))
            elif cmd == LC_DYSYMTAB:
                vals = struct.unpack('<18I', rd(f, p + 8, 72))
                # vals[0]=ilocalsym … [10]=extrefsymoff [11]=nextrefsyms
                # [12]=indirectsymoff [13]=nindirectsyms
                self.indirectsymoff = vals[12]
                self.nindirectsyms = vals[13]
            p += cmdsize

    def symbols(self):
        out = []
        for i in range(self.nsyms):
            p = self.base + self.symoff + i * 16
            strx, ntype, sect, desc, value = struct.unpack('<IBBHQ', rd(self.f, p, 16))
            name = b''
            if strx:
                self.f.seek(self.base + self.stroff + strx)
                buf = b''
                while True:
                    c = self.f.read(1)
                    if not c or c == b'\x00':
                        break
                    buf += c
                name = buf
            out.append({'i': i, 'name': name.decode('utf-8', 'ignore'),
                        'type': ntype, 'value': value})
        return out

    def indirect_at(self, idx):
        self.f.seek(self.base + self.indirectsymoff + idx * 4)
        return struct.unpack('<I', self.f.read(4))[0]

    def stub_for_symbol(self, symname):
        """返回该符号的 stub 地址（__TEXT,__stubs）。"""
        syms = self.symbols()
        idx = None
        for s in syms:
            if s['name'] == symname:
                idx = s['i']
                break
        if idx is None:
            return None, None
        sym = [s for s in syms if s['i'] == idx][0]
        # 若符号有定义地址（非 0），直接用
        for stubsect in ('__stubs', '__auth_stubs'):
            for (segn, sname), sec in self.sections.items():
                if sname != stubsect:
                    continue
                n = sec['size'] // 16
                for i in range(n):
                    isym = self.indirect_at(sec['reserved1'] + i)
                    if isym == idx:
                        return sec['addr'] + i * 16, sec
        return (sym['value'] or None), None


def find_calls(sl, stub_addr):
    sec = sl.sections.get(('__TEXT', '__text'))
    sl.f.seek(sl.base + sec['offset'])
    code = sl.f.read(sec['size'])
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    hits = []
    for ins in md.disasm(code, sec['addr']):
        if ins.mnemonic == 'bl':
            op = ins.op_str.strip()
            try:
                tgt = int(op, 16)
            except ValueError:
                continue
            if tgt == stub_addr:
                hits.append(ins.address)
    return hits, sec


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__)
        return 1
    path, cmd = a[0], a[1]
    with open(path, 'rb') as f:
        slices = parse_fat(f)
        if slices is None:
            sl = Slice(f, 0)
            targets = [(0, sl)]
        else:
            targets = []
            for s in slices:
                targets.append((s['off'], Slice(f, s['off'])))

        if cmd == 'info':
            for off, sl in targets:
                print(f'--- slice @0x{off:x}  {slice_name(sl.cputype, sl.cpusub)}')
                print(f'    sections: {len(sl.sections)}  syms: {sl.nsyms}')
                for k in sorted(sl.sections):
                    sec = sl.sections[k]
                    print(f'      {k[0]},{k[1]:24s} addr=0x{sec["addr"]:x} size=0x{sec["size"]:x} off=0x{sec["offset"]:x}')
            return 0

        symname = a[2] if len(a) > 2 else '_CCCrypt'
        for off, sl in targets:
            print(f'\n===== slice @0x{off:x}  {slice_name(sl.cputype, sl.cpusub)} =====')
            stub, sec = sl.stub_for_symbol(symname)
            if stub is None:
                print(f'  {symname}: 未找到')
                continue
            text = sl.sections.get(('__TEXT', '__text'))
            print(f'  {symname} stub addr = 0x{stub:x}  (file off = 0x{stub - text["addr"] + text["offset"]:x})')
            if cmd == 'sym':
                continue
            hits, tsec = find_calls(sl, stub)
            print(f'  调用点 {len(hits)} 处:')
            for h in hits:
                foff = h - tsec['addr'] + tsec['offset']
                print(f'    call @ vmaddr 0x{h:x}   fileoff 0x{sl.base + foff:x}  (slice内 0x{foff:x})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
