#!/usr/bin/env python3
"""
Generate a build-specific iOS dyld profile from an extracted dyld_shared_cache.

This script does not ship offsets. It derives a JSON profile from the exact cache
for a target build, then the browser-side code can consume that profile.

Typical inputs:
  - --cache /path/to/dyld_shared_cache_arm64e
  - --build 22F76 --ios 18.5 --device iPhone16,2

Optional external tools, discovered on PATH:
  - dyld_shared_cache_util or xcrun dyld_shared_cache_util for mapping/symbol data
  - jtool2 for image and symbol lookup
  - ROPgadget or ropper for ARM64 gadget scanning
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

GADGET_PATTERNS = {
    "load_x0_from_x1": ["mov x0, x1", "ret"],
    "deref_x0_plus_10": ["ldr x0, [x0, #0x10]", "ret"],
    "blr_x8": ["blr x8"],
    "epilogue": ["ldp x29, x30, [sp], #0x10", "ret"],
    "ret_zero": ["mov x0, #0", "ret"],
    "store_x0_to_x1": ["str x0, [x1]", "ret"],
    "add_x0_x1": ["add x0, x0, x1", "ret"],
}

SYMBOLS = {
    "libsystem_kernel.dylib": [
        "mach_task_self_",
        "mach_msg",
        "mach_vm_read",
        "mach_vm_write",
    ],
    "libsystem_malloc.dylib": ["malloc", "free"],
}


def run(cmd: list[str], timeout: int = 120) -> str:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return proc.stdout


def tool(name: str) -> str | None:
    return shutil.which(name)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_cache_magic(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        head = f.read(0x4000)
    magic = head[:32].rstrip(b"\x00").decode("ascii", "replace")
    return {"magic": magic, "file_size": path.stat().st_size}


def parse_cache_regions(cache: Path) -> dict[str, str | None]:
    """Best-effort dyld region discovery from dyld_shared_cache_util -map."""
    candidates: list[list[str]] = []
    if tool("dyld_shared_cache_util"):
        candidates.append([tool("dyld_shared_cache_util") or "", "-map", str(cache)])
    if tool("xcrun"):
        candidates.append([tool("xcrun") or "", "dyld_shared_cache_util", "-map", str(cache)])

    regions: dict[str, str | None] = {
        "text_region": None,
        "data_region": None,
        "auth_region": None,
        "linkedit_region": None,
        "slide_info_v5": None,
    }

    for cmd in candidates:
        out = run(cmd, timeout=180)
        if not out.strip():
            continue

        # Common map output contains lines such as:
        # mapping  0x180000000 -> 0x1...  __TEXT
        # mapping  0x1e0000000 -> ...     __AUTH
        for line in out.splitlines():
            m = re.search(r"0x([0-9a-fA-F]{8,16}).*__(TEXT|DATA|AUTH|LINKEDIT)\b", line)
            if not m:
                continue
            addr = "0x" + m.group(1).lower()
            seg = m.group(2)
            if seg == "TEXT" and regions["text_region"] is None:
                regions["text_region"] = addr
            elif seg == "DATA" and regions["data_region"] is None:
                regions["data_region"] = addr
            elif seg == "AUTH" and regions["auth_region"] is None:
                regions["auth_region"] = addr
            elif seg == "LINKEDIT" and regions["linkedit_region"] is None:
                regions["linkedit_region"] = addr

        # slide info v5 address is tool/version dependent; keep null unless explicit.
        if any(v is not None for v in regions.values()):
            break

    return regions


def parse_symbols_with_jtool(cache: Path) -> dict[str, dict[str, str | None]]:
    result: dict[str, dict[str, str | None]] = {
        lib: {sym: None for sym in symbols} for lib, symbols in SYMBOLS.items()
    }
    jtool2 = tool("jtool2")
    if not jtool2:
        return result

    for lib, symbols in SYMBOLS.items():
        out = run([jtool2, "-S", str(cache), lib], timeout=240)
        for sym in symbols:
            # Accept common forms: 00000001... _mach_msg or 0x... mach_msg
            m = re.search(rf"(?:0x)?([0-9a-fA-F]{{8,16}})\s+_?{re.escape(sym)}\b", out)
            if m:
                result[lib][sym] = "0x" + m.group(1).lower()
    return result


def normalize_asm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def scan_gadgets(cache: Path) -> dict[str, str | None]:
    gadgets = {name: None for name in GADGET_PATTERNS}
    ropgadget = tool("ROPgadget") or tool("ropgadget")
    ropper = tool("ropper")

    outputs: list[str] = []
    if ropgadget:
        outputs.append(run([ropgadget, "--binary", str(cache), "--only", "mov|ldr|str|add|ldp|blr|ret"], timeout=600))
    if ropper:
        outputs.append(run([ropper, "--file", str(cache), "--nocolor", "--type", "rop"], timeout=600))

    for out in outputs:
        for line in out.splitlines():
            m = re.search(r"(0x[0-9a-fA-F]+)\s*:?\s*(.*)$", line)
            if not m:
                continue
            addr = m.group(1).lower()
            asm = normalize_asm(m.group(2).replace(";", " ; "))
            for name, parts in GADGET_PATTERNS.items():
                if gadgets[name] is not None:
                    continue
                if all(normalize_asm(p) in asm for p in parts):
                    gadgets[name] = addr
    return gadgets


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate iOS build-specific dyld profile JSON")
    ap.add_argument("--cache", required=True, type=Path, help="Path to dyld_shared_cache_arm64e")
    ap.add_argument("--build", required=True, help="Apple build train, e.g. 22F76 or 22G81")
    ap.add_argument("--ios", required=True, help="iOS version, e.g. 18.5 or 18.6")
    ap.add_argument("--device", default="", help="Device model, e.g. iPhone16,2")
    ap.add_argument("--out", type=Path, default=None, help="Output JSON path")
    args = ap.parse_args()

    cache = args.cache.resolve()
    if not cache.is_file():
        raise SystemExit(f"cache not found: {cache}")

    meta = find_cache_magic(cache)
    profile: dict[str, Any] = {
        "schema": 1,
        "ios": args.ios,
        "build": args.build,
        "device": args.device,
        "source": {
            "cache_path": str(cache),
            "cache_sha256": sha256_file(cache),
            **meta,
        },
        "dyld": parse_cache_regions(cache),
        "offsets": {
            "dyld_cache_slide_info": None,
            "dyld_shared_cache_base": None,
            "arraybuffer_data_offset": None,
            "float64array_vector_offset": None,
            "jsc_butterfly_offset": None,
            "jsc_structureID_offset": None,
        },
        "symbols": parse_symbols_with_jtool(cache),
        "gadgets": scan_gadgets(cache),
        "notes": [
            "Null values mean the local toolchain could not resolve that field automatically.",
            "Do not copy profiles across build trains; validate cache_sha256 and build first.",
        ],
    }

    # Fill base from TEXT region when discovered.
    if profile["dyld"].get("text_region"):
        profile["offsets"]["dyld_shared_cache_base"] = profile["dyld"]["text_region"]

    out = args.out or Path(f"profiles/ios_{args.ios.replace('.', '_')}_{args.build}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(str(out))

    unresolved = []
    for section in ("dyld", "offsets", "gadgets"):
        for k, v in profile[section].items():
            if v is None:
                unresolved.append(f"{section}.{k}")
    for lib, syms in profile["symbols"].items():
        for sym, val in syms.items():
            if val is None:
                unresolved.append(f"symbols.{lib}.{sym}")

    if unresolved:
        print("unresolved:")
        for item in unresolved:
            print(f"  - {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())