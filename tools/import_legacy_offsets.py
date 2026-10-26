#!/usr/bin/env python3
"""
Import legacy DarkSword rce_offsets tables into a structured JSON artifact.

This importer is for public GitHub exploit-kit offset tables that contain
build/device-specific JavaScript BigInt values but do not include a dyld cache
hash. The output is intentionally not a deployable iOS build profile.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ENTRY_RE = re.compile(r'"(?P<key>[^"]*?22F76[^"]*?)"\s*:\s*\{(?P<body>.*?)\n\s*\}', re.DOTALL)
KV_RE = re.compile(r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<value>0x[0-9a-fA-F]+n|\d+n|0x[0-9a-fA-F]+|\d+)\s*,?')


def normalize_value(value: str) -> str:
    value = value.strip()
    if value.endswith('n'):
        value = value[:-1]
    if value.startswith('0x'):
        return '0x' + value[2:].lower()
    return hex(int(value, 10))


def parse_device_key(key: str) -> dict[str, str]:
    parts = key.split('_')
    device = parts[0]
    build = parts[-1]
    board_variant = ''
    if len(parts) > 2:
        board_variant = '_'.join(parts[1:-1])
    return {"device": device, "board_variant": board_variant, "build": build}


def import_offsets(source: Path, source_url: str) -> dict[str, Any]:
    text = source.read_text(encoding='utf-8', errors='replace')
    entries = []

    for match in ENTRY_RE.finditer(text):
        key = match.group('key')
        body = match.group('body')
        fields = {}
        for kv in KV_RE.finditer(body):
            fields[kv.group('name')] = normalize_value(kv.group('value'))
        if not fields:
            continue
        meta = parse_device_key(key)
        entries.append({
            "key": key,
            **meta,
            "offsets": fields,
        })

    entries.sort(key=lambda item: item['key'])
    return {
        "schema": 1,
        "artifact_type": "legacy_rce_offsets",
        "deployable_profile": False,
        "trust_level": "public-github-offset-table-no-cache-hash",
        "source": {
            "url": source_url,
            "file": str(source),
            "format": "JavaScript rce_offsets object",
        },
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "builds": sorted({entry['build'] for entry in entries}),
        "entry_count": len(entries),
        "entries": entries,
        "notes": [
            "This artifact preserves public legacy offsets with source provenance.",
            "It is not a dyld build profile because no dyld_shared_cache SHA-256 is available.",
            "Do not feed this file to the iOS 26 profile loader. Use generate_ios_build_profile.py for deployable profiles.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import legacy DarkSword rce_offsets into JSON")
    parser.add_argument("source", type=Path, help="Path to rce_module.js containing rce_offsets")
    parser.add_argument("--source-url", required=True, help="Original repository or raw file URL")
    parser.add_argument("--out", type=Path, default=Path("data/imported_offsets/darksword_22F76_legacy_offsets.json"))
    args = parser.parse_args()

    if not args.source.is_file():
        raise SystemExit(f"source not found: {args.source}")

    artifact = import_offsets(args.source, args.source_url)
    if artifact["entry_count"] == 0:
        raise SystemExit("no 22F76 rce_offsets entries found")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({artifact['entry_count']} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())