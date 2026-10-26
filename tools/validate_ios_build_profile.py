#!/usr/bin/env python3
"""
Validate DarkSword-RCE iOS build profile JSON files.

The validator is intentionally strict for deployable profiles and permissive only
when --allow-template is set. It prevents placeholder offsets/gadgets from being
silently consumed by the browser-side loader.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOP_LEVEL = ["schema", "ios", "build", "source", "dyld", "offsets", "symbols", "gadgets"]

REQUIRED_DYLD = [
    "text_region",
    "data_region",
    "auth_region",
    "linkedit_region",
]

REQUIRED_OFFSETS = [
    "dyld_cache_slide_info",
    "dyld_shared_cache_base",
    "arraybuffer_data_offset",
    "float64array_vector_offset",
    "jsc_butterfly_offset",
    "jsc_structureID_offset",
]

REQUIRED_GADGETS = [
    "load_x0_from_x1",
    "deref_x0_plus_10",
    "blr_x8",
    "epilogue",
    "ret_zero",
    "store_x0_to_x1",
    "add_x0_x1",
]

REQUIRED_SYMBOLS = {
    "libsystem_kernel.dylib": [
        "mach_task_self_",
        "mach_msg",
        "mach_vm_read",
        "mach_vm_write",
    ],
    "libsystem_malloc.dylib": ["malloc", "free"],
}

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
PLACEHOLDER_RE = re.compile(r"(<.*>|replace-|template|dummy|todo|null)", re.IGNORECASE)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def value_missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return not stripped or bool(PLACEHOLDER_RE.search(stripped))
    return False


def validate_hex(value: Any) -> bool:
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        return bool(HEX_RE.match(value.strip()))
    return False


def check_required_object(data: dict[str, Any], path: str, keys: list[str], errors: list[str], allow_template: bool) -> None:
    obj = data
    for part in path.split(".") if path else []:
        obj = obj.get(part, {}) if isinstance(obj, dict) else {}
    if not isinstance(obj, dict):
        errors.append(f"{path or '<root>'} must be an object")
        return
    for key in keys:
        value = obj.get(key)
        field = f"{path + '.' if path else ''}{key}"
        if value_missing(value):
            if not allow_template:
                errors.append(f"{field} is missing or placeholder")
            continue
        if path in {"dyld", "offsets", "gadgets"} and not validate_hex(value):
            errors.append(f"{field} must be a hex address string like 0x180000000")


def validate_profile(path: Path, allow_template: bool = False) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"invalid JSON: {exc}"], warnings

    if not isinstance(data, dict):
        return ["profile root must be an object"], warnings

    for key in REQUIRED_TOP_LEVEL:
        if key not in data:
            errors.append(f"missing top-level key: {key}")

    if data.get("schema") != 1:
        errors.append("schema must be 1")

    for field in ["ios", "build"]:
        value = data.get(field)
        if value_missing(value) and not allow_template:
            errors.append(f"{field} is missing or placeholder")

    check_required_object(data, "dyld", REQUIRED_DYLD, errors, allow_template)
    check_required_object(data, "offsets", REQUIRED_OFFSETS, errors, allow_template)
    check_required_object(data, "gadgets", REQUIRED_GADGETS, errors, allow_template)

    symbols = data.get("symbols", {})
    if not isinstance(symbols, dict):
        errors.append("symbols must be an object")
    else:
        for lib, names in REQUIRED_SYMBOLS.items():
            lib_obj = symbols.get(lib)
            if not isinstance(lib_obj, dict):
                if not allow_template:
                    errors.append(f"symbols.{lib} is missing")
                continue
            for name in names:
                value = lib_obj.get(name)
                field = f"symbols.{lib}.{name}"
                if value_missing(value):
                    if not allow_template:
                        errors.append(f"{field} is missing or placeholder")
                    continue
                if not validate_hex(value):
                    errors.append(f"{field} must be a hex address string like 0x180000000")

    source = data.get("source", {})
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        cache_sha = source.get("cache_sha256")
        if value_missing(cache_sha):
            if not allow_template:
                errors.append("source.cache_sha256 is missing or placeholder")
        elif not re.fullmatch(r"[0-9a-fA-F]{64}", str(cache_sha)):
            errors.append("source.cache_sha256 must be a 64-character SHA-256 hex digest")

        cache_path = source.get("cache_path")
        if cache_path and not value_missing(cache_path):
            cache_file = Path(str(cache_path))
            if cache_file.is_file() and cache_sha and re.fullmatch(r"[0-9a-fA-F]{64}", str(cache_sha)):
                actual = sha256_file(cache_file)
                if actual.lower() != str(cache_sha).lower():
                    errors.append(f"source.cache_sha256 mismatch: expected {cache_sha}, got {actual}")
            elif not allow_template:
                warnings.append(f"source.cache_path not available locally: {cache_path}")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate iOS build profile JSON")
    parser.add_argument("profiles", nargs="+", type=Path, help="Profile JSON file(s)")
    parser.add_argument("--allow-template", action="store_true", help="Allow null/template placeholders")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON result")
    args = parser.parse_args()

    results = []
    exit_code = 0
    for profile in args.profiles:
        if not profile.is_file():
            errors = [f"profile not found: {profile}"]
            warnings: list[str] = []
        else:
            errors, warnings = validate_profile(profile, args.allow_template)
        if errors:
            exit_code = 1
        results.append({"path": str(profile), "ok": not errors, "errors": errors, "warnings": warnings})

    if args.json:
        print(json.dumps({"ok": exit_code == 0, "profiles": results}, indent=2))
    else:
        for result in results:
            status = "OK" if result["ok"] else "FAIL"
            print(f"[{status}] {result['path']}")
            for warning in result["warnings"]:
                print(f"  warning: {warning}")
            for error in result["errors"]:
                print(f"  error: {error}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())