#!/usr/bin/env python3
"""Small, token-safe status helper for a local CLIProxyAPI profile.

The command deliberately reports metadata only.  It never prints token values,
account payloads, or contents of backup files.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.cliproxyapi_dedupe_codex_subscriptions import (
    DEFAULT_DIR,
    configured_backup_dir,
    is_valid_proxy,
    load_sub_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default=str(DEFAULT_DIR), help="CLIProxyAPI auth directory")
    parser.add_argument("--json", action="store_true", help="emit machine-readable metadata")
    args = parser.parse_args()

    root = Path(args.dir).expanduser()
    if not root.is_dir():
        parser.error(f"auth directory does not exist or is not a directory: {root}")
    backup = configured_backup_dir(root)
    rows = []
    for path in sorted(root.glob("codex-*-plus.json")):
        record = load_sub_file(path)
        if record is None:
            rows.append({"file": path.name, "state": "unreadable"})
            continue
        rows.append({
            "file": path.name,
            "email": record.email,
            "account_id_suffix": record.account_id[-6:] if record.account_id else None,
            "state": "valid" if is_valid_proxy(record.data) else "invalid",
            "size": record.size,
        })
    payload = {
        "auth_dir": str(root),
        "backup_dir": str(backup),
        "account_file_count": len(rows),
        "accounts": rows,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"auth_dir={root}")
        print(f"backup_dir={backup}")
        print(f"account_file_count={len(rows)}")
        for row in rows:
            suffix = row.get("account_id_suffix") or "unknown"
            print(f"- {row['file']}: {row.get('state', 'unknown')} account_id=...{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
