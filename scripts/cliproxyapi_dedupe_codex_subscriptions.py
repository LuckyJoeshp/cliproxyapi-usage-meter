#!/usr/bin/env python3
"""Normalize Codex Plus files without exposing archive files to CLIProxyAPI.

CLIProxyAPI recursively walks ``auth-dir``.  Therefore backup and quarantine
directories must live *outside* ``~/.cli-proxy-api``; placing ``*.json`` files
below that directory makes the management panel load them as credentials.

The command keeps one canonical file per e-mail, moves valid duplicates and
explicitly disabled credentials to an external backup directory, removes
invalid duplicates, and migrates legacy backup directories that were created
inside the auth directory by older versions of this helper.  Token values are
never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path.home() / ".cli-proxy-api"
DEFAULT_BACKUP_DIR = Path.home() / ".cli-proxy-api-backups"
BACKUP_ENV_NAMES = ("CLIPROXYAPI_BACKUP_DIR", "CLIPROXY_BACKUP_DIR")
LEGACY_BACKUP_PREFIXES = ("duplicate_subscription_backup_", "backup_")
DISABLED_QUARANTINE_PREFIX = "disabled_subscription_quarantine_"
SINGLE_FAILURE_RC = 10


@dataclass
class SubFile:
    path: Path
    data: dict[str, Any]
    email: str
    account_id: str
    mtime: float
    size: int


def configured_backup_dir(root: Path, value: str | None = None) -> Path:
    """Return a backup directory guaranteed to be outside ``root``.

    The default for the normal auth directory is a stable sibling.  A custom
    ``--dir`` gets a sibling with the same ``*-backups`` convention so tests
    and alternate profiles do not accidentally write archives into the data
    tree either.
    """
    root = root.expanduser()
    if value is None:
        for env_name in BACKUP_ENV_NAMES:
            value = os.environ.get(env_name)
            if value:
                break
    if value:
        backup = Path(value).expanduser()
    elif root.resolve() == DEFAULT_DIR.resolve():
        backup = DEFAULT_BACKUP_DIR
    else:
        backup = root.parent / f"{root.name}-backups"

    root_abs = root.resolve()
    backup_abs = backup.resolve()
    if backup_abs == root_abs or root_abs in backup_abs.parents:
        raise ValueError(f"backup directory must be outside auth directory: {backup_abs}")
    return backup_abs


def _unique_destination(parent: Path, name: str) -> Path:
    destination = parent / name
    if not destination.exists():
        return destination
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    candidate = parent / f"{name}.{stamp}.{os.getpid()}"
    serial = 1
    while candidate.exists():
        candidate = parent / f"{name}.{stamp}.{os.getpid()}.{serial}"
        serial += 1
    return candidate


def migrate_legacy_backups(root: Path, backup_root: Path, dry_run: bool) -> int:
    """Move old in-tree archive directories to the external backup root.

    Only immediate, non-symlink directories with an archive prefix are moved.
    This deliberately avoids touching active account files and unrelated
    runtime directories such as ``logs``.
    """
    moved = 0
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        print(f"WARN: cannot inspect legacy backups in {root}: {exc}", file=sys.stderr)
        return 0

    candidates = [
        entry
        for entry in entries
        if entry.is_dir() and not entry.is_symlink() and entry.name.startswith(LEGACY_BACKUP_PREFIXES)
    ]
    if not candidates:
        return 0

    destination_root = backup_root
    if not dry_run:
        destination_root.mkdir(parents=True, exist_ok=True)
        try:
            destination_root.chmod(0o700)
        except OSError:
            pass

    for entry in candidates:
        destination = _unique_destination(destination_root, entry.name)
        if dry_run:
            print(f"DRY-RUN: would move legacy backup {entry.name} -> {destination}")
        else:
            shutil.move(str(entry), str(destination))
            print(f"moved legacy backup {entry.name} -> {destination}")
        moved += 1
    return moved


def quarantine_disabled_subscriptions(
    subscriptions: list[SubFile],
    backup_root: Path,
    dry_run: bool,
) -> tuple[list[SubFile], int]:
    """Remove explicitly disabled credentials from CLIProxyAPI's auth tree.

    The files are moved, rather than deleted, so the operation remains
    recoverable.  ``backup_root`` is already guaranteed to be outside the auth
    directory, which prevents CLIProxyAPI's recursive scanner from loading the
    quarantined credentials.
    """
    disabled = [sf for sf in subscriptions if bool(sf.data.get("disabled"))]
    if not disabled:
        return subscriptions, 0

    quarantine_dir: Path | None = None
    if not dry_run:
        quarantine_dir = _unique_destination(
            backup_root,
            f"{DISABLED_QUARANTINE_PREFIX}{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantine_dir.chmod(0o700)

    for sf in disabled:
        if dry_run:
            print(f"DRY-RUN: would quarantine disabled subscription {sf.path.name} -> {backup_root}")
            continue
        assert quarantine_dir is not None
        destination = _unique_destination(quarantine_dir, sf.path.name)
        shutil.move(str(sf.path), str(destination))
        try:
            destination.chmod(0o600)
        except OSError:
            pass
        print(f"quarantined disabled subscription {sf.path.name} -> {quarantine_dir.name}/")

    disabled_paths = {sf.path for sf in disabled}
    active = [sf for sf in subscriptions if sf.path not in disabled_paths]
    return active, len(disabled)


def load_sub_file(path: Path) -> SubFile | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        stat = path.stat()
    except Exception as exc:
        print(f"WARN: skip unreadable json: {path.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None
    email = str(data.get("email") or "").strip().lower()
    if not email:
        # Filename fallback, intentionally conservative.
        match = re.match(r"^codex-(?:[0-9a-f]{8}-)?(.+)-plus\.json$", path.name)
        email = match.group(1).lower() if match else ""
    if not email:
        print(f"WARN: skip file without email: {path.name}", file=sys.stderr)
        return None
    account_id = str(data.get("account_id") or "").strip()
    return SubFile(path=path, data=data, email=email, account_id=account_id,
                   mtime=stat.st_mtime, size=stat.st_size)


def canonical_name(email: str) -> str:
    return f"codex-{email}-plus.json"


def parse_expired(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed if parsed.tzinfo is not None else parsed.astimezone()
        except Exception:
            continue
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo is not None else parsed.astimezone()
    except Exception:
        return None


def is_valid_proxy(data: dict[str, Any]) -> bool:
    if any(not data.get(key) for key in ("id_token", "access_token", "refresh_token")):
        return False
    if bool(data.get("disabled")):
        return False
    expired = str(data.get("expired") or "").strip()
    if expired:
        parsed = parse_expired(expired)
        if parsed is not None:
            try:
                if parsed <= datetime.now().astimezone(parsed.tzinfo):
                    return False
            except (TypeError, ValueError):
                return False
    return True


def _proxy_failure_reason(data: dict[str, Any]) -> str | None:
    """Return a token-safe reason when a file cannot be reconciled."""
    missing = [key for key in ("id_token", "access_token", "refresh_token") if not data.get(key)]
    if missing:
        return "missing " + ",".join(missing)
    if bool(data.get("disabled")):
        return "disabled"
    expired = str(data.get("expired") or "").strip()
    if expired:
        parsed = parse_expired(expired)
        if parsed is None:
            return "unreadable expiry"
        try:
            if parsed <= datetime.now().astimezone(parsed.tzinfo):
                return "expired"
        except (TypeError, ValueError):
            return "unreadable expiry"
    if not str(data.get("account_id") or "").strip():
        return "missing account_id"
    return None


def unpaired_failed_subscriptions(root: Path) -> list[tuple[Path, str]]:
    """Find lone unusable files that must block automatic reconciliation.

    A malformed file is grouped by its filename because its e-mail cannot be
    trusted.  In that case we fail closed and preserve it rather than guessing
    that it is a duplicate of another account.  Normal cleanup quarantines
    explicit ``disabled`` files before this check runs.
    """
    grouped: dict[str, list[tuple[Path, str | None]]] = {}
    for path in sorted(root.glob("codex-*-plus.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            grouped.setdefault(f"path:{path.name}", []).append(
                (path, f"unreadable JSON ({type(exc).__name__})")
            )
            continue
        email = str(data.get("email") or "").strip().lower()
        key = f"email:{email}" if email else f"path:{path.name}"
        grouped.setdefault(key, []).append((path, _proxy_failure_reason(data)))
    return [items[0] for items in grouped.values() if len(items) == 1 and items[0][1]]


def file_state(sf: SubFile) -> str:
    return "valid" if is_valid_proxy(sf.data) else "invalid"


def score(sf: SubFile) -> tuple[int, int, float, int]:
    """Prefer usable, token-bearing, newest and largest records."""
    disabled = bool(sf.data.get("disabled"))
    expired = bool(sf.data.get("expired"))
    has_tokens = all(bool(sf.data.get(key)) for key in ("access_token", "refresh_token", "id_token"))
    return (0 if disabled or expired else 1, 1 if has_tokens else 0, sf.mtime, sf.size)


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def run_brew_restart(dry_run: bool) -> None:
    cmd = ["brew", "services", "restart", "cliproxyapi"]
    if dry_run:
        print("DRY-RUN: would run: " + " ".join(cmd))
        return
    print("Restarting cliproxyapi: " + " ".join(cmd))
    subprocess.run(cmd, check=False)


def dedupe(
    root: Path,
    dry_run: bool,
    restart: bool,
    update_only: bool,
    backup_root: Path,
    migrate_legacy: bool,
) -> int:
    files = sorted(root.glob("codex-*-plus.json"))
    subscriptions = [sf for path in files if (sf := load_sub_file(path))]
    migrated = migrate_legacy_backups(root, backup_root, dry_run) if migrate_legacy else 0
    subscriptions, quarantined = quarantine_disabled_subscriptions(subscriptions, backup_root, dry_run)
    groups: dict[str, list[SubFile]] = {}
    for sf in subscriptions:
        groups.setdefault(sf.email, []).append(sf)

    changed = migrated > 0 or quarantined > 0
    run_backup_dir: Path | None = None

    for email, items in sorted(groups.items()):
        if len(items) <= 1:
            if items and not is_valid_proxy(items[0].data):
                # A lone failed/expired record is an operator's re-login
                # handle. Keep it visible and untouched so the account can be
                # repaired manually; explicit disabled records were already
                # quarantined above.
                print(f"  retained single failed subscription: {items[0].path.name} (no cleanup)")
            continue
        valid_items = [sf for sf in items if is_valid_proxy(sf.data)]
        candidates = valid_items if valid_items else items
        winner = max(candidates, key=score)
        canonical = root / canonical_name(email)
        valid_set = {sf.path for sf in valid_items}
        # The canonical path is retained after it has been synchronized above.
        # If the newest source is a hashed filename, that source itself becomes
        # an archive candidate; archiving the canonical path here would remove
        # the freshly written source of truth.
        duplicate_items = [sf for sf in items if sf.path != canonical]

        print(f"\n{email}")
        print(
            f"  source: {winner.path.name}  "
            f"mtime={datetime.fromtimestamp(winner.mtime):%Y-%m-%d %H:%M:%S}  "
            f"account_id=...{winner.account_id[-6:] if winner.account_id else 'unknown'}"
        )
        print(f"  canonical: {canonical.name}")
        for sf in sorted(items, key=lambda item: (item.path.name != winner.path.name, item.mtime)):
            print(f"   - {sf.path.name} [{file_state(sf)}] mtime={datetime.fromtimestamp(sf.mtime):%Y-%m-%d %H:%M:%S}")

        canonical_needs_write = True
        if canonical.exists():
            try:
                canonical_needs_write = json.loads(canonical.read_text(encoding="utf-8")) != winner.data
            except Exception:
                canonical_needs_write = True
        if canonical_needs_write:
            changed = True
            if dry_run:
                print("  DRY-RUN: would sync source content into canonical file")
            else:
                atomic_write_json(canonical, winner.data)
                print("  synced canonical file")
        else:
            print("  canonical already matches source")

        if not duplicate_items:
            continue
        changed = True
        if dry_run:
            print("  DRY-RUN: duplicate resolution plan:")
            for sf in duplicate_items:
                action = "archive valid" if sf.path in valid_set else "delete invalid"
                print(f"    - {sf.path.name}: {action} -> {backup_root}")
            continue

        if run_backup_dir is None:
            run_backup_dir = _unique_destination(backup_root, f"duplicate_subscription_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            run_backup_dir.mkdir(parents=True, exist_ok=True)
            run_backup_dir.chmod(0o700)
        for sf in duplicate_items:
            path = sf.path
            if path not in valid_set:
                path.unlink(missing_ok=True)
                print(f"  deleted invalid duplicate: {path.name}")
            elif update_only:
                print(f"  kept valid duplicate in place (update-only): {path.name}")
            else:
                destination = _unique_destination(run_backup_dir, path.name)
                shutil.move(str(path), str(destination))
                print(f"  archived valid duplicate {path.name} -> {destination.parent.name}/")

    if migrated:
        verb = "Planned migration of" if dry_run else "Migrated"
        print(f"\n{verb} {migrated} legacy backup director{'y' if migrated == 1 else 'ies'} outside auth-dir: {backup_root}")
    if quarantined:
        verb = "Planned quarantine of" if dry_run else "Quarantined"
        print(
            f"\n{verb} {quarantined} disabled subscription file"
            f"{'s' if quarantined != 1 else ''} outside auth-dir: {backup_root}"
        )
    if not changed:
        print("No duplicate or disabled Codex subscription files found.")
    elif restart:
        run_brew_restart(dry_run)
    else:
        print("\nNote: cliproxyapi was not restarted. Use --restart if you want it to reload immediately.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default=str(DEFAULT_DIR), help="CLIProxyAPI auth directory")
    ap.add_argument("--backup-dir", default=None, help="external archive directory (must be outside --dir)")
    ap.add_argument("--dry-run", action="store_true", help="show planned changes only")
    ap.add_argument("--restart", action="store_true", help="restart brew service cliproxyapi after changes")
    ap.add_argument("--update-only", action="store_true", help="sync canonical file but keep duplicate files in place")
    ap.add_argument("--no-migrate-legacy-backups", action="store_true", help="leave old in-tree backup directories untouched")
    ap.add_argument(
        "--check-single-failures",
        action="store_true",
        help="report lone failed files and return 10; do not modify anything",
    )
    args = ap.parse_args()
    root = Path(args.dir).expanduser()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: auth directory does not exist or is not a directory: {root}", file=sys.stderr)
        return 2
    if args.check_single_failures:
        failures = unpaired_failed_subscriptions(root)
        if not failures:
            print("No lone failed subscription files found.")
            return 0
        print("Lone unusable subscription file(s) require manual attention:")
        for path, reason in failures:
            print(f"  - {path.name}: {reason}")
        return SINGLE_FAILURE_RC
    try:
        backup_root = configured_backup_dir(root, args.backup_dir)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return dedupe(
        root,
        args.dry_run,
        args.restart,
        args.update_only,
        backup_root,
        not args.no_migrate_legacy_backups,
    )


if __name__ == "__main__":
    raise SystemExit(main())
