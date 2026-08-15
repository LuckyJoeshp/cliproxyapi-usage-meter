#!/usr/bin/env python3
"""Incrementally import CLIProxyAPI Codex accounts into Cockpit Tools.

The default mode is a read-only dry run.  ``--apply`` sends only accounts that
are absent from Cockpit or whose credentials differ through Cockpit's supported
``cockpit-tools://import`` flow.  Credentials are held in memory and served
only once over loopback; this script never edits Cockpit's account database or
the CLIProxyAPI auth files directly.

The migration history contains counts, timestamps, and keyed (non-reversible)
fingerprints only.  It deliberately never stores an email, account ID, token,
source filename, or local absolute path.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import plistlib
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlencode


COCKPIT_CACHE_KEY = "agtools.codex.accounts.cache"
COCKPIT_INDEX_NAME = "codex_accounts.json"
COCKPIT_LOG_DB_NAME = "codex_local_access_logs.sqlite"
DEFAULT_SOURCE_DIR = Path.home() / ".cli-proxy-api"
DEFAULT_COCKPIT_DIR = Path.home() / ".antigravity_cockpit"
DEFAULT_MAX_AUTH_BYTES = 8 * 1024 * 1024
DEFAULT_WAIT_SECONDS = 45.0
HISTORY_SCHEMA_VERSION = 1


class MigrationError(RuntimeError):
    """A safe, user-actionable migration failure."""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalized(value: Any) -> str:
    return _text(value).casefold()


def _token_tuple(record: Mapping[str, Any]) -> tuple[str, str, str]:
    nested = record.get("tokens")
    token_record = nested if isinstance(nested, Mapping) else record
    return tuple(
        _text(token_record.get(name))
        for name in ("id_token", "access_token", "refresh_token")
    )


def _decode_jwt_payload(token: str) -> Mapping[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _identity_keys(record: Mapping[str, Any]) -> frozenset[str]:
    """Build matching keys without exposing their values to output."""

    keys: set[str] = set()
    for field in ("email", "account_id", "chatgpt_account_id", "user_id"):
        value = _normalized(record.get(field))
        if value:
            keys.add(f"{field}:{value}")

    # Some CLIProxyAPI records only carry the account identity inside a JWT.
    for token in _token_tuple(record)[:2]:
        claims = _decode_jwt_payload(token)
        auth_claims = claims.get("https://api.openai.com/auth")
        if isinstance(auth_claims, Mapping):
            for field in ("chatgpt_account_id", "chatgpt_user_id", "email"):
                value = _normalized(auth_claims.get(field))
                if value:
                    keys.add(f"jwt_{field}:{value}")
        for field in ("email", "sub"):
            value = _normalized(claims.get(field))
            if value:
                keys.add(f"jwt_{field}:{value}")
    return frozenset(keys)


def _strong_identity_keys(record: Mapping[str, Any]) -> frozenset[str]:
    """Return keys that identify a member, not merely a shared workspace.

    ``account_id``/``chatgpt_account_id`` can legitimately be shared by
    several team members.  Email and user-level identifiers therefore win for
    deduplication; workspace keys are only a fallback when they are unique.
    """

    keys: set[str] = set()
    for field in ("email", "user_id"):
        value = _normalized(record.get(field))
        if value:
            keys.add(f"{field}:{value}")
    for token in _token_tuple(record)[:2]:
        claims = _decode_jwt_payload(token)
        auth_claims = claims.get("https://api.openai.com/auth")
        if isinstance(auth_claims, Mapping):
            value = _normalized(auth_claims.get("chatgpt_user_id"))
            if value:
                keys.add(f"jwt_chatgpt_user_id:{value}")
        value = _normalized(claims.get("sub"))
        if value:
            keys.add(f"jwt_sub:{value}")
    return frozenset(keys)


def _matching_account_indices(
    source: SourceAccount | Mapping[str, Any],
    accounts: Sequence[Mapping[str, Any]],
) -> set[int]:
    source_keys = (
        source.identity_keys
        if isinstance(source, SourceAccount)
        else _identity_keys(source)
    )
    strong_source_keys = (
        _strong_identity_keys(source.payload)
        if isinstance(source, SourceAccount)
        else _strong_identity_keys(source)
    )
    strong_index: dict[str, set[int]] = collections.defaultdict(set)
    fallback_index: dict[str, set[int]] = collections.defaultdict(set)
    for position, account in enumerate(accounts):
        for key in _strong_identity_keys(account):
            strong_index[key].add(position)
        for key in _identity_keys(account):
            fallback_index[key].add(position)

    strong_matches: set[int] = set()
    for key in strong_source_keys:
        strong_matches.update(strong_index.get(key, set()))
    if strong_matches:
        return strong_matches
    if strong_source_keys:
        # A member-level identifier that is absent from Cockpit must not fall
        # through to a shared workspace ID and accidentally overwrite another
        # member.  Treat it as a new account and let Cockpit's own upsert logic
        # resolve the authoritative token claims.
        return set()

    fallback_matches: set[int] = set()
    for key in source_keys:
        fallback_matches.update(fallback_index.get(key, set()))
    return fallback_matches


def _has_importable_credentials(record: Mapping[str, Any]) -> bool:
    id_token, access_token, refresh_token = _token_tuple(record)
    return bool(refresh_token or (id_token and access_token))


@dataclass(frozen=True)
class SourceAccount:
    path: Path
    payload: dict[str, Any]
    identity_keys: frozenset[str]
    tokens: tuple[str, str, str]


@dataclass
class SourceScan:
    accounts: list[SourceAccount]
    file_count: int = 0
    invalid_count: int = 0
    unsupported_count: int = 0
    duplicate_count: int = 0
    conflict_count: int = 0


def read_source_accounts(
    source_dir: Path,
    *,
    max_bytes: int = DEFAULT_MAX_AUTH_BYTES,
) -> SourceScan:
    if not source_dir.is_dir():
        raise MigrationError("CLIProxyAPI auth directory is unavailable")

    scan = SourceScan(accounts=[])
    by_identity: dict[str, SourceAccount] = {}
    for auth_path in sorted(source_dir.glob("*.json")):
        scan.file_count += 1
        try:
            if auth_path.stat().st_size > max_bytes:
                scan.invalid_count += 1
                continue
            payload = json.loads(auth_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            scan.invalid_count += 1
            continue
        if not isinstance(payload, dict):
            scan.invalid_count += 1
            continue
        if _normalized(payload.get("type")) != "codex":
            scan.unsupported_count += 1
            continue
        identity_keys = _identity_keys(payload)
        if not identity_keys or not _has_importable_credentials(payload):
            scan.invalid_count += 1
            continue
        account = SourceAccount(
            path=auth_path,
            payload=payload,
            identity_keys=identity_keys,
            tokens=_token_tuple(payload),
        )
        dedupe_keys = _strong_identity_keys(payload) or identity_keys
        prior = next((by_identity.get(key) for key in dedupe_keys if key in by_identity), None)
        if prior is not None:
            if prior.tokens == account.tokens:
                scan.duplicate_count += 1
            else:
                scan.conflict_count += 1
            continue
        for key in dedupe_keys:
            by_identity[key] = account
        scan.accounts.append(account)
    return scan


def _decode_cache_value(raw: Any) -> Any:
    if isinstance(raw, bytes):
        text = raw.decode("utf-16le")
    elif isinstance(raw, str):
        text = raw
    else:
        return None
    return json.loads(text.lstrip("\ufeff"))


def _cache_candidates(home: Path, explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    root = home / "Library" / "WebKit" / "com.jlcodes.cockpit-tools" / "WebsiteData"
    try:
        candidates = list(root.rglob("LocalStorage/localstorage.sqlite3"))
    except OSError:
        return []
    return sorted(
        candidates,
        key=lambda item: item.stat().st_mtime_ns if item.exists() else 0,
        reverse=True,
    )


def _open_sqlite_readonly(
    database_path: Path,
    *,
    timeout: float = 2.0,
) -> sqlite3.Connection:
    """Open Cockpit's SQLite files without taking a writer lock.

    Cockpit uses WAL mode and may remove its ``-shm`` sidecar between short
    lived commands.  The normal read-only VFS is attempted first so active
    WAL frames are visible.  An immutable view is used only when neither a
    WAL nor rollback journal has pending bytes; otherwise the operation fails
    closed instead of returning a stale snapshot.
    """

    target = database_path.expanduser().absolute()
    timeout_seconds = max(0.1, float(timeout))
    busy_timeout_ms = max(100, int(timeout_seconds * 1000))

    def connect(query: str) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{target.as_uri()}?{query}",
                uri=True,
                timeout=timeout_seconds,
            )
            connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            return connection
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            raise

    errors: list[sqlite3.OperationalError] = []
    for query in ("mode=ro", "mode=ro&cache=shared"):
        try:
            return connect(query)
        except sqlite3.OperationalError as exc:
            errors.append(exc)

    try:
        journal_pending = any(
            candidate.is_file() and candidate.stat().st_size > 0
            for candidate in (
                Path(f"{target}-wal"),
                Path(f"{target}-journal"),
            )
        )
    except OSError:
        journal_pending = True
    if not journal_pending:
        try:
            return connect("mode=ro&immutable=1")
        except sqlite3.OperationalError as exc:
            errors.append(exc)
    if errors:
        raise errors[-1]
    raise sqlite3.OperationalError("unable to open database file")


def read_cockpit_cache(
    home: Path,
    explicit_db: Path | None,
) -> tuple[list[dict[str, Any]], Path | None, bool]:
    for database_path in _cache_candidates(home, explicit_db):
        try:
            if not database_path.is_file():
                continue
            connection = _open_sqlite_readonly(database_path, timeout=1)
            try:
                row = connection.execute(
                    "SELECT value FROM ItemTable WHERE key=? LIMIT 1",
                    (COCKPIT_CACHE_KEY,),
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                continue
            payload = _decode_cache_value(row[0])
            if isinstance(payload, Mapping):
                payload = payload.get("accounts", payload.get("data", payload.get("items")))
            if not isinstance(payload, list):
                continue
            records = [item for item in payload if isinstance(item, dict)]
            return records, database_path, True
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            continue
    return [], None, False


def read_cockpit_index(cockpit_dir: Path) -> tuple[list[dict[str, Any]], bool]:
    index_path = cockpit_dir / COCKPIT_INDEX_NAME
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [], False
    accounts = payload.get("accounts") if isinstance(payload, Mapping) else None
    if not isinstance(accounts, list):
        return [], False
    return [item for item in accounts if isinstance(item, dict)], True


@dataclass
class CockpitSnapshot:
    accounts: list[dict[str, Any]]
    cache_accounts: list[dict[str, Any]]
    cache_available: bool
    index_available: bool
    cache_path: Path | None


def read_cockpit_snapshot(
    cockpit_dir: Path,
    home: Path,
    explicit_db: Path | None,
) -> CockpitSnapshot:
    cache_accounts, cache_path, cache_available = read_cockpit_cache(home, explicit_db)
    index_accounts, index_available = read_cockpit_index(cockpit_dir)
    accounts = cache_accounts if cache_available else index_accounts
    return CockpitSnapshot(
        accounts=accounts,
        cache_accounts=cache_accounts,
        cache_available=cache_available,
        index_available=index_available,
        cache_path=cache_path,
    )


@dataclass
class MigrationPlan:
    source: SourceScan
    cockpit: CockpitSnapshot
    candidates: list[SourceAccount]
    reasons: collections.Counter[str]
    ambiguous_count: int = 0
    unverified_count: int = 0

    def summary(self) -> dict[str, int | bool]:
        return {
            "source_accounts": len(self.source.accounts),
            "source_files": self.source.file_count,
            "source_invalid": self.source.invalid_count,
            "source_unsupported": self.source.unsupported_count,
            "source_duplicates": self.source.duplicate_count,
            "source_conflicts": self.source.conflict_count,
            "cockpit_accounts": len(self.cockpit.accounts),
            "cockpit_cache_available": self.cockpit.cache_available,
            "candidate_accounts": len(self.candidates),
            "identical_accounts": self.reasons["identical"],
            "new_accounts": self.reasons["new"],
            "updated_accounts": self.reasons["updated"],
            "ambiguous_accounts": self.ambiguous_count,
            "unverified_existing_accounts": self.unverified_count,
        }


def build_plan(
    source: SourceScan,
    cockpit: CockpitSnapshot,
) -> MigrationPlan:
    reasons: collections.Counter[str] = collections.Counter()
    candidates: list[SourceAccount] = []
    ambiguous_count = 0
    unverified_count = 0

    for account in source.accounts:
        matches = _matching_account_indices(account, cockpit.accounts)
        if len(matches) > 1:
            reasons["ambiguous"] += 1
            ambiguous_count += 1
            continue
        if not matches:
            reasons["new"] += 1
            candidates.append(account)
            continue

        existing = cockpit.accounts[next(iter(matches))]
        if not cockpit.cache_available:
            reasons["unverified_existing"] += 1
            unverified_count += 1
            continue
        if account.tokens == _token_tuple(existing):
            reasons["identical"] += 1
        else:
            reasons["updated"] += 1
            candidates.append(account)

    return MigrationPlan(
        source=source,
        cockpit=cockpit,
        candidates=candidates,
        reasons=reasons,
        ambiguous_count=ambiguous_count,
        unverified_count=unverified_count,
    )


def _load_fingerprint_key(cockpit_dir: Path, *, create: bool) -> bytes:
    for key_path in (
        cockpit_dir / "secure-account-storage.key",
        cockpit_dir / "cliproxyapi_migration.key",
    ):
        try:
            key = key_path.read_bytes()
        except OSError:
            key = b""
        if len(key) >= 16:
            return key
    if not create:
        return secrets.token_bytes(32)
    key_path = cockpit_dir / "cliproxyapi_migration.key"
    cockpit_dir.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(key_path, flags, 0o600)
    except FileExistsError:
        return key_path.read_bytes()
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
    return key


def account_fingerprint(account: SourceAccount, key: bytes) -> str:
    message = json.dumps(
        {
            "identity": sorted(account.identity_keys),
            "tokens": account.tokens,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _cockpit_app_version() -> str | None:
    info_path = Path("/Applications/Cockpit Tools.app/Contents/Info.plist")
    try:
        with info_path.open("rb") as handle:
            payload = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    value = payload.get("CFBundleShortVersionString") if isinstance(payload, Mapping) else None
    return _text(value) or None


def _write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
    os.chmod(path, 0o600)


def append_history(
    history_path: Path,
    *,
    status: str,
    plan: MigrationPlan,
    fingerprints: Sequence[str],
    backup_created: bool = False,
    requested: int = 0,
    verified: int = 0,
    import_request_received: bool = False,
) -> None:
    try:
        previous = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        previous = {}
    runs = previous.get("runs") if isinstance(previous, Mapping) else None
    if not isinstance(runs, list):
        runs = []
    safe_run = {
        "at": _utc_now(),
        "status": status,
        "cockpit_version": _cockpit_app_version(),
        "requested": requested,
        "verified": verified,
        "import_request_received": bool(import_request_received),
        "backup_created": bool(backup_created),
        "fingerprints": list(fingerprints),
        **plan.summary(),
    }
    runs.append(safe_run)
    _write_private_json(
        history_path,
        {"schema_version": HISTORY_SCHEMA_VERSION, "runs": runs[-50:]},
    )


def _copy_if_present(source: Path, target: Path) -> bool:
    if source.is_symlink() or not source.is_file():
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    os.chmod(target, 0o600)
    return True


def _backup_sqlite(source: Path, target: Path) -> bool:
    if not source.is_file():
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    source_connection = _open_sqlite_readonly(source, timeout=2)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()
    os.chmod(target, 0o600)
    return True


def create_backup(cockpit_dir: Path, cache_path: Path | None) -> bool:
    backup_root = cockpit_dir / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_root, 0o700)
    backup_dir = backup_root / (
        "cliproxyapi_migration_"
        + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "_"
        + secrets.token_hex(4)
    )
    backup_dir.mkdir(mode=0o700)
    os.chmod(backup_dir, 0o700)
    copied = 0
    for filename in (
        COCKPIT_INDEX_NAME,
        f"{COCKPIT_INDEX_NAME}.bak",
        "secure-account-storage.key",
    ):
        copied += int(_copy_if_present(cockpit_dir / filename, backup_dir / filename))
    account_dir = cockpit_dir / "codex_accounts"
    if account_dir.is_dir() and not account_dir.is_symlink():
        shutil.copytree(account_dir, backup_dir / "codex_accounts", symlinks=True)
        for child in (backup_dir / "codex_accounts").rglob("*"):
            if child.is_symlink():
                continue
            if child.is_dir():
                os.chmod(child, 0o700)
            elif child.is_file():
                os.chmod(child, 0o600)
                copied += 1
    if cache_path is not None:
        copied += int(_backup_sqlite(cache_path, backup_dir / "localstorage.sqlite3"))
    _write_private_json(
        backup_dir / "manifest.json",
        {
            "schema_version": 1,
            "created_at": _utc_now(),
            "copied_files": copied,
            "contains_credentials": True,
        },
    )
    return copied > 0


class _BundleHandler(http.server.BaseHTTPRequestHandler):
    server: "_BundleServer"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != self.server.endpoint:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(self.server.payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(self.server.payload)
        self.server.served.set()

    def log_message(self, _format: str, *_args: Any) -> None:
        # Never put a source URL, filename, or payload in a migration log.
        return


class _BundleServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, payload: bytes, endpoint: str):
        super().__init__(("127.0.0.1", 0), _BundleHandler)
        self.payload = payload
        self.endpoint = endpoint
        self.served = threading.Event()


def send_bundle_to_cockpit(accounts: Sequence[SourceAccount], timeout: float) -> bool:
    payload = json.dumps(
        [account.payload for account in accounts],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    endpoint = "/bundle/" + secrets.token_urlsafe(24)
    server = _BundleServer(payload, endpoint)
    server.timeout = 0.5
    deep_link = "cockpit-tools://import?" + urlencode(
        {
            "provider": "codex",
            "import_url": f"http://127.0.0.1:{server.server_port}{endpoint}",
            "auto_import": "true",
            "source": "cliproxyapi-migration",
        }
    )
    open_command = "/usr/bin/open" if Path("/usr/bin/open").is_file() else shutil.which("open")
    if not open_command:
        server.server_close()
        raise MigrationError("Cockpit deep-link import requires macOS open")
    try:
        try:
            subprocess.run(
                [open_command, deep_link],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise MigrationError("无法唤起 Cockpit 官方导入入口") from exc
        deadline = time.monotonic() + max(timeout, 1.0)
        while not server.served.is_set() and time.monotonic() < deadline:
            server.handle_request()
        return server.served.is_set()
    finally:
        server.server_close()


def _identity_match(source: SourceAccount, accounts: Sequence[Mapping[str, Any]]) -> bool:
    return bool(_matching_account_indices(source, accounts))


def wait_for_verification(
    plan: MigrationPlan,
    *,
    home: Path,
    cockpit_dir: Path,
    explicit_db: Path | None,
    timeout: float,
) -> int:
    if timeout <= 0:
        return 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = read_cockpit_snapshot(cockpit_dir, home, explicit_db)
        verified = sum(
            int(_identity_match(candidate, snapshot.accounts))
            for candidate in plan.candidates
        )
        if verified == len(plan.candidates):
            return verified
        time.sleep(0.5)
    snapshot = read_cockpit_snapshot(cockpit_dir, home, explicit_db)
    return sum(
        int(_identity_match(candidate, snapshot.accounts)) for candidate in plan.candidates
    )


def _print_summary(summary: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return
    for key, value in summary.items():
        print(f"{key}={value}")


def run_migration(args: argparse.Namespace) -> int:
    source_dir = Path(args.source_dir).expanduser()
    cockpit_dir = Path(args.cockpit_data_dir).expanduser()
    explicit_db = Path(args.cockpit_localstorage_db).expanduser() if args.cockpit_localstorage_db else None
    history_path = (
        Path(args.history_file).expanduser()
        if args.history_file
        else cockpit_dir / "cliproxyapi_migration_history.json"
    )

    source = read_source_accounts(source_dir)
    cockpit = read_cockpit_snapshot(cockpit_dir, Path.home(), explicit_db)
    plan = build_plan(source, cockpit)
    if plan.ambiguous_count or source.conflict_count:
        raise MigrationError("发现身份或凭据冲突，已停止；没有写入 Cockpit")
    if plan.unverified_count and not args.allow_unverified:
        raise MigrationError(
            "Cockpit 凭据缓存不可读，无法安全判断更新；请修复缓存后重试，或明确使用 --allow-unverified"
        )

    fingerprint_key = _load_fingerprint_key(cockpit_dir, create=bool(args.apply))
    fingerprints = [account_fingerprint(account, fingerprint_key) for account in plan.candidates]
    summary: dict[str, Any] = {
        **plan.summary(),
        "mode": "apply" if args.apply else "dry_run",
        "status": "planned",
        "requested": 0,
        "verified": 0,
        "import_request_received": False,
        "backup_created": False,
    }

    if not args.apply or not plan.candidates:
        append_history(
            history_path,
            status="dry_run" if not args.apply else "noop",
            plan=plan,
            fingerprints=fingerprints,
        )
        summary["status"] = "dry_run" if not args.apply else "noop"
        _print_summary(summary, as_json=args.json)
        return 0

    if not args.yes:
        if not sys.stdin.isatty():
            raise MigrationError("应用迁移请同时使用 --yes（当前不会自动确认）")
        answer = input(f"将通过 Cockpit 导入 {len(plan.candidates)} 个新增/更新账号，继续？ [y/N] ")
        if answer.strip().casefold() not in {"y", "yes"}:
            raise MigrationError("用户取消迁移")

    backup_created = create_backup(cockpit_dir, cockpit.cache_path)
    received = send_bundle_to_cockpit(plan.candidates, args.wait_seconds)
    verified = wait_for_verification(
        plan,
        home=Path.home(),
        cockpit_dir=cockpit_dir,
        explicit_db=explicit_db,
        timeout=args.wait_seconds,
    )
    status = "applied" if received and verified == len(plan.candidates) else "partial"
    append_history(
        history_path,
        status=status,
        plan=plan,
        fingerprints=fingerprints,
        backup_created=backup_created,
        requested=len(plan.candidates),
        verified=verified,
        import_request_received=received,
    )
    summary.update(
        {
            "status": status,
            "requested": len(plan.candidates),
            "verified": verified,
            "import_request_received": received,
            "backup_created": backup_created,
        }
    )
    _print_summary(summary, as_json=args.json)
    return 0 if status == "applied" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        default=os.environ.get("CLIPROXYAPI_AUTH_DIR", str(DEFAULT_SOURCE_DIR)),
        help="CLIProxyAPI auth directory (default: ~/.cli-proxy-api)",
    )
    parser.add_argument(
        "--cockpit-data-dir",
        default=os.environ.get("COCKPIT_TOOLS_DATA_DIR", str(DEFAULT_COCKPIT_DIR)),
        help="Cockpit data directory (default: ~/.antigravity_cockpit)",
    )
    parser.add_argument(
        "--cockpit-localstorage-db",
        help="Optional explicit Cockpit WebKit LocalStorage SQLite path",
    )
    parser.add_argument(
        "--history-file",
        help="Safe local history JSON path (default: Cockpit data directory)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the official Cockpit import (dry-run is the default)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Do not ask for an interactive confirmation",
    )
    parser.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow new imports when an existing Cockpit credential cache is unavailable",
    )
    parser.add_argument(
        "--wait-seconds",
        type=float,
        default=DEFAULT_WAIT_SECONDS,
        help="Seconds to wait for the deep-link request and verification",
    )
    parser.add_argument("--json", action="store_true", help="Print a sanitized JSON summary")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_migration(args)
    except MigrationError as exc:
        print(f"migration_error={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
