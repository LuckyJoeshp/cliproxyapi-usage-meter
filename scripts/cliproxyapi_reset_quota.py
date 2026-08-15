#!/usr/bin/env python3
"""Clear one or all confirmed CLIProxyAPI quota cooldowns through its management API.

The helper never edits or deletes ``.cds`` files directly.  It resolves an
exact local Codex alias, auth filename, auth id, or auth index and calls the
official ``reset-quota`` endpoint.  Management keys are read only from an
owner-only file, an explicitly named environment variable, or (when requested)
the existing Chrome-session helper; key values are never printed or logged.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import stat
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.cliproxy_usage_meter import AccountResolver  # noqa: E402
from scripts.cliproxyapi_quota_guard import (  # noqa: E402
    DEFAULT_STATE_FILE as DEFAULT_QUOTA_GUARD_STATE_FILE,
    GuardLock,
    QuotaGuardError,
    load_guard_locks,
    save_guard_locks,
)


DEFAULT_BASE_URL = "http://127.0.0.1:8317"
DEFAULT_KEY_ENV = "CLIPROXY_MANAGEMENT_KEY"
MAX_KEY_BYTES = 4096
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
QUOTA_MARKERS = (
    "usage_limit",
    "usage limit",
    "quota",
    "额度",
)


class QuotaResetError(RuntimeError):
    """Expected, redacted operator error."""


def parse_loopback_base_url(value: str) -> SplitResult:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise QuotaResetError("management URL must use http or https")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise QuotaResetError("management URL must point to loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise QuotaResetError("management URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise QuotaResetError("management URL must not contain a path")
    return parsed


def load_owner_key_file(path: Path) -> str:
    try:
        file_stat = path.stat()
    except OSError as exc:
        raise QuotaResetError("management key file is unavailable") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise QuotaResetError("management key path is not a regular file")
    if file_stat.st_mode & 0o077:
        raise QuotaResetError("management key file must be owner-only (mode 600)")
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_KEY_BYTES:
        raise QuotaResetError("management key file has an invalid size")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise QuotaResetError("management key file could not be read") from exc
    if not value or len(value.encode("utf-8")) > MAX_KEY_BYTES:
        raise QuotaResetError("management key file is empty or too large")
    return value


def load_management_key(
    *,
    key_file: str | None,
    key_env: str,
    from_chrome: bool,
) -> str:
    if key_file:
        return load_owner_key_file(Path(key_file).expanduser())
    env_name = key_env.strip()
    if env_name:
        value = os.environ.get(env_name, "").strip()
        if value:
            if len(value.encode("utf-8")) > MAX_KEY_BYTES:
                raise QuotaResetError("management key environment value is too large")
            return value
    if from_chrome:
        from scripts.start_cliproxy_usage_meter_from_chrome import iter_management_keys

        value = next(iter_management_keys(), None)
        if value:
            return value
        raise QuotaResetError("no Chrome management session key was found")
    raise QuotaResetError(
        "no management key configured; use --management-key-file, the configured environment variable, or --from-chrome"
    )


def management_request(
    parsed_base: SplitResult,
    key: str,
    method: str,
    path: str,
    payload: Mapping[str, Any] | None = None,
    *,
    timeout: float = 10.0,
) -> tuple[int, Any]:
    host = parsed_base.hostname
    if host is None:
        raise QuotaResetError("management URL has no host")
    port = parsed_base.port or (443 if parsed_base.scheme == "https" else 80)
    connection_class = (
        http.client.HTTPSConnection
        if parsed_base.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_class(host, port, timeout=max(float(timeout), 1.0))
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "Connection": "close",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise QuotaResetError(f"management request failed: {type(exc).__name__}") from exc
    finally:
        connection.close()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise QuotaResetError("management response is too large")
    try:
        parsed = json.loads(raw) if raw else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = None
    return response.status, parsed


def codex_files(payload: Any) -> list[Mapping[str, Any]]:
    if not isinstance(payload, Mapping) or not isinstance(payload.get("files"), list):
        raise QuotaResetError("management auth inventory is incomplete")
    return [
        item
        for item in payload["files"]
        if isinstance(item, Mapping)
        and str(item.get("provider") or item.get("type") or "").strip().lower() == "codex"
    ]


def item_names(item: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("name", "id", "filename", "file_name"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return tuple(dict.fromkeys(values))


def item_alias(item: Mapping[str, Any], resolver: AccountResolver) -> str | None:
    aliases: set[str] = set()
    for name in item_names(item):
        identity = resolver.resolve_auth_file(name)
        if identity.usage_alias:
            aliases.add(identity.usage_alias)
    return next(iter(aliases)) if len(aliases) == 1 else None


def select_target(
    files: Iterable[Mapping[str, Any]],
    selector: str,
    resolver: AccountResolver,
) -> Mapping[str, Any]:
    selector = selector.strip()
    if not selector:
        raise QuotaResetError("credential selector is empty")
    candidates = list(files)
    exact = [
        item
        for item in candidates
        if selector in item_names(item)
        or selector == str(item.get("auth_index") or item.get("authIndex") or "").strip()
    ]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise QuotaResetError("credential selector is ambiguous")
    by_alias = [item for item in candidates if item_alias(item, resolver) == selector]
    if len(by_alias) == 1:
        return by_alias[0]
    if len(by_alias) > 1:
        raise QuotaResetError("Codex alias maps to multiple credential records")
    raise QuotaResetError("credential selector did not match a Codex record")


def quota_lock_deadline(item: Mapping[str, Any]) -> str | None:
    if item.get("unavailable") is not True:
        return None
    deadline = item.get("next_retry_after") or item.get("nextRetryAfter")
    if not isinstance(deadline, str) or not deadline.strip():
        return None
    message = str(item.get("status_message") or item.get("statusMessage") or "").lower()
    return deadline.strip() if any(marker in message for marker in QUOTA_MARKERS) else None


def auth_index(item: Mapping[str, Any]) -> str:
    value = item.get("auth_index") or item.get("authIndex")
    if not isinstance(value, str) or not value.strip():
        raise QuotaResetError("matched credential has no auth_index")
    return value.strip()


def explicit_weight(item: Mapping[str, Any]) -> int | None:
    if "weight" not in item or item.get("weight") is None:
        return None
    value = item.get("weight")
    if isinstance(value, bool):
        raise QuotaResetError("matched credential has an invalid routing weight")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise QuotaResetError("matched credential has an invalid routing weight") from exc
    if str(value).strip() != str(parsed) or not 0 <= parsed <= 1_000_000:
        raise QuotaResetError("matched credential has an invalid routing weight")
    return parsed


def restore_guard_weight(
    parsed_base: SplitResult,
    key: str,
    item: Mapping[str, Any],
    lock: GuardLock,
    locks: dict[str, GuardLock],
    state_file: str | Path,
    *,
    timeout: float,
) -> None:
    # A nonzero current weight is treated as an explicit operator override and
    # is never replaced with stale guard state.
    if explicit_weight(item) == 0:
        names = item_names(item)
        if not names:
            raise QuotaResetError("matched credential has no auth filename")
        status, payload = management_request(
            parsed_base,
            key,
            "PATCH",
            "/v0/management/auth-files/fields",
            {"name": names[0], "weight": lock.original_weight},
            timeout=timeout,
        )
        if status != 200 or not isinstance(payload, Mapping) or payload.get("status") != "ok":
            raise QuotaResetError(f"quota guard weight restore failed (HTTP {status})")
    locks.pop(lock.auth_index, None)
    save_guard_locks(state_file, locks)


def numeric_alias_key(alias: str | None) -> tuple[int, str]:
    if alias and alias.startswith("codex-") and alias[6:].isdigit():
        return int(alias[6:]), alias
    return sys.maxsize, alias or ""


def print_locked_credentials(
    files: Iterable[Mapping[str, Any]],
    resolver: AccountResolver,
    *,
    show_names: bool,
    guard_locks: Mapping[str, GuardLock] | None = None,
) -> None:
    guard_locks = guard_locks or {}
    rows: list[tuple[str | None, str | None, str]] = []
    seen_indexes: set[str] = set()
    for item in files:
        index = str(item.get("auth_index") or item.get("authIndex") or "").strip()
        if index:
            seen_indexes.add(index)
        guard_lock = guard_locks.get(index)
        deadline = quota_lock_deadline(item) or (
            guard_lock.locked_until if guard_lock is not None else None
        )
        if deadline is None:
            continue
        alias = item_alias(item, resolver)
        name = item_names(item)[0] if item_names(item) else None
        rows.append((alias, name, deadline))
    rows.sort(key=lambda row: numeric_alias_key(row[0]))
    print(f"confirmed quota locks: {len(rows)}")
    unmapped = 0
    for alias, name, deadline in rows:
        label = alias
        if label is None and show_names:
            label = name or "unmapped"
        if label is None:
            unmapped += 1
            continue
        print(f"- {label}: retry after {deadline}")
    if unmapped:
        print(f"- {unmapped} additional locked credential(s) have no local codex-N alias")
    missing = len(set(guard_locks) - seen_indexes)
    if missing:
        print(f"- {missing} additional guard lock(s) are waiting for their credential inventory")


def confirmed_lock_targets(
    files: Iterable[Mapping[str, Any]],
    guard_locks: Mapping[str, GuardLock],
) -> list[Mapping[str, Any]]:
    """Resolve every confirmed official or guard-owned lock before mutation."""

    targets: list[Mapping[str, Any]] = []
    seen_indexes: set[str] = set()
    for item in files:
        raw_index = item.get("auth_index") or item.get("authIndex")
        index_hint = raw_index.strip() if isinstance(raw_index, str) else ""
        deadline = quota_lock_deadline(item)
        if deadline is None and index_hint not in guard_locks:
            continue
        index = auth_index(item)
        if index in seen_indexes:
            raise QuotaResetError("confirmed quota inventory contains a duplicate auth_index")
        seen_indexes.add(index)
        targets.append(item)
    missing = set(guard_locks) - seen_indexes
    if missing:
        raise QuotaResetError(
            f"{len(missing)} guard lock(s) could not be resolved in the current credential inventory"
        )
    return targets


def clear_confirmed_lock(
    parsed_base: SplitResult,
    key: str,
    item: Mapping[str, Any],
    guard_locks: dict[str, GuardLock],
    state_file: str | Path,
    *,
    timeout: float,
) -> None:
    index = auth_index(item)
    guard_lock = guard_locks.get(index)
    if quota_lock_deadline(item) is None and guard_lock is None:
        raise QuotaResetError("matched credential is not in a confirmed quota cooldown")
    status, response_payload = management_request(
        parsed_base,
        key,
        "POST",
        "/v0/management/reset-quota",
        {"auth_index": index},
        timeout=timeout,
    )
    if (
        status != 200
        or not isinstance(response_payload, Mapping)
        or response_payload.get("status") != "ok"
    ):
        raise QuotaResetError(f"quota reset failed (HTTP {status})")
    if guard_lock is not None:
        restore_guard_weight(
            parsed_base,
            key,
            item,
            guard_lock,
            guard_locks,
            state_file,
            timeout=timeout,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selector", nargs="?", help="Exact codex-N alias, auth filename, auth id, or auth_index")
    parser.add_argument("--list", action="store_true", help="List confirmed quota locks without changing them")
    parser.add_argument(
        "--all",
        dest="all_locked",
        action="store_true",
        help="Clear every confirmed official cooldown and guard-owned routing lock",
    )
    parser.add_argument("--show-names", action="store_true", help="Show auth filenames for locked records without codex-N aliases")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and validate the selected lock or batch without clearing it",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Loopback CLIProxyAPI management origin")
    parser.add_argument(
        "--management-key-file",
        default=os.environ.get("CLIPROXY_MANAGEMENT_KEY_FILE", ""),
        help="Owner-only file containing the management key",
    )
    parser.add_argument(
        "--management-key-env",
        default=os.environ.get("CLIPROXY_MANAGEMENT_KEY_ENV", DEFAULT_KEY_ENV),
        help="Environment variable name containing the management key",
    )
    parser.add_argument(
        "--from-chrome",
        action="store_true",
        help="Explicitly use the existing local Chrome management session when no file/environment key is set",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Management request timeout in seconds")
    parser.add_argument(
        "--quota-guard-state-file",
        default=os.environ.get(
            "CLIPROXY_QUOTA_ROUTING_GUARD_STATE_FILE",
            str(DEFAULT_QUOTA_GUARD_STATE_FILE),
        ),
        help="Owner-only state file used by the confirmed quota routing guard",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    action_count = int(bool(args.selector)) + int(args.list) + int(args.all_locked)
    if action_count > 1:
        print("selector, --list, and --all are mutually exclusive", file=sys.stderr)
        return 2
    if action_count == 0:
        print("a selector, --list, or --all is required", file=sys.stderr)
        return 2
    try:
        parsed_base = parse_loopback_base_url(args.base_url)
        key = load_management_key(
            key_file=args.management_key_file or None,
            key_env=args.management_key_env,
            from_chrome=args.from_chrome,
        )
        status, payload = management_request(
            parsed_base,
            key,
            "GET",
            "/v0/management/auth-files",
            timeout=args.timeout,
        )
        if status != 200:
            raise QuotaResetError(f"management authentication or inventory request failed (HTTP {status})")
        files = codex_files(payload)
        resolver = AccountResolver()
        guard_locks = load_guard_locks(args.quota_guard_state_file)
        if args.list:
            print_locked_credentials(
                files,
                resolver,
                show_names=args.show_names,
                guard_locks=guard_locks,
            )
            return 0
        if args.all_locked:
            targets = confirmed_lock_targets(files, guard_locks)
            if args.dry_run:
                print(
                    "dry-run: "
                    f"{len(targets)} confirmed quota cooldown(s) would be cleared"
                )
                return 0
            for target in targets:
                clear_confirmed_lock(
                    parsed_base,
                    key,
                    target,
                    guard_locks,
                    args.quota_guard_state_file,
                    timeout=args.timeout,
                )
            print(f"confirmed quota cooldowns cleared: {len(targets)}")
            return 0
        target = select_target(files, args.selector, resolver)
        deadline = quota_lock_deadline(target)
        index = auth_index(target)
        guard_lock = guard_locks.get(index)
        if deadline is None and guard_lock is None:
            raise QuotaResetError("matched credential is not in a confirmed quota cooldown")
        effective_deadline = deadline or guard_lock.locked_until  # type: ignore[union-attr]
        if args.dry_run:
            print(
                "dry-run: confirmed quota lock would be cleared; "
                f"current retry deadline is {effective_deadline}"
            )
            return 0
        clear_confirmed_lock(
            parsed_base,
            key,
            target,
            guard_locks,
            args.quota_guard_state_file,
            timeout=args.timeout,
        )
        print("confirmed quota cooldown cleared")
        return 0
    except (QuotaResetError, QuotaGuardError) as exc:
        print(f"quota reset error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
