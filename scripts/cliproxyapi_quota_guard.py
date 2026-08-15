#!/usr/bin/env python3
"""Persistently exclude credentials after a confirmed Codex usage-limit 429.

The guard deliberately ignores provider quota percentages.  It acts only on an
execution record whose error type is exactly ``usage_limit_reached``.  A locked
credential receives weight zero while CLIProxyAPI uses weighted round-robin;
its previous weight is restored after the confirmed provider reset deadline or
by the companion manual reset helper.

No token, email address, auth filename, or management key is written to the
guard state file.  The file contains only CLIProxyAPI's opaque auth index, the
sidecar's private subscription identity, timestamps, and the previous numeric
weight.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlencode, urlsplit


DEFAULT_STATE_FILE = (
    Path.home() / ".config" / "cliproxy-usage" / "quota-routing-locks.json"
)
MAX_STATE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_ERROR_BODY_BYTES = 128 * 1024
MAX_LOCK_WINDOW = timedelta(days=45)
MAX_SNAPSHOT_AGE = timedelta(hours=24)
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
WEIGHTED_STRATEGIES = {"weighted-round-robin", "weightedroundrobin", "wrr"}
USAGE_LIMIT_PATTERN = re.compile(
    r'["\']type["\']\s*:\s*["\']usage_limit_reached["\']', re.IGNORECASE
)
RESET_AT_PATTERN = re.compile(r'["\']resets_at["\']\s*:\s*(\d+)', re.IGNORECASE)
RESET_IN_PATTERN = re.compile(r'["\']resets_in_seconds["\']\s*:\s*(\d+)', re.IGNORECASE)


class QuotaGuardError(RuntimeError):
    """Expected, redacted guard failure."""


@dataclass(frozen=True)
class GuardLock:
    auth_index: str
    identity_key: str
    locked_until: str
    locked_at: str
    original_weight: int | None
    applied: bool = True
    source: str = "usage_limit_reached"

    def as_json(self) -> dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "locked_until": self.locked_until,
            "locked_at": self.locked_at,
            "original_weight": self.original_weight,
            "applied": self.applied,
            "source": self.source,
        }


def utc_datetime(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def utc_text(value: datetime) -> str:
    return utc_datetime(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return utc_datetime(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        raw = float(value)
        if raw <= 0:
            return None
        if raw > 10_000_000_000:
            raw /= 1000.0
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return utc_datetime(parsed)


def _validated_lock(auth_index: str, raw: Any) -> GuardLock:
    if (
        not isinstance(auth_index, str)
        or not auth_index.strip()
        or len(auth_index) > 512
    ):
        raise QuotaGuardError("quota guard state contains an invalid auth index")
    if not isinstance(raw, Mapping):
        raise QuotaGuardError("quota guard state contains an invalid lock")
    identity_key = raw.get("identity_key")
    if (
        not isinstance(identity_key, str)
        or not identity_key.startswith("subscription:")
        or len(identity_key) > 300
    ):
        raise QuotaGuardError(
            "quota guard state contains an invalid subscription identity"
        )
    locked_until = raw.get("locked_until")
    locked_at = raw.get("locked_at")
    if parse_time(locked_until) is None or parse_time(locked_at) is None:
        raise QuotaGuardError("quota guard state contains an invalid timestamp")
    original_weight = raw.get("original_weight")
    if original_weight is not None and (
        isinstance(original_weight, bool)
        or not isinstance(original_weight, int)
        or not 0 < original_weight <= 1_000_000
    ):
        raise QuotaGuardError("quota guard state contains an invalid previous weight")
    applied = raw.get("applied", True)
    if not isinstance(applied, bool):
        raise QuotaGuardError("quota guard state contains an invalid phase")
    source = raw.get("source", "usage_limit_reached")
    if source != "usage_limit_reached":
        raise QuotaGuardError("quota guard state contains an unsupported source")
    return GuardLock(
        auth_index=auth_index.strip(),
        identity_key=identity_key,
        locked_until=utc_text(parse_time(locked_until)),  # type: ignore[arg-type]
        locked_at=utc_text(parse_time(locked_at)),  # type: ignore[arg-type]
        original_weight=original_weight,
        applied=applied,
        source=source,
    )


def load_guard_locks(path: str | Path = DEFAULT_STATE_FILE) -> dict[str, GuardLock]:
    state_path = Path(path).expanduser()
    try:
        file_stat = state_path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise QuotaGuardError("quota guard state is unavailable") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise QuotaGuardError("quota guard state must be a regular non-symlink file")
    if file_stat.st_mode & 0o077:
        raise QuotaGuardError("quota guard state must be owner-only (mode 600)")
    if file_stat.st_size <= 0 or file_stat.st_size > MAX_STATE_BYTES:
        raise QuotaGuardError("quota guard state has an invalid size")
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QuotaGuardError("quota guard state is invalid") from exc
    if not isinstance(payload, Mapping) or payload.get("version") != 1:
        raise QuotaGuardError("quota guard state has an unsupported version")
    raw_locks = payload.get("locks")
    if not isinstance(raw_locks, Mapping):
        raise QuotaGuardError("quota guard state has no lock inventory")
    return {
        lock.auth_index: lock
        for auth_index, raw in raw_locks.items()
        if (lock := _validated_lock(auth_index, raw))
    }


def save_guard_locks(
    path: str | Path,
    locks: Mapping[str, GuardLock],
) -> None:
    state_path = Path(path).expanduser()
    parent = state_path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_stat = parent.lstat()
    except OSError as exc:
        raise QuotaGuardError("quota guard state directory is unavailable") from exc
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise QuotaGuardError("quota guard state directory is unsafe")
    try:
        existing = state_path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise QuotaGuardError("quota guard state path is unavailable") from exc
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
    ):
        raise QuotaGuardError("quota guard state path is unsafe")

    payload = {
        "version": 1,
        "locks": {
            auth_index: locks[auth_index].as_json() for auth_index in sorted(locks)
        },
    }
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".quota-routing-locks.", dir=parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(
                payload,
                handle,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, state_path)
        temporary_name = ""
        state_path.chmod(0o600)
    except OSError as exc:
        raise QuotaGuardError("quota guard state could not be saved") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def remove_guard_lock(
    path: str | Path,
    auth_index: str,
) -> bool:
    locks = load_guard_locks(path)
    if auth_index not in locks:
        return False
    del locks[auth_index]
    save_guard_locks(path, locks)
    return True


def _decoded_body(body: Any) -> tuple[Any, str]:
    if isinstance(body, (bytes, bytearray)):
        text = bytes(body[:MAX_ERROR_BODY_BYTES]).decode("utf-8", "replace")
    elif isinstance(body, str):
        text = body[:MAX_ERROR_BODY_BYTES]
    elif isinstance(body, Mapping) or isinstance(body, list):
        try:
            text = json.dumps(body, ensure_ascii=True, separators=(",", ":"))[
                :MAX_ERROR_BODY_BYTES
            ]
        except (TypeError, ValueError):
            text = ""
        return body, text
    else:
        return None, ""
    decoded: Any = None
    candidate = text
    for _ in range(2):
        try:
            decoded = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            break
        if isinstance(decoded, str):
            candidate = decoded[:MAX_ERROR_BODY_BYTES]
            continue
        break
    return decoded, text


def usage_limit_signal(
    body: Any,
    now: datetime | None = None,
) -> tuple[bool, datetime | None]:
    """Return an exact usage-limit signal and its provider reset deadline."""

    current = utc_datetime(now)
    decoded, text = _decoded_body(body)
    exact = False
    reset_at_values: list[datetime] = []
    reset_in_values: list[datetime] = []

    def visit(value: Any) -> None:
        nonlocal exact
        if isinstance(value, Mapping):
            node_exact = (
                str(value.get("type") or "").strip().lower() == "usage_limit_reached"
            )
            if node_exact:
                exact = True
                reset_at = parse_time(value.get("resets_at"))
                if reset_at is not None and reset_at > current:
                    reset_at_values.append(reset_at)
                reset_in = value.get("resets_in_seconds")
                if (
                    isinstance(reset_in, (int, float))
                    and not isinstance(reset_in, bool)
                    and 0 < float(reset_in) <= MAX_LOCK_WINDOW.total_seconds()
                ):
                    reset_in_values.append(current + timedelta(seconds=float(reset_in)))
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(decoded)
    if not exact and USAGE_LIMIT_PATTERN.search(text):
        exact = True
        for match in RESET_AT_PATTERN.finditer(text):
            parsed = parse_time(int(match.group(1)))
            if parsed is not None and parsed > current:
                reset_at_values.append(parsed)
        for match in RESET_IN_PATTERN.finditer(text):
            seconds = int(match.group(1))
            if 0 < seconds <= MAX_LOCK_WINDOW.total_seconds():
                reset_in_values.append(current + timedelta(seconds=seconds))
    if not exact:
        return False, None
    if reset_at_values:
        return True, max(reset_at_values)
    if reset_in_values:
        return True, max(reset_in_values)
    return True, None


def snapshot_reset_deadline(
    repo: Any,
    identity_key: str,
    now: datetime | None = None,
) -> datetime | None:
    """Return the latest future reset shared by provider-confirmed full windows."""

    current = utc_datetime(now)
    candidates: list[datetime] = []
    try:
        rows = repo.latest_subscription_quotas()
    except Exception as exc:
        raise QuotaGuardError("quota snapshot lookup failed") from exc
    for row in rows:
        if not isinstance(row, Mapping) or row.get("identity_key") != identity_key:
            continue
        fetched_at = parse_time(row.get("fetched_at"))
        reset_at = parse_time(row.get("reset_at"))
        if (
            fetched_at is None
            or reset_at is None
            or current - fetched_at > MAX_SNAPSHOT_AGE
            or reset_at <= current
            or reset_at - current > MAX_LOCK_WINDOW
        ):
            continue
        used = row.get("used_percent")
        remaining = row.get("remaining_percent")
        try:
            exhausted = (remaining is not None and float(remaining) <= 0.0001) or (
                used is not None and float(used) >= 99.9999
            )
        except (TypeError, ValueError, OverflowError):
            exhausted = False
        if exhausted:
            candidates.append(reset_at)
    return max(candidates) if candidates else None


ManagementRequester = Callable[[str, str, str, Any], tuple[int, Any]]


class QuotaRoutingGuard:
    """Manage weight-zero routing locks for exact Codex quota exhaustion."""

    def __init__(
        self,
        repo: Any,
        upstream: str | SplitResult,
        *,
        enabled: bool = False,
        state_file: str | Path = DEFAULT_STATE_FILE,
        timeout: float = 10.0,
        requester: ManagementRequester | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.repo = repo
        self.upstream = urlsplit(upstream) if isinstance(upstream, str) else upstream
        if (
            self.upstream.scheme not in {"http", "https"}
            or self.upstream.hostname not in LOOPBACK_HOSTS
            or self.upstream.username
            or self.upstream.password
        ):
            raise ValueError(
                "quota routing guard requires a loopback management origin"
            )
        self.enabled = bool(enabled)
        self.state_file = Path(state_file).expanduser()
        self.timeout = max(1.0, float(timeout))
        self.requester = requester
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._last_error_type: str | None = None
        self._last_action_at: str | None = None
        self._locks_created = 0
        self._locks_released = 0
        self._routing_checked_at: datetime | None = None
        self._routing_compatible = False

    def _now(self) -> datetime:
        return utc_datetime(self.now_fn())

    def _request(
        self,
        key: str,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        if self.requester is not None:
            return self.requester(key, method, path, payload)
        port = self.upstream.port or (443 if self.upstream.scheme == "https" else 80)
        if self.upstream.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.upstream.hostname,
                port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(
                self.upstream.hostname, port, timeout=self.timeout
            )
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
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
            raise QuotaGuardError(
                f"quota guard management request failed: {type(exc).__name__}"
            ) from exc
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise QuotaGuardError("quota guard management response is too large")
        try:
            parsed = json.loads(raw) if raw else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = None
        return response.status, parsed

    def _weighted_routing_enabled(self, key: str, now: datetime) -> bool:
        if (
            self._routing_checked_at is not None
            and now - self._routing_checked_at < timedelta(seconds=60)
        ):
            return self._routing_compatible
        status, payload = self._request(key, "GET", "/v0/management/routing/strategy")
        strategy = (
            str(payload.get("strategy") or "").strip().lower()
            if status == 200 and isinstance(payload, Mapping)
            else ""
        )
        self._routing_checked_at = now
        self._routing_compatible = strategy in WEIGHTED_STRATEGIES
        return self._routing_compatible

    def _auth_item(self, key: str, auth_index: str) -> Mapping[str, Any]:
        query = urlencode({"auth_index": auth_index})
        status, payload = self._request(
            key, "GET", f"/v0/management/auth-files?{query}"
        )
        files = payload.get("files") if isinstance(payload, Mapping) else None
        matches = [
            item
            for item in files or []
            if isinstance(item, Mapping)
            and str(item.get("auth_index") or item.get("authIndex") or "").strip()
            == auth_index
            and str(item.get("provider") or item.get("type") or "").strip().lower()
            == "codex"
        ]
        if status != 200 or len(matches) != 1:
            raise QuotaGuardError("quota guard could not resolve one Codex credential")
        return matches[0]

    @staticmethod
    def _item_weight(item: Mapping[str, Any]) -> int | None:
        if "weight" not in item or item.get("weight") is None:
            return None
        value = item.get("weight")
        if isinstance(value, bool):
            raise QuotaGuardError("credential has an invalid routing weight")
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise QuotaGuardError("credential has an invalid routing weight") from exc
        if str(value).strip() != str(parsed) or not 0 <= parsed <= 1_000_000:
            raise QuotaGuardError("credential has an invalid routing weight")
        return parsed

    def _patch_weight(
        self,
        key: str,
        item: Mapping[str, Any],
        weight: int | None,
    ) -> None:
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or len(name) > 512:
            raise QuotaGuardError("credential has no safe auth filename")
        status, payload = self._request(
            key,
            "PATCH",
            "/v0/management/auth-files/fields",
            {"name": name.strip(), "weight": weight},
        )
        if (
            status != 200
            or not isinstance(payload, Mapping)
            or payload.get("status") != "ok"
        ):
            raise QuotaGuardError("quota guard weight update failed")

    def observe_record(self, record: Mapping[str, Any], event: Any, key: str) -> bool:
        """Lock one credential when a queue record proves usage exhaustion."""

        if not self.enabled:
            return False
        fail = record.get("fail") if isinstance(record.get("fail"), Mapping) else {}
        status_code = fail.get("status_code")
        try:
            status = int(status_code)
        except (TypeError, ValueError, OverflowError):
            status = 0
        if record.get("failed") is not True or status != 429:
            return False
        exact, provider_deadline = usage_limit_signal(fail.get("body"), self._now())
        if not exact:
            return False
        auth_index = record.get("auth_index")
        identity_key = getattr(event, "identity_key", None)
        if (
            not isinstance(auth_index, str)
            or not auth_index.strip()
            or len(auth_index) > 512
            or not isinstance(identity_key, str)
            or not identity_key.startswith("subscription:")
        ):
            self._last_error_type = "identity_unresolved"
            return False
        now = self._now()
        deadline = provider_deadline or snapshot_reset_deadline(
            self.repo, identity_key, now
        )
        if (
            deadline is None
            or deadline <= now + timedelta(seconds=1)
            or deadline - now > MAX_LOCK_WINDOW
        ):
            self._last_error_type = "reset_deadline_unavailable"
            return False
        try:
            with self._lock:
                if not self._weighted_routing_enabled(key, now):
                    raise QuotaGuardError(
                        "quota routing guard requires weighted-round-robin"
                    )
                self._apply_lock(
                    key,
                    auth_index.strip(),
                    identity_key,
                    deadline,
                    now,
                )
            self._last_error_type = None
            self._last_action_at = utc_text(now)
            return True
        except QuotaGuardError as exc:
            self._last_error_type = type(exc).__name__
            return False

    def _apply_lock(
        self,
        key: str,
        auth_index: str,
        identity_key: str,
        deadline: datetime,
        now: datetime,
    ) -> None:
        locks = load_guard_locks(self.state_file)
        existing = locks.get(auth_index)
        item = self._auth_item(key, auth_index)
        current_weight = self._item_weight(item)
        if existing is None and current_weight == 0:
            raise QuotaGuardError(
                "credential already has an operator-supplied zero weight"
            )
        original_weight = (
            existing.original_weight if existing is not None else current_weight
        )
        existing_deadline = parse_time(existing.locked_until) if existing else None
        effective_deadline = max(
            deadline,
            existing_deadline or deadline,
        )
        pending = GuardLock(
            auth_index=auth_index,
            identity_key=identity_key,
            locked_until=utc_text(effective_deadline),
            locked_at=existing.locked_at if existing else utc_text(now),
            original_weight=original_weight,
            applied=False,
        )
        locks[auth_index] = pending
        save_guard_locks(self.state_file, locks)
        if current_weight != 0:
            try:
                self._patch_weight(key, item, 0)
            except Exception:
                locks.pop(auth_index, None)
                save_guard_locks(self.state_file, locks)
                raise
        # If this final state write fails after the management PATCH succeeded,
        # keep the already-durable pending record.  The next reconcile pass can
        # observe weight zero and finish the state transition instead of
        # orphaning a credential that no longer has restoration metadata.
        locks[auth_index] = GuardLock(**{**pending.__dict__, "applied": True})
        save_guard_locks(self.state_file, locks)
        if existing is None:
            self._locks_created += 1

    def reconcile(self, key: str) -> int:
        """Finish pending locks and release locks whose reset time has arrived."""

        if not self.enabled:
            return 0
        released = 0
        now = self._now()
        try:
            with self._lock:
                routing_compatible = self._weighted_routing_enabled(key, now)
                locks = load_guard_locks(self.state_file)
                for auth_index, lock in list(locks.items()):
                    deadline = parse_time(lock.locked_until)
                    if deadline is None:
                        raise QuotaGuardError("quota guard lock has no deadline")
                    if not lock.applied and deadline > now:
                        item = self._auth_item(key, auth_index)
                        if self._item_weight(item) != 0:
                            self._patch_weight(key, item, 0)
                        locks[auth_index] = GuardLock(
                            **{**lock.__dict__, "applied": True}
                        )
                        save_guard_locks(self.state_file, locks)
                        continue
                    if deadline > now:
                        continue
                    item = self._auth_item(key, auth_index)
                    status, payload = self._request(
                        key,
                        "POST",
                        "/v0/management/reset-quota",
                        {"auth_index": auth_index},
                    )
                    if (
                        status != 200
                        or not isinstance(payload, Mapping)
                        or payload.get("status") != "ok"
                    ):
                        raise QuotaGuardError("automatic quota reset failed")
                    if self._item_weight(item) == 0:
                        self._patch_weight(key, item, lock.original_weight)
                    del locks[auth_index]
                    save_guard_locks(self.state_file, locks)
                    released += 1
                if released:
                    self._locks_released += released
                    self._last_action_at = utc_text(now)
            self._last_error_type = (
                None if routing_compatible else "routing_strategy_incompatible"
            )
        except QuotaGuardError as exc:
            self._last_error_type = type(exc).__name__
        return released

    def status(self) -> dict[str, Any]:
        count = 0
        next_unlock: str | None = None
        try:
            locks = load_guard_locks(self.state_file) if self.enabled else {}
            count = len(locks)
            deadlines = [
                lock.locked_until
                for lock in locks.values()
                if parse_time(lock.locked_until) is not None
            ]
            next_unlock = min(deadlines) if deadlines else None
        except QuotaGuardError:
            self._last_error_type = "QuotaGuardError"
        return {
            "enabled": self.enabled,
            "routing_compatible": self._routing_compatible,
            "active_locks": count,
            "next_unlock_at": next_unlock,
            "locks_created": self._locks_created,
            "locks_released": self._locks_released,
            "last_action_at": self._last_action_at,
            "last_error_type": self._last_error_type,
        }
