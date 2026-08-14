#!/usr/bin/env python3
"""Local, token-safe usage meter in front of an OpenAI-compatible proxy.

The proxy deliberately uses only Python's standard library. Request and response
bodies are inspected in memory for metadata/usage, but are never persisted.
Authorization values are forwarded upstream and immediately reduced to a short
SHA-256 fingerprint for metering.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import html
from html.parser import HTMLParser
import http.client
import json
import logging
import math
import os
import re
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


LOG = logging.getLogger("cliproxy_usage_meter")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8327
DEFAULT_UPSTREAM = "http://127.0.0.1:8317"
DEFAULT_DB = Path(__file__).resolve().parents[1] / "datas" / "cliproxy_usage.sqlite"
OFFICIAL_PRICING_URL = "https://developers.openai.com/api/docs/pricing"
OFFICIAL_PRICING_HOSTS = {"developers.openai.com", "platform.openai.com"}
OFFICIAL_PRICE_PARSER_VERSION = "openai-html-table-v2-long-context"
LONG_CONTEXT_THRESHOLD_TOKENS = 272_000
DEFAULT_USAGE_QUEUE_PATH = "/v0/management/usage-queue"
DEFAULT_USAGE_QUEUE_COUNT = 100
DEFAULT_USAGE_QUEUE_POLL_SECONDS = 5.0
DEFAULT_QUOTA_POLL_SECONDS = 300.0
DEFAULT_QUOTA_POLL_TIMEOUT = 20.0
CODEX_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"
DEFAULT_CODEX_APP_HOME = Path.home() / ".codex"
DEFAULT_CODEX_APP_ALIAS = "codex-13"
DEFAULT_CODEX_APP_POLL_SECONDS = 15.0
MAX_CODEX_APP_JSONL_BYTES = 128 * 1024 * 1024
DEFAULT_CODEX_APP_MAX_FILES = 500
MAX_MANUAL_IMPORT_BYTES = 64 * 1024
DEFAULT_MANAGEMENT_BACKOFF_SECONDS = 300.0
MAX_MANAGEMENT_BACKOFF_SECONDS = 1800.0
MAX_INSPECT_BYTES = 8 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
MAX_SSE_EVENT_BYTES = 2 * 1024 * 1024
QUOTA_ESTIMATE_MIN_USED_PERCENT = 5.0
QUOTA_ESTIMATE_STABLE_USED_PERCENT = 10.0
# Only a provider-reported 100% is treated as a hard cap.  At 95% used
# (5% remaining) we still project to 100% from the observed spend.
QUOTA_ESTIMATE_CAP_CONFIDENCE_PERCENT = 100.0
ALL_TIME_PERIODS = {"all", "all-time", "all_time", "ever", "total"}
PERIOD_START_SENTINEL = "0001-01-01T00:00:00.000000Z"

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
METER_ONLY_HEADERS = {"x-usage-alias", "x-usage-session", "x-usage-project"}
RESET_EVENT_TYPES = {"reset_detected", "manual_reset"}
QUOTA_EVENT_TYPES = {
    "quota_hit",
    "cooldown_hit",
    "usage_limit_hit",
    "rate_limit_hit",
    "manual_quota_hit",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalize_timestamp(value: Any) -> str:
    """Normalize upstream RFC3339 timestamps to the DB's UTC ``Z`` dialect."""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = safe_text(value, 128) if value is not None else None
        if not text:
            return utc_now()
        parsed = None
        candidate = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            parsed = None
        if parsed is None:
            return utc_now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalize_optional_timestamp(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        raw = float(value)
        if raw <= 0:
            return None
        if raw > 10_000_000_000:
            raw /= 1000.0
        try:
            return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            )
        except (OSError, OverflowError, ValueError):
            return None
    text = safe_text(value, 128)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def short_hash(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    raw = value if isinstance(value, bytes) else value.encode("utf-8", "ignore")
    if not raw:
        return None
    return hashlib.sha256(raw).hexdigest()[:16]


def safe_text(value: Any, limit: int = 256) -> str | None:
    if value is None:
        return None
    text = str(value).strip().replace("\x00", "")
    return text[:limit] if text else None


def safe_alias(value: Any) -> str | None:
    text = safe_text(value, 128)
    if text and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", text):
        return text
    return None


def safe_email(value: Any) -> str | None:
    """Return a bounded local identity email suitable for escaped display."""

    text = safe_text(value, 320)
    if not text or text.count("@") != 1 or any(character.isspace() for character in text):
        return None
    local, domain = text.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return None
    return text


def is_auth_fallback_alias(value: Any) -> bool:
    """Return whether an alias is the queue's temporary auth-fingerprint label.

    Queue records can arrive while CLIProxyAPI is still writing a refreshed
    auth file.  During that small race the resolver has no named ``codex-N``
    alias and persists ``auth:<fingerprint>`` instead.  This is a provisional
    label, not a user alias, and may be safely re-bound later.
    """

    text = safe_text(value, 128)
    return bool(text and re.fullmatch(r"auth:[0-9a-f]{16}", text, re.IGNORECASE))


def numeric_alias_key(value: Any) -> tuple[int, str]:
    text = safe_text(value, 128) or ""
    match = re.fullmatch(r"codex-(\d+)", text, re.IGNORECASE)
    return (int(match.group(1)), text) if match else (10**9, text)


_SECRET_KEY_VALUE = re.compile(
    r'(?i)("?(?:authorization|access_token|refresh_token|id_token|api[_-]?key)"?\s*[:=]\s*)'
    r'("?)[^",\s}]+\2'
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SK_TOKEN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_JWT = re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b")
_LONG_SECRET = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")


def redact_text(value: Any, limit: int = 600) -> str | None:
    """Redact common credential shapes before text reaches SQLite or logs."""

    text = safe_text(value, max(limit * 4, 2048))
    if not text:
        return None
    text = _BEARER.sub("Bearer <redacted>", text)
    text = _SECRET_KEY_VALUE.sub(r"\1<redacted>", text)
    text = _SK_TOKEN.sub("<redacted-key>", text)
    text = _JWT.sub("<redacted-jwt>", text)
    text = _LONG_SECRET.sub("<redacted-secret>", text)
    return text[:limit]


def as_nonnegative_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return max(result, 0)


def first_present(mapping: Mapping[str, Any] | None, names: Sequence[str]) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return None


def find_named_mapping(value: Any, key_name: str, depth: int = 0) -> Mapping[str, Any] | None:
    if depth > 5:
        return None
    if isinstance(value, Mapping):
        candidate = value.get(key_name)
        if isinstance(candidate, Mapping):
            return candidate
        for child in value.values():
            found = find_named_mapping(child, key_name, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value[:100]:
            found = find_named_mapping(child, key_name, depth + 1)
            if found is not None:
                return found
    return None


def find_model(value: Any, depth: int = 0) -> str | None:
    if depth > 5:
        return None
    if isinstance(value, Mapping):
        model = value.get("model")
        if isinstance(model, str) and model.strip():
            return safe_text(model, 200)
        for child in value.values():
            found = find_model(child, depth + 1)
            if found:
                return found
    elif isinstance(value, list):
        for child in value[:100]:
            found = find_model(child, depth + 1)
            if found:
                return found
    return None


@dataclass
class NormalizedUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    cache_write_tokens: int | None = None
    reasoning_tokens: int | None = None
    total_tokens: int | None = None

    @property
    def missing(self) -> bool:
        return all(value is None for value in asdict(self).values())


@dataclass(frozen=True)
class PriceComponents:
    """Per-event API-equivalent costs frozen when the event is priced."""

    non_cached_input_cost_usd: float
    cached_input_cost_usd: float
    output_cost_usd: float
    long_context_pricing_applied: bool = False

    @property
    def total_cost_usd(self) -> float:
        return (
            self.non_cached_input_cost_usd
            + self.cached_input_cost_usd
            + self.output_cost_usd
        )


def normalize_usage(value: Any) -> NormalizedUsage:
    usage = value
    if isinstance(value, Mapping) and isinstance(value.get("usage"), Mapping):
        usage = value["usage"]
    if not isinstance(usage, Mapping):
        return NormalizedUsage()

    input_tokens = as_nonnegative_int(first_present(usage, ("input_tokens", "prompt_tokens")))
    output_tokens = as_nonnegative_int(first_present(usage, ("output_tokens", "completion_tokens")))
    total_tokens = as_nonnegative_int(usage.get("total_tokens"))

    input_details = first_present(usage, ("input_tokens_details", "prompt_tokens_details"))
    output_details = first_present(usage, ("output_tokens_details", "completion_tokens_details"))
    cached_tokens = as_nonnegative_int(
        input_details.get("cached_tokens") if isinstance(input_details, Mapping) else None
    )
    cache_write_tokens = as_nonnegative_int(
        input_details.get("cache_write_tokens") if isinstance(input_details, Mapping) else None
    )
    reasoning_tokens = as_nonnegative_int(
        output_details.get("reasoning_tokens") if isinstance(output_details, Mapping) else None
    )
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return NormalizedUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        cache_write_tokens=cache_write_tokens,
        reasoning_tokens=reasoning_tokens,
        total_tokens=total_tokens,
    )


def find_usage(value: Any, depth: int = 0) -> NormalizedUsage:
    if depth > 6:
        return NormalizedUsage()
    if isinstance(value, Mapping):
        direct = normalize_usage(value)
        if not direct.missing:
            return direct
        for child in value.values():
            found = find_usage(child, depth + 1)
            if not found.missing:
                return found
    elif isinstance(value, list):
        for child in value[:200]:
            found = find_usage(child, depth + 1)
            if not found.missing:
                return found
    return NormalizedUsage()


def parse_json_bytes(body: bytes) -> Any:
    if not body or len(body) > MAX_INSPECT_BYTES:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def extract_error(body: bytes, status_code: int) -> tuple[str | None, str | None]:
    if 200 <= status_code < 300:
        return None, None
    parsed = parse_json_bytes(body[:MAX_ERROR_BYTES])
    error_type: Any = None
    message: Any = None
    if isinstance(parsed, Mapping):
        error = parsed.get("error")
        if isinstance(error, Mapping):
            error_type = first_present(error, ("type", "code"))
            message = first_present(error, ("message", "detail", "error"))
        else:
            error_type = first_present(parsed, ("type", "code", "error_type"))
            message = first_present(parsed, ("message", "detail", "error"))
    if message is None and body:
        message = body[:MAX_ERROR_BYTES].decode("utf-8", "replace")
    return redact_text(error_type, 120) or f"http_{status_code}", redact_text(message)


class SSEInspector:
    """Incrementally inspect SSE data without delaying or rewriting the stream."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._data_lines: list[bytes] = []
        self._event_size = 0
        self.usage = NormalizedUsage()
        self.model: str | None = None

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                if len(self._buffer) > MAX_SSE_EVENT_BYTES:
                    self._buffer.clear()
                    self._data_lines.clear()
                    self._event_size = 0
                return
            line = bytes(self._buffer[:newline]).rstrip(b"\r")
            del self._buffer[: newline + 1]
            self._consume_line(line)

    def finish(self) -> None:
        if self._buffer:
            self._consume_line(bytes(self._buffer).rstrip(b"\r"))
            self._buffer.clear()
        self._dispatch()

    def _consume_line(self, line: bytes) -> None:
        if not line:
            self._dispatch()
            return
        if line.startswith(b"data:"):
            payload = line[5:]
            if payload.startswith(b" "):
                payload = payload[1:]
            self._event_size += len(payload)
            if self._event_size <= MAX_SSE_EVENT_BYTES:
                self._data_lines.append(payload)

    def _dispatch(self) -> None:
        if not self._data_lines:
            self._event_size = 0
            return
        data = b"\n".join(self._data_lines)
        self._data_lines.clear()
        self._event_size = 0
        if data.strip() == b"[DONE]":
            return
        parsed = parse_json_bytes(data)
        if parsed is None:
            return
        usage = find_usage(parsed)
        if not usage.missing:
            self.usage = usage
        self.model = find_model(parsed) or self.model


@dataclass(frozen=True)
class AccountIdentity:
    usage_alias: str | None
    account_id_hash: str | None
    account_id_tail: str | None
    # Read from the local Codex auth identity only for loopback dashboard
    # display.  Email is deliberately never copied into SQLite usage/quota
    # rows, logs, queue payloads or health responses.
    account_email: str | None = None


class AccountResolver:
    """Best-effort, read-only mapping from local Codex homes to safe identities."""

    def __init__(self, home: Path | None = None, enabled: bool = True, refresh_seconds: float = 60.0):
        self.home = home or Path.home()
        self.enabled = enabled
        self.refresh_seconds = refresh_seconds
        # ``0.0`` is a valid monotonic timestamp on fresh processes.  Use a
        # negative sentinel so the first resolve always performs a scan.
        self._last_refresh = -float("inf")
        self._lock = threading.Lock()
        self._aliases: dict[str, AccountIdentity] = {}
        self._tokens: dict[str, AccountIdentity] = {}
        self._auth_indexes: dict[str, AccountIdentity] = {}
        self._accounts: dict[str, AccountIdentity] = {}

    def resolve(self, usage_alias: str | None, auth_fingerprint: str | None) -> AccountIdentity:
        self._refresh_if_needed()
        if usage_alias and usage_alias in self._aliases:
            return self._aliases[usage_alias]
        if auth_fingerprint and auth_fingerprint in self._tokens:
            matched = self._tokens[auth_fingerprint]
            # ``auth:<fingerprint>`` is emitted as a temporary fallback when
            # the queue wins a refresh/write race.  Prefer the now-known
            # local alias so new events do not create a second account card.
            resolved_alias = (
                matched.usage_alias
                if not usage_alias or is_auth_fallback_alias(usage_alias)
                else usage_alias
            )
            return AccountIdentity(
                resolved_alias,
                matched.account_id_hash,
                matched.account_id_tail,
                matched.account_email,
            )
        return AccountIdentity(usage_alias, None, None)

    def resolve_queue(
        self,
        auth_index: str | None,
        access_token_sha256: str | None,
        model_alias: str | None = None,
    ) -> AccountIdentity:
        """Resolve a CLIProxyAPI usage-queue item without retaining its API key.

        CLIProxyAPI publishes the full SHA-256 digest in ``access_token_sha256``
        and an auth-file name in ``auth_index``.  The normal sidecar resolver
        intentionally stores only a 16-character digest prefix, so this method
        compares prefixes and never treats the queue's ``api_key`` field as an
        identity source.
        """

        self._refresh_if_needed()
        safe_index = safe_text(auth_index, 512)
        if safe_index:
            identity = self._auth_indexes.get(Path(safe_index).name)
            if identity is not None:
                return identity
        digest = safe_text(access_token_sha256, 128)
        if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            identity = self._tokens.get(digest[:16].lower())
            if identity is not None:
                return identity
        # The model alias is useful as a last-resort display label, but it is
        # deliberately not used as an account identity when no auth mapping is
        # available.
        return AccountIdentity(None, None, None)

    def resolve_account_id(self, account_id: str | None) -> AccountIdentity:
        account = safe_text(account_id, 256)
        if not account:
            return AccountIdentity(None, None, None)
        self._refresh_if_needed()
        identity = self._accounts.get(account)
        return identity if identity is not None else self._identity(None, account)

    def resolve_account_hash(self, account_id_hash: str | None) -> AccountIdentity:
        """Resolve a previously stored short account hash to a local alias."""

        target = safe_text(account_id_hash, 64)
        if not target:
            return AccountIdentity(None, None, None)
        self._refresh_if_needed()
        for identity in self._accounts.values():
            if identity.account_id_hash == target:
                return identity
        return AccountIdentity(None, None, None)

    def _refresh_if_needed(self) -> None:
        if not self.enabled or time.monotonic() - self._last_refresh < self.refresh_seconds:
            return
        with self._lock:
            if time.monotonic() - self._last_refresh < self.refresh_seconds:
                return
            aliases, tokens, auth_indexes, accounts = self._scan()
            self._aliases = aliases
            self._tokens = tokens
            self._auth_indexes = auth_indexes
            self._accounts = accounts
            self._last_refresh = time.monotonic()

    def _scan(
        self,
    ) -> tuple[
        dict[str, AccountIdentity],
        dict[str, AccountIdentity],
        dict[str, AccountIdentity],
        dict[str, AccountIdentity],
    ]:
        aliases: dict[str, AccountIdentity] = {}
        tokens: dict[str, AccountIdentity] = {}
        auth_indexes: dict[str, AccountIdentity] = {}
        accounts: dict[str, AccountIdentity] = {}
        zshrc = self.home / ".zshrc"
        alias_homes: dict[str, Path] = {}
        try:
            text = zshrc.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        pattern = re.compile(
            r"^alias\s+(codex-\d+)=.*?(?:CODEX_HOME=)?[\\\"]?\$HOME/([^\"' ;]+)", re.MULTILINE
        )
        for match in pattern.finditer(text):
            alias_homes[match.group(1)] = self.home / match.group(2)

        account_to_alias: dict[str, str] = {}
        for alias, codex_home in alias_homes.items():
            data = self._read_json(codex_home / "auth.json")
            account_id, access_tokens, account_email = self._account_and_tokens(data)
            if not account_id:
                continue
            identity = self._identity(alias, account_id, account_email)
            aliases[alias] = identity
            account_to_alias[account_id] = alias
            accounts[account_id] = identity
            for token in access_tokens:
                fingerprint = short_hash(token)
                if fingerprint:
                    tokens[fingerprint] = identity

        proxy_dir = self.home / ".cli-proxy-api"
        try:
            # CLIProxyAPI accepts Codex auth files with user-defined names.
            # Team/workspace exports in particular do not necessarily use the
            # historical ``codex-*.json`` convention, so inspect every JSON
            # file and then filter by its provider metadata.  Keep the legacy
            # filename fallback for older records that predate ``type``.
            proxy_files = list(proxy_dir.glob("*.json"))
        except OSError:
            proxy_files = []
        for path in proxy_files:
            data = self._read_json(path)
            provider = (
                safe_text(data.get("provider") or data.get("type"), 64)
                if isinstance(data, Mapping)
                else None
            )
            if (provider or "").lower() != "codex" and not path.name.startswith("codex-"):
                continue
            account_id, access_tokens, account_email = self._account_and_tokens(data)
            if not account_id:
                continue
            alias = account_to_alias.get(account_id)
            known = accounts.get(account_id)
            identity = self._identity(
                alias,
                account_id,
                account_email or (known.account_email if known else None),
            )
            accounts[account_id] = identity
            auth_indexes[path.name] = identity
            for token in access_tokens:
                fingerprint = short_hash(token)
                if fingerprint:
                    tokens[fingerprint] = identity
        return aliases, tokens, auth_indexes, accounts

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    @staticmethod
    def _account_and_tokens(data: Any) -> tuple[str | None, list[str], str | None]:
        if not isinstance(data, Mapping):
            return None, [], None
        nested = data.get("tokens") if isinstance(data.get("tokens"), Mapping) else {}
        account_id = safe_text(first_present(nested, ("account_id",)) or data.get("account_id"), 256)
        raw_tokens = [nested.get("access_token"), data.get("access_token")]
        claims = _decode_jwt_claims_unverified(
            nested.get("id_token") or data.get("id_token")
        )
        auth_claims = claims.get("https://api.openai.com/auth")
        auth_claims = auth_claims if isinstance(auth_claims, Mapping) else {}
        profile_claims = claims.get("https://api.openai.com/profile")
        profile_claims = profile_claims if isinstance(profile_claims, Mapping) else {}
        account_email = safe_email(
            data.get("email")
            or nested.get("email")
            or claims.get("email")
            or auth_claims.get("email")
            or profile_claims.get("email")
        )
        return (
            account_id,
            [token for token in raw_tokens if isinstance(token, str) and token],
            account_email,
        )

    @staticmethod
    def _identity(
        alias: str | None,
        account_id: str,
        account_email: str | None = None,
    ) -> AccountIdentity:
        return AccountIdentity(
            alias,
            short_hash(account_id),
            account_id[-8:] if account_id else None,
            safe_email(account_email),
        )


def identity_key(
    account_id_hash: str | None,
    usage_alias: str | None,
    auth_fingerprint: str | None,
    installation_id: str | None,
    session_id: str | None,
) -> str:
    if account_id_hash:
        return f"account:{account_id_hash}"
    if usage_alias:
        return f"alias:{usage_alias}"
    if auth_fingerprint:
        return f"auth:{auth_fingerprint}"
    if installation_id:
        return f"installation:{short_hash(installation_id)}"
    if session_id:
        return f"session:{short_hash(session_id)}"
    return "unknown"


@dataclass
class RequestInfo:
    endpoint: str
    method: str
    model: str | None
    stream: int
    session_id: str | None
    thread_id: str | None
    turn_id: str | None
    installation_id: str | None
    window_id: str | None
    usage_alias: str | None
    usage_project: str | None
    auth_fingerprint: str | None
    account_id_hash: str | None
    account_id_tail: str | None
    identity_key: str


def request_info(
    endpoint: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes,
    resolver: AccountResolver,
) -> RequestInfo:
    parsed = parse_json_bytes(body)
    payload = parsed if isinstance(parsed, Mapping) else {}
    metadata = find_named_mapping(payload, "client_metadata") or {}
    usage_alias = safe_alias(headers.get("X-Usage-Alias"))
    session_id = safe_text(
        first_present(metadata, ("session_id", "sessionId")) or headers.get("X-Usage-Session"), 256
    )
    thread_id = safe_text(first_present(metadata, ("thread_id", "threadId")), 256)
    turn_id = safe_text(first_present(metadata, ("turn_id", "turnId")), 256)
    installation_id = safe_text(
        first_present(metadata, ("x-codex-installation-id", "installation_id", "installationId"))
        or headers.get("X-Codex-Installation-Id"),
        256,
    )
    window_id = safe_text(
        first_present(metadata, ("x-codex-window-id", "window_id", "windowId"))
        or headers.get("X-Codex-Window-Id"),
        256,
    )
    model = safe_text(payload.get("model"), 200)
    stream_value = payload.get("stream")
    stream = int(stream_value is True or str(stream_value).lower() in {"1", "true", "yes"})
    usage_project = redact_text(headers.get("X-Usage-Project"), 256)

    authorization = headers.get("Authorization", "")
    token: str | None = None
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif headers.get("X-Api-Key"):
        token = headers.get("X-Api-Key")
    auth_fingerprint = short_hash(token)
    identity = resolver.resolve(usage_alias, auth_fingerprint)
    resolved_alias = usage_alias or identity.usage_alias
    key = identity_key(
        identity.account_id_hash, resolved_alias, auth_fingerprint, installation_id, session_id
    )
    return RequestInfo(
        endpoint=endpoint,
        method=method,
        model=model,
        stream=stream,
        session_id=session_id,
        thread_id=thread_id,
        turn_id=turn_id,
        installation_id=installation_id,
        window_id=window_id,
        usage_alias=resolved_alias,
        usage_project=usage_project,
        auth_fingerprint=auth_fingerprint,
        account_id_hash=identity.account_id_hash,
        account_id_tail=identity.account_id_tail,
        identity_key=key,
    )


@dataclass
class UsageEvent:
    ts: str
    identity_key: str
    endpoint: str
    method: str
    model: str | None
    status_code: int
    ok: int
    duration_ms: int
    stream: int
    session_id: str | None
    thread_id: str | None
    turn_id: str | None
    installation_id: str | None
    window_id: str | None
    usage_alias: str | None
    usage_project: str | None
    auth_fingerprint: str | None
    account_id_hash: str | None
    account_id_tail: str | None
    input_tokens: int | None
    output_tokens: int | None
    cached_tokens: int | None
    cache_write_tokens: int | None
    reasoning_tokens: int | None
    total_tokens: int | None
    estimated_api_cost_usd: float | None
    non_cached_input_cost_usd: float | None
    cached_input_cost_usd: float | None
    output_cost_usd: float | None
    long_context_pricing_applied: int
    subscription_amortized_cost_usd: float | None
    api_equivalent_quota_usd: float | None
    usage_missing: int
    error_type: str | None
    error_message_redacted: str | None
    request_bytes: int
    response_bytes: int
    call_count: int = 1
    source: str = "sidecar"
    request_id: str | None = None


def _decode_jwt_claims_unverified(value: Any) -> Mapping[str, Any]:
    """Read non-secret identity metadata from a local JWT without verifying it.

    The token itself is never returned, logged or persisted.  This is suitable
    only for matching two already-local Codex homes; it is not authentication.
    """

    if not isinstance(value, str) or value.count(".") < 2:
        return {}
    try:
        encoded = value.split(".", 2)[1]
        encoded += "=" * (-len(encoded) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")))
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def period_start(period: str, now: datetime | None = None) -> str:
    local_now = now or datetime.now().astimezone()
    if local_now.tzinfo is None:
        local_now = local_now.replace(tzinfo=timezone.utc)
    if str(period).strip().lower() in ALL_TIME_PERIODS:
        # SQLite stores UTC timestamps in lexicographically sortable ISO form.
        # A year-0001 sentinel gives an explicit, portable all-time query while
        # keeping the existing SQL shape and indexes intact.
        return PERIOD_START_SENTINEL
    if period == "today":
        start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        match = re.fullmatch(r"([1-9]\d*)d", period)
        if not match:
            raise ValueError("period must be 'today', 'all', or Nd, for example 7d")
        start = local_now - timedelta(days=int(match.group(1)))
    return start.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class UsageRepository:
    def __init__(self, path: Path | str):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS usage_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts TEXT NOT NULL,
                  identity_key TEXT,
                  endpoint TEXT,
                  method TEXT,
                  model TEXT,
                  status_code INTEGER,
                  ok INTEGER,
                  duration_ms INTEGER,
                  stream INTEGER,
                  session_id TEXT,
                  thread_id TEXT,
                  turn_id TEXT,
                  installation_id TEXT,
                  window_id TEXT,
                  usage_alias TEXT,
                  usage_project TEXT,
                  auth_fingerprint TEXT,
                  account_id_hash TEXT,
                  account_id_tail TEXT,
                  input_tokens INTEGER,
                  output_tokens INTEGER,
                  cached_tokens INTEGER,
                  cache_write_tokens INTEGER,
                  reasoning_tokens INTEGER,
                  total_tokens INTEGER,
                  estimated_api_cost_usd REAL,
                  non_cached_input_cost_usd REAL,
                  cached_input_cost_usd REAL,
                  output_cost_usd REAL,
                  long_context_pricing_applied INTEGER DEFAULT 0,
                  subscription_amortized_cost_usd REAL,
                  api_equivalent_quota_usd REAL,
                  usage_missing INTEGER,
                  error_type TEXT,
                  error_message_redacted TEXT,
                  request_bytes INTEGER,
                  response_bytes INTEGER,
                  call_count INTEGER DEFAULT 1,
                  source TEXT DEFAULT 'sidecar',
                  request_id TEXT
                );

                CREATE TABLE IF NOT EXISTS model_prices (
                  model_pattern TEXT PRIMARY KEY,
                  input_per_million REAL,
                  output_per_million REAL,
                  cached_input_per_million REAL,
                  cache_write_per_million REAL,
                  long_context_threshold_tokens INTEGER,
                  long_input_per_million REAL,
                  long_cached_input_per_million REAL,
                  long_cache_write_per_million REAL,
                  long_output_per_million REAL,
                  reasoning_per_million REAL,
                  currency TEXT,
                  source_note TEXT,
                  source_kind TEXT DEFAULT 'manual',
                  updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS price_sync_metadata (
                  id INTEGER PRIMARY KEY CHECK (id = 1),
                  source_url TEXT,
                  fetched_at TEXT,
                  content_sha256 TEXT,
                  parser_version TEXT,
                  status TEXT,
                  model_count INTEGER,
                  repriced_events INTEGER DEFAULT 0,
                  error_type TEXT,
                  error_message_redacted TEXT,
                  updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS quota_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts TEXT NOT NULL,
                  identity_key TEXT,
                  account_id_hash TEXT,
                  account_id_tail TEXT,
                  usage_alias TEXT,
                  event_type TEXT,
                  source TEXT,
                  raw_message_redacted TEXT
                );

                CREATE TABLE IF NOT EXISTS account_quota_cycles (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  identity_key TEXT,
                  account_id_hash TEXT,
                  account_id_tail TEXT,
                  usage_alias TEXT,
                  cycle_start_ts TEXT,
                  cycle_end_ts TEXT,
                  reset_detected_by TEXT,
                  quota_hit_detected_by TEXT,
                  total_calls INTEGER,
                  successful_calls INTEGER,
                  failed_calls INTEGER,
                  streaming_calls INTEGER,
                  total_input_tokens INTEGER,
                  total_cached_tokens INTEGER,
                  total_output_tokens INTEGER,
                  total_reasoning_tokens INTEGER,
                  total_tokens INTEGER,
                  estimated_api_cost_usd REAL,
                  observed_floor_usd REAL,
                  api_equivalent_quota_usd REAL,
                  is_complete_cycle INTEGER,
                  notes TEXT
                );

                CREATE TABLE IF NOT EXISTS subscription_quota_snapshots (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fetched_at TEXT NOT NULL,
                  identity_key TEXT NOT NULL,
                  account_id_hash TEXT,
                  account_id_tail TEXT,
                  usage_alias TEXT,
                  plan_type TEXT,
                  subscription_active_until TEXT,
                  window_kind TEXT NOT NULL,
                  used_percent REAL,
                  remaining_percent REAL,
                  window_seconds INTEGER,
                  reset_at TEXT,
                  estimated_full_quota_usd REAL,
                  estimated_remaining_quota_usd REAL,
                  estimate_method TEXT,
                  source TEXT NOT NULL,
                  UNIQUE(identity_key, window_kind, fetched_at)
                );

                CREATE TABLE IF NOT EXISTS local_import_records (
                  import_key TEXT PRIMARY KEY,
                  source TEXT NOT NULL,
                  usage_event_id INTEGER,
                  imported_at TEXT NOT NULL,
                  FOREIGN KEY(usage_event_id) REFERENCES usage_events(id)
                );

                CREATE TABLE IF NOT EXISTS local_import_files (
                  path TEXT PRIMARY KEY,
                  size INTEGER NOT NULL DEFAULT 0,
                  mtime_ns INTEGER NOT NULL DEFAULT 0,
                  offset INTEGER NOT NULL DEFAULT 0,
                  session_id TEXT,
                  model_provider TEXT,
                  model TEXT,
                  turn_id TEXT,
                  updated_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(conn, "usage_events", "identity_key", "TEXT")
            self._ensure_column(conn, "usage_events", "source", "TEXT DEFAULT 'sidecar'")
            self._ensure_column(conn, "usage_events", "request_id", "TEXT")
            self._ensure_column(conn, "usage_events", "non_cached_input_cost_usd", "REAL")
            self._ensure_column(conn, "usage_events", "cached_input_cost_usd", "REAL")
            self._ensure_column(conn, "usage_events", "output_cost_usd", "REAL")
            self._ensure_column(conn, "usage_events", "cache_write_tokens", "INTEGER")
            self._ensure_column(
                conn,
                "usage_events",
                "long_context_pricing_applied",
                "INTEGER DEFAULT 0",
            )
            self._ensure_column(conn, "model_prices", "source_kind", "TEXT DEFAULT 'manual'")
            self._ensure_column(conn, "model_prices", "long_context_threshold_tokens", "INTEGER")
            self._ensure_column(conn, "model_prices", "cache_write_per_million", "REAL")
            self._ensure_column(conn, "model_prices", "long_input_per_million", "REAL")
            self._ensure_column(conn, "model_prices", "long_cached_input_per_million", "REAL")
            self._ensure_column(conn, "model_prices", "long_cache_write_per_million", "REAL")
            self._ensure_column(conn, "model_prices", "long_output_per_million", "REAL")
            self._ensure_column(conn, "price_sync_metadata", "repriced_events", "INTEGER DEFAULT 0")
            self._ensure_column(conn, "quota_events", "identity_key", "TEXT")
            self._ensure_column(conn, "account_quota_cycles", "identity_key", "TEXT")
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_usage_events_ts ON usage_events(ts);
                CREATE INDEX IF NOT EXISTS idx_usage_events_identity_ts ON usage_events(identity_key, ts);
                CREATE INDEX IF NOT EXISTS idx_usage_events_alias_ts ON usage_events(usage_alias, ts);
                CREATE INDEX IF NOT EXISTS idx_usage_events_model_ts ON usage_events(model, ts);
                CREATE INDEX IF NOT EXISTS idx_quota_events_identity_ts ON quota_events(identity_key, ts);
                CREATE INDEX IF NOT EXISTS idx_quota_cycles_identity_end ON account_quota_cycles(identity_key, cycle_end_ts);
                CREATE INDEX IF NOT EXISTS idx_subscription_quota_identity_kind_ts
                  ON subscription_quota_snapshots(identity_key, window_kind, fetched_at DESC);
                CREATE INDEX IF NOT EXISTS idx_local_import_records_source
                  ON local_import_records(source, imported_at DESC);
                CREATE INDEX IF NOT EXISTS idx_local_import_files_updated
                  ON local_import_files(updated_at DESC);
                """
            )
            self._backfill_frozen_cost_components(conn)
            self._upgrade_long_context_costs(conn)

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    @staticmethod
    def _matched_price(model: str | None, rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
        if not model:
            return None
        matches = [row for row in rows if fnmatch.fnmatchcase(model, row["model_pattern"])]
        if not matches:
            return None
        matches.sort(key=lambda row: (row["model_pattern"] == model, len(row["model_pattern"])), reverse=True)
        return matches[0]

    @staticmethod
    def _components_for_price(
        usage: NormalizedUsage,
        price: Mapping[str, Any] | None,
    ) -> PriceComponents | None:
        if price is None or usage.missing:
            return None
        # A total-only usage object cannot be priced without inventing an
        # input/output split; keep every cost field NULL instead of returning 0.
        if usage.input_tokens is None or usage.output_tokens is None:
            return None
        price = dict(price)
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        cached_tokens = usage.cached_tokens or 0
        cache_write_tokens = usage.cache_write_tokens or 0
        ordinary_input_tokens = max(input_tokens - cached_tokens - cache_write_tokens, 0)
        long_context = False
        threshold = as_nonnegative_int(price.get("long_context_threshold_tokens"))
        if threshold is not None and input_tokens > threshold:
            long_rates = (
                price.get("long_input_per_million"),
                price.get("long_cached_input_per_million"),
                price.get("long_cache_write_per_million"),
                price.get("long_output_per_million"),
            )
            # A partially documented long-context tier is not safe to infer.
            # Use it only when every token category needed by this event has a
            # corresponding official rate; otherwise leave the event unpriced.
            if (
                (ordinary_input_tokens > 0 and long_rates[0] is None)
                or (cached_tokens > 0 and long_rates[1] is None)
                or (cache_write_tokens > 0 and long_rates[2] is None)
                or (output_tokens > 0 and long_rates[3] is None)
            ):
                return None
            raw_rates = long_rates
            long_context = True
        else:
            raw_rates = (
                price["input_per_million"],
                price["cached_input_per_million"],
                price.get("cache_write_per_million"),
                price["output_per_million"],
            )
        rates: list[float | None] = []
        for raw in raw_rates:
            if raw is None:
                rates.append(None)
                continue
            try:
                rate = float(raw)
            except (TypeError, ValueError, OverflowError):
                return None
            if not math.isfinite(rate) or rate < 0:
                return None
            rates.append(rate)
        input_rate, cached_rate, cache_write_rate, output_rate = rates
        if ordinary_input_tokens and input_rate is None:
            return None
        if cached_tokens and cached_rate is None:
            return None
        if cache_write_tokens and cache_write_rate is None:
            return None
        if output_tokens and output_rate is None:
            return None
        return PriceComponents(
            non_cached_input_cost_usd=(
                (
                    ordinary_input_tokens * float(input_rate or 0.0)
                    + cache_write_tokens * float(cache_write_rate or 0.0)
                )
                / 1_000_000
            ),
            cached_input_cost_usd=(
                cached_tokens * float(cached_rate or 0.0) / 1_000_000
            ),
            output_cost_usd=output_tokens * float(output_rate or 0.0) / 1_000_000,
            long_context_pricing_applied=long_context,
        )

    def price_components_for(
        self,
        model: str | None,
        usage: NormalizedUsage,
    ) -> PriceComponents | None:
        if not model or usage.missing:
            return None
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM model_prices WHERE currency = 'USD' OR currency IS NULL"
            ).fetchall()
        price = self._matched_price(model, rows)
        return self._components_for_price(usage, price)

    def price_for(self, model: str | None, usage: NormalizedUsage) -> float | None:
        components = self.price_components_for(model, usage)
        return components.total_cost_usd if components is not None else None

    def _backfill_frozen_cost_components(self, conn: sqlite3.Connection) -> int:
        """Safely split legacy totals without changing their frozen value.

        A legacy row is filled only when all three new fields are NULL and the
        current component calculation agrees with its already-persisted total
        to sub-nanodollar precision. Price drift therefore leaves the row
        untouched instead of silently rewriting history.
        """

        prices = conn.execute(
            "SELECT * FROM model_prices WHERE currency = 'USD' OR currency IS NULL"
        ).fetchall()
        if not prices:
            return 0
        events = conn.execute(
            """
            SELECT id, model, input_tokens, cached_tokens, cache_write_tokens, output_tokens,
                   estimated_api_cost_usd
              FROM usage_events
             WHERE estimated_api_cost_usd IS NOT NULL
               AND input_tokens IS NOT NULL
               AND output_tokens IS NOT NULL
               AND non_cached_input_cost_usd IS NULL
               AND cached_input_cost_usd IS NULL
               AND output_cost_usd IS NULL
            """
        ).fetchall()
        filled = 0
        for event in events:
            usage = NormalizedUsage(
                input_tokens=as_nonnegative_int(event["input_tokens"]),
                output_tokens=as_nonnegative_int(event["output_tokens"]),
                cached_tokens=as_nonnegative_int(event["cached_tokens"]),
                cache_write_tokens=as_nonnegative_int(event["cache_write_tokens"]),
            )
            components = self._components_for_price(
                usage,
                self._matched_price(event["model"], prices),
            )
            if components is None:
                continue
            frozen_total = float(event["estimated_api_cost_usd"])
            if not math.isfinite(frozen_total) or not math.isclose(
                components.total_cost_usd,
                frozen_total,
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                continue
            cursor = conn.execute(
                """
                UPDATE usage_events
                   SET non_cached_input_cost_usd=?,
                       cached_input_cost_usd=?,
                       output_cost_usd=?
                 WHERE id=?
                   AND estimated_api_cost_usd=?
                   AND non_cached_input_cost_usd IS NULL
                   AND cached_input_cost_usd IS NULL
                   AND output_cost_usd IS NULL
                """,
                (
                    components.non_cached_input_cost_usd,
                    components.cached_input_cost_usd,
                    components.output_cost_usd,
                    event["id"],
                    event["estimated_api_cost_usd"],
                ),
            )
            filled += max(int(cursor.rowcount), 0)
        return filled

    def backfill_frozen_cost_components(self) -> int:
        """Public, idempotent entry point used by migration diagnostics."""

        with self.connect() as conn:
            return self._backfill_frozen_cost_components(conn)

    def _upgrade_long_context_costs(self, conn: sqlite3.Connection) -> int:
        """Upgrade frozen short-tier totals when the old total proves their origin.

        Older versions stored only short-context rates.  A row is rewritten
        only when all frozen components exactly match the current short tier
        and the model price now supplies a complete long tier.  This preserves
        manual/historical totals whose provenance cannot be established.
        """

        prices = conn.execute(
            """SELECT * FROM model_prices
                WHERE (currency='USD' OR currency IS NULL)
                  AND long_context_threshold_tokens IS NOT NULL"""
        ).fetchall()
        if not prices:
            return 0
        events = conn.execute(
            """
            SELECT id, model, input_tokens, cached_tokens, cache_write_tokens, output_tokens,
                   estimated_api_cost_usd, non_cached_input_cost_usd,
                   cached_input_cost_usd, output_cost_usd
              FROM usage_events
             WHERE COALESCE(long_context_pricing_applied, 0)=0
               AND input_tokens IS NOT NULL
               AND output_tokens IS NOT NULL
               AND estimated_api_cost_usd IS NOT NULL
               AND non_cached_input_cost_usd IS NOT NULL
               AND cached_input_cost_usd IS NOT NULL
               AND output_cost_usd IS NOT NULL
            """
        ).fetchall()
        updated = 0
        for event in events:
            price = self._matched_price(event["model"], prices)
            if price is None:
                continue
            threshold = as_nonnegative_int(price["long_context_threshold_tokens"])
            input_tokens = as_nonnegative_int(event["input_tokens"])
            if threshold is None or input_tokens is None or input_tokens <= threshold:
                continue
            usage = NormalizedUsage(
                input_tokens=input_tokens,
                output_tokens=as_nonnegative_int(event["output_tokens"]),
                cached_tokens=as_nonnegative_int(event["cached_tokens"]),
                cache_write_tokens=as_nonnegative_int(event["cache_write_tokens"]),
            )
            short_price = dict(price)
            short_price["long_context_threshold_tokens"] = None
            short_components = self._components_for_price(usage, short_price)
            long_components = self._components_for_price(usage, price)
            if short_components is None or long_components is None:
                continue
            frozen = (
                float(event["non_cached_input_cost_usd"]),
                float(event["cached_input_cost_usd"]),
                float(event["output_cost_usd"]),
                float(event["estimated_api_cost_usd"]),
            )
            expected_short = (
                short_components.non_cached_input_cost_usd,
                short_components.cached_input_cost_usd,
                short_components.output_cost_usd,
                short_components.total_cost_usd,
            )
            if not all(
                math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)
                for actual, expected in zip(frozen, expected_short)
            ):
                continue
            cursor = conn.execute(
                """
                UPDATE usage_events
                   SET non_cached_input_cost_usd=?, cached_input_cost_usd=?,
                       output_cost_usd=?, estimated_api_cost_usd=?,
                       long_context_pricing_applied=1
                 WHERE id=? AND COALESCE(long_context_pricing_applied, 0)=0
                """,
                (
                    long_components.non_cached_input_cost_usd,
                    long_components.cached_input_cost_usd,
                    long_components.output_cost_usd,
                    long_components.total_cost_usd,
                    event["id"],
                ),
            )
            updated += max(int(cursor.rowcount), 0)
        return updated

    def upgrade_long_context_costs(self) -> int:
        """Public, idempotent long-context pricing migration entry point."""

        with self.connect() as conn:
            return self._upgrade_long_context_costs(conn)

    def reconcile_auth_identities(self, resolver: AccountResolver) -> int:
        """Re-bind provisional queue identities after auth files become visible.

        CLIProxyAPI may publish a usage-queue item in the same moment that it
        refreshes an auth file.  If the resolver scans before that file is
        complete, the event is stored as ``alias:auth:<fingerprint>``.  That
        identity would otherwise remain a permanent, misleading ``UNKNOWN``
        dashboard card even after the file is available.  Reconciliation is
        deliberately narrow: it only considers rows carrying an auth
        fingerprint and only rewrites provisional/partially-resolved fields.
        Tokens themselves are never read from or written to SQLite.
        """

        if not resolver.enabled:
            return 0
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, identity_key, usage_alias, auth_fingerprint,
                       account_id_hash, account_id_tail
                 FROM usage_events
                 WHERE auth_fingerprint IS NOT NULL
                   AND (
                         usage_alias LIKE 'auth:%'
                         OR identity_key LIKE 'alias:auth:%'
                         OR account_id_hash IS NULL
                       )
                """
            ).fetchall()
            changed = 0
            related: dict[str, tuple[str, str | None, str | None, str | None]] = {}
            for row in rows:
                fingerprint = safe_text(row["auth_fingerprint"], 64)
                if not fingerprint:
                    continue
                current_alias = safe_text(row["usage_alias"], 128)
                identity_is_provisional = (
                    is_auth_fallback_alias(current_alias)
                    or str(row["identity_key"] or "").startswith("alias:auth:")
                    or row["account_id_hash"] is None
                )
                if not identity_is_provisional:
                    continue
                identity = resolver.resolve(None, fingerprint.lower()[:16])
                if not identity.account_id_hash and not identity.usage_alias:
                    identity = resolver.resolve_account_hash(row["account_id_hash"])
                if not identity.account_id_hash and not identity.usage_alias:
                    continue
                resolved_alias = identity.usage_alias
                resolved_key = identity_key(
                    identity.account_id_hash,
                    resolved_alias,
                    fingerprint.lower()[:16],
                    None,
                    None,
                )
                if (
                    row["identity_key"] == resolved_key
                    and row["usage_alias"] == resolved_alias
                    and row["account_id_hash"] == identity.account_id_hash
                    and row["account_id_tail"] == identity.account_id_tail
                ):
                    continue
                cursor = conn.execute(
                    """
                    UPDATE usage_events
                       SET identity_key=?, usage_alias=?, account_id_hash=?, account_id_tail=?
                     WHERE id=?
                    """,
                    (
                        resolved_key,
                        resolved_alias,
                        identity.account_id_hash,
                        identity.account_id_tail,
                        row["id"],
                    ),
                )
                changed += max(int(cursor.rowcount), 0)
                old_key = safe_text(row["identity_key"], 300)
                if old_key:
                    related[old_key] = (
                        resolved_key,
                        resolved_alias,
                        identity.account_id_hash,
                        identity.account_id_tail,
                    )

            # Keep quota markers/cycles aligned if a provisional identity had
            # already produced one.  ``UPDATE OR IGNORE`` avoids violating the
            # snapshot uniqueness constraint when a canonical row exists.
            for old_key, (new_key, alias, account_hash, account_tail) in related.items():
                for table in ("quota_events", "account_quota_cycles"):
                    conn.execute(
                        f"""
                        UPDATE {table}
                           SET identity_key=?, usage_alias=?, account_id_hash=?, account_id_tail=?
                         WHERE identity_key=?
                        """,
                        (new_key, alias, account_hash, account_tail, old_key),
                    )
                conn.execute(
                    """
                    UPDATE OR IGNORE subscription_quota_snapshots
                       SET identity_key=?, usage_alias=?, account_id_hash=?, account_id_tail=?
                     WHERE identity_key=?
                    """,
                    (new_key, alias, account_hash, account_tail, old_key),
                )

            # Quota markers can outlive the usage row that first created them.
            # Reconcile those rows independently as well, using the embedded
            # auth fallback label or their already persisted account hash.
            for table in ("quota_events", "account_quota_cycles", "subscription_quota_snapshots"):
                related_rows = conn.execute(
                    f"""
                    SELECT id, identity_key, usage_alias, account_id_hash, account_id_tail
                      FROM {table}
                     WHERE usage_alias LIKE 'auth:%'
                        OR identity_key LIKE 'alias:auth:%'
                        OR account_id_hash IS NULL
                    """
                ).fetchall()
                for row in related_rows:
                    alias_text = safe_text(row["usage_alias"], 128)
                    key_text = safe_text(row["identity_key"], 300) or ""
                    fingerprint = None
                    if is_auth_fallback_alias(alias_text):
                        fingerprint = alias_text[5:]
                    else:
                        match = re.fullmatch(r"alias:(auth:[0-9a-f]{16})", key_text, re.IGNORECASE)
                        if match:
                            fingerprint = match.group(1)[5:]
                    identity = resolver.resolve(None, fingerprint.lower() if fingerprint else None)
                    if not identity.account_id_hash and not identity.usage_alias:
                        identity = resolver.resolve_account_hash(row["account_id_hash"])
                    if not identity.account_id_hash and not identity.usage_alias:
                        continue
                    resolved_alias = identity.usage_alias
                    resolved_key = identity_key(
                        identity.account_id_hash,
                        resolved_alias,
                        fingerprint.lower() if fingerprint else None,
                        None,
                        None,
                    )
                    if (
                        row["identity_key"] == resolved_key
                        and row["usage_alias"] == resolved_alias
                        and row["account_id_hash"] == identity.account_id_hash
                        and row["account_id_tail"] == identity.account_id_tail
                    ):
                        continue
                    conn.execute(
                        f"""
                        UPDATE OR IGNORE {table}
                           SET identity_key=?, usage_alias=?, account_id_hash=?, account_id_tail=?
                         WHERE id=?
                        """,
                        (
                            resolved_key,
                            resolved_alias,
                            identity.account_id_hash,
                            identity.account_id_tail,
                            row["id"],
                        ),
                    )
                    changed += 1
            return changed

    def set_price(
        self,
        pattern: str,
        input_rate: float,
        output_rate: float,
        cached_rate: float,
        source_note: str | None,
    ) -> None:
        if min(input_rate, output_rate, cached_rate) < 0:
            raise ValueError("prices must be non-negative")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO model_prices (
                  model_pattern, input_per_million, output_per_million,
                  cached_input_per_million, cache_write_per_million,
                  long_context_threshold_tokens,
                  long_input_per_million, long_cached_input_per_million,
                  long_cache_write_per_million, long_output_per_million,
                  reasoning_per_million, currency,
                  source_note, source_kind, updated_at
                ) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'USD', ?, 'manual', ?)
                ON CONFLICT(model_pattern) DO UPDATE SET
                  input_per_million=excluded.input_per_million,
                  output_per_million=excluded.output_per_million,
                  cached_input_per_million=excluded.cached_input_per_million,
                  cache_write_per_million=NULL,
                  long_context_threshold_tokens=NULL,
                  long_input_per_million=NULL,
                  long_cached_input_per_million=NULL,
                  long_cache_write_per_million=NULL,
                  long_output_per_million=NULL,
                  currency='USD', source_note=excluded.source_note,
                  source_kind='manual',
                  updated_at=excluded.updated_at
                """,
                (pattern, input_rate, output_rate, cached_rate, redact_text(source_note, 500), utc_now()),
            )

    def list_prices(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM model_prices ORDER BY model_pattern")]

    def price_sync_status(self) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM price_sync_metadata WHERE id=1").fetchone()
        return dict(row) if row else {
            "id": 1,
            "source_url": None,
            "fetched_at": None,
            "content_sha256": None,
            "parser_version": OFFICIAL_PRICE_PARSER_VERSION,
            "status": "never_run",
            "model_count": 0,
            "repriced_events": 0,
            "error_type": None,
            "error_message_redacted": None,
            "updated_at": None,
        }

    def record_price_sync(
        self,
        *,
        source_url: str,
        fetched_at: str,
        content_sha256: str | None,
        parser_version: str,
        status: str,
        model_count: int,
        repriced_events: int = 0,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO price_sync_metadata (
                  id, source_url, fetched_at, content_sha256, parser_version,
                  status, model_count, repriced_events, error_type,
                  error_message_redacted, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  source_url=excluded.source_url,
                  fetched_at=excluded.fetched_at,
                  content_sha256=excluded.content_sha256,
                  parser_version=excluded.parser_version,
                  status=excluded.status,
                  model_count=excluded.model_count,
                  repriced_events=excluded.repriced_events,
                  error_type=excluded.error_type,
                  error_message_redacted=excluded.error_message_redacted,
                  updated_at=excluded.updated_at
                """,
                (
                    source_url,
                    fetched_at,
                    content_sha256,
                    parser_version,
                    status,
                    max(int(model_count), 0),
                    max(int(repriced_events), 0),
                    safe_text(error_type, 120),
                    redact_text(error_message, 600),
                    utc_now(),
                ),
            )

    def replace_official_prices(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        source_url: str,
        fetched_at: str,
        content_sha256: str,
        parser_version: str,
    ) -> int:
        """Atomically replace only rows previously owned by the official sync."""

        if not rows:
            raise ValueError("official pricing parser returned no models")
        patterns = [safe_text(row.get("model_pattern"), 200) for row in rows]
        if any(not pattern for pattern in patterns):
            raise ValueError("official pricing parser returned an invalid model name")
        note = (
            f"official OpenAI pricing; URL={source_url}; fetched_at={fetched_at}; "
            f"sha256={content_sha256}; parser={parser_version}; standard short/long-context rates"
        )
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM model_prices WHERE source_kind='official'")
            repriced_events = 0
            for row in rows:
                conn.execute(
                    """
                    INSERT INTO model_prices (
                      model_pattern, input_per_million, output_per_million,
                      cached_input_per_million, cache_write_per_million,
                      long_context_threshold_tokens,
                      long_input_per_million, long_cached_input_per_million,
                      long_cache_write_per_million, long_output_per_million,
                      reasoning_per_million, currency,
                      source_note, source_kind, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'USD', ?, 'official', ?)
                    ON CONFLICT(model_pattern) DO UPDATE SET
                      input_per_million=excluded.input_per_million,
                      output_per_million=excluded.output_per_million,
                      cached_input_per_million=excluded.cached_input_per_million,
                      cache_write_per_million=excluded.cache_write_per_million,
                      long_context_threshold_tokens=excluded.long_context_threshold_tokens,
                      long_input_per_million=excluded.long_input_per_million,
                      long_cached_input_per_million=excluded.long_cached_input_per_million,
                      long_cache_write_per_million=excluded.long_cache_write_per_million,
                      long_output_per_million=excluded.long_output_per_million,
                      reasoning_per_million=NULL,
                      currency='USD', source_note=excluded.source_note,
                      source_kind='official', updated_at=excluded.updated_at
                    """,
                    (
                        row["model_pattern"],
                        row.get("input_per_million"),
                        row.get("output_per_million"),
                        row.get("cached_input_per_million"),
                        row.get("cache_write_per_million"),
                        row.get("long_context_threshold_tokens"),
                        row.get("long_input_per_million"),
                        row.get("long_cached_input_per_million"),
                        row.get("long_cache_write_per_million"),
                        row.get("long_output_per_million"),
                        note,
                        fetched_at,
                    ),
                )
                unpriced = conn.execute(
                    """
                    SELECT id, input_tokens, cached_tokens, cache_write_tokens, output_tokens
                      FROM usage_events
                     WHERE estimated_api_cost_usd IS NULL
                       AND non_cached_input_cost_usd IS NULL
                       AND cached_input_cost_usd IS NULL
                       AND output_cost_usd IS NULL
                       AND model=?
                       AND input_tokens IS NOT NULL
                       AND output_tokens IS NOT NULL
                    """,
                    (row["model_pattern"],),
                ).fetchall()
                for event in unpriced:
                    usage = NormalizedUsage(
                        input_tokens=as_nonnegative_int(event["input_tokens"]),
                        output_tokens=as_nonnegative_int(event["output_tokens"]),
                        cached_tokens=as_nonnegative_int(event["cached_tokens"]),
                        cache_write_tokens=as_nonnegative_int(event["cache_write_tokens"]),
                    )
                    components = self._components_for_price(usage, row)
                    if components is None:
                        continue
                    cursor = conn.execute(
                        """
                        UPDATE usage_events
                           SET non_cached_input_cost_usd=?, cached_input_cost_usd=?,
                               output_cost_usd=?, estimated_api_cost_usd=?,
                               long_context_pricing_applied=?
                         WHERE id=? AND estimated_api_cost_usd IS NULL
                        """,
                        (
                            components.non_cached_input_cost_usd,
                            components.cached_input_cost_usd,
                            components.output_cost_usd,
                            components.total_cost_usd,
                            int(components.long_context_pricing_applied),
                            event["id"],
                        ),
                    )
                    repriced_events += max(int(cursor.rowcount), 0)
            repriced_events += self._upgrade_long_context_costs(conn)
            conn.execute(
                """
                INSERT INTO price_sync_metadata (
                  id, source_url, fetched_at, content_sha256, parser_version,
                  status, model_count, repriced_events, error_type,
                  error_message_redacted, updated_at
                ) VALUES (1, ?, ?, ?, ?, 'ok', ?, ?, NULL, NULL, ?)
                ON CONFLICT(id) DO UPDATE SET
                  source_url=excluded.source_url,
                  fetched_at=excluded.fetched_at,
                  content_sha256=excluded.content_sha256,
                  parser_version=excluded.parser_version,
                  status='ok', model_count=excluded.model_count,
                  repriced_events=excluded.repriced_events,
                  error_type=NULL, error_message_redacted=NULL, updated_at=excluded.updated_at
                """,
                (
                    source_url,
                    fetched_at,
                    content_sha256,
                    parser_version,
                    len(rows),
                    repriced_events,
                    utc_now(),
                ),
            )
        return repriced_events

    def maybe_auto_reset(self, info: RequestInfo, ts: str) -> bool:
        with self.connect() as conn:
            last_quota = conn.execute(
                f"SELECT ts FROM quota_events WHERE identity_key=? AND event_type IN ({','.join('?' for _ in QUOTA_EVENT_TYPES)}) ORDER BY ts DESC, id DESC LIMIT 1",
                (info.identity_key, *sorted(QUOTA_EVENT_TYPES)),
            ).fetchone()
            if not last_quota:
                return False
            # A successful queue item is not proof that the subscription was
            # reset: CLIProxyAPI can succeed on another route while the
            # account's Codex weekly/monthly window is still exhausted.  The
            # read-only WHAM snapshot is stronger evidence.  Do not split a
            # cycle while the latest subscription window still reports 100%.
            snapshot = conn.execute(
                """
                SELECT used_percent, reset_at
                  FROM subscription_quota_snapshots
                 WHERE identity_key=?
                   AND window_kind IN ('weekly', 'monthly')
                 ORDER BY id DESC LIMIT 1
                """,
                (info.identity_key,),
            ).fetchone()
            if snapshot and snapshot["used_percent"] is not None:
                try:
                    reset_at = normalize_optional_timestamp(snapshot["reset_at"])
                    if float(snapshot["used_percent"]) >= QUOTA_ESTIMATE_CAP_CONFIDENCE_PERCENT and (
                        not reset_at or ts < reset_at
                    ):
                        return False
                except (TypeError, ValueError):
                    pass
            last_reset = conn.execute(
                f"SELECT ts FROM quota_events WHERE identity_key=? AND event_type IN ({','.join('?' for _ in RESET_EVENT_TYPES)}) ORDER BY ts DESC, id DESC LIMIT 1",
                (info.identity_key, *sorted(RESET_EVENT_TYPES)),
            ).fetchone()
            if last_reset and last_reset["ts"] >= last_quota["ts"]:
                return False
            conn.execute(
                """INSERT INTO quota_events
                (ts, identity_key, account_id_hash, account_id_tail, usage_alias,
                 event_type, source, raw_message_redacted)
                VALUES (?, ?, ?, ?, ?, 'reset_detected', 'success_after_quota', NULL)""",
                (ts, info.identity_key, info.account_id_hash, info.account_id_tail, info.usage_alias),
            )
            return True

    def insert_event(self, event: UsageEvent) -> int:
        component_values = (
            event.non_cached_input_cost_usd,
            event.cached_input_cost_usd,
            event.output_cost_usd,
        )
        populated_components = sum(value is not None for value in component_values)
        if populated_components not in {0, 3}:
            raise ValueError("event cost components must be all NULL or all populated")
        if populated_components == 3:
            if event.estimated_api_cost_usd is None:
                raise ValueError("event total cost is required with cost components")
            total = sum(float(value) for value in component_values if value is not None)
            if not math.isclose(
                total,
                float(event.estimated_api_cost_usd),
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                raise ValueError("event cost components do not equal total cost")
        values = asdict(event)
        columns = list(values)
        placeholders = ",".join("?" for _ in columns)
        with self.connect() as conn:
            cursor = conn.execute(
                f"INSERT INTO usage_events ({','.join(columns)}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )
            return int(cursor.lastrowid)

    def record_event(self, event: UsageEvent, info: RequestInfo, source: str | None = None) -> int:
        """Persist one event and derive quota transitions in one best-effort path."""

        if source:
            event.source = safe_text(source, 64) or "sidecar"
        if event.ok:
            self.maybe_auto_reset(info, event.ts)
        event_id = self.insert_event(event)
        # HTTP handlers can finish out of order.  A quota error may close a
        # cycle before an earlier-timestamped successful response has finished
        # its SQLite insert.  Reconcile any already-complete cycle after every
        # insert so the cycle cost is not permanently understated by that race.
        self._refresh_complete_cycles_for_event(event)
        quota_type = detect_quota_event(event.status_code, event.error_type, event.error_message_redacted)
        if quota_type:
            self.record_quota_hit(
                info,
                event.ts,
                quota_type,
                event.source,
                event.error_message_redacted,
                usage_event_id=event_id,
            )
            # A quota-hit handler can finish before an older successful
            # response is inserted. Refresh once more after the hit creates a
            # cycle so that out-of-order HTTP completions cannot undercount it.
            self._refresh_complete_cycles_for_event(event)
        return event_id

    def _refresh_complete_cycles_for_event(self, event: UsageEvent) -> None:
        with self.connect() as conn:
            cycles = conn.execute(
                """SELECT id, identity_key, cycle_start_ts, cycle_end_ts
                     FROM account_quota_cycles
                    WHERE identity_key=? AND is_complete_cycle=1""",
                (event.identity_key,),
            ).fetchall()
            for cycle in cycles:
                # A later reset starts a new cycle; otherwise a response that
                # completed out of order is still part of this already-closed
                # provider window and may extend its observed end timestamp.
                later_reset = conn.execute(
                    f"""SELECT 1 FROM quota_events
                         WHERE identity_key=? AND event_type IN ({','.join('?' for _ in RESET_EVENT_TYPES)})
                           AND ts>? LIMIT 1""",
                    (event.identity_key, *sorted(RESET_EVENT_TYPES), cycle["cycle_end_ts"]),
                ).fetchone()
                if later_reset:
                    continue
                end_ts = max(str(cycle["cycle_end_ts"]), str(event.ts))
                reset = conn.execute(
                    f"""SELECT ts FROM quota_events
                         WHERE identity_key=? AND event_type IN ({','.join('?' for _ in RESET_EVENT_TYPES)})
                           AND ts<=?
                         ORDER BY ts DESC, id DESC LIMIT 1""",
                    (event.identity_key, *sorted(RESET_EVENT_TYPES), end_ts),
                ).fetchone()
                boundary = reset["ts"] if reset else None
                if boundary is None:
                    first = conn.execute(
                        "SELECT MIN(ts) AS ts FROM usage_events WHERE identity_key=? AND ts<=?",
                        (event.identity_key, end_ts),
                    ).fetchone()
                else:
                    first = conn.execute(
                        """SELECT MIN(ts) AS ts FROM usage_events
                             WHERE identity_key=? AND ts>=? AND ts<=?""",
                        (event.identity_key, boundary, end_ts),
                    ).fetchone()
                start = first["ts"] if first and first["ts"] else cycle["cycle_start_ts"]
                totals = conn.execute(
                    """SELECT
                         COALESCE(SUM(call_count),0) total_calls,
                         COALESCE(SUM(CASE WHEN ok=1 THEN call_count ELSE 0 END),0) successful_calls,
                         COALESCE(SUM(CASE WHEN ok=0 THEN call_count ELSE 0 END),0) failed_calls,
                         COALESCE(SUM(CASE WHEN stream=1 THEN call_count ELSE 0 END),0) streaming_calls,
                         COALESCE(SUM(input_tokens),0) total_input_tokens,
                         COALESCE(SUM(cached_tokens),0) total_cached_tokens,
                         COALESCE(SUM(output_tokens),0) total_output_tokens,
                         COALESCE(SUM(reasoning_tokens),0) total_reasoning_tokens,
                         COALESCE(SUM(total_tokens),0) total_tokens,
                         SUM(estimated_api_cost_usd) estimated_api_cost_usd
                       FROM usage_events
                      WHERE identity_key=? AND ts>=? AND ts<=?""",
                    (event.identity_key, start, end_ts),
                ).fetchone()
                cost = totals["estimated_api_cost_usd"]
                conn.execute(
                    """UPDATE account_quota_cycles SET
                         cycle_start_ts=?, cycle_end_ts=?, total_calls=?, successful_calls=?, failed_calls=?,
                         streaming_calls=?, total_input_tokens=?, total_cached_tokens=?,
                         total_output_tokens=?, total_reasoning_tokens=?, total_tokens=?,
                         estimated_api_cost_usd=?, observed_floor_usd=?,
                         api_equivalent_quota_usd=? WHERE id=?""",
                    (
                        start,
                        end_ts,
                        totals["total_calls"],
                        totals["successful_calls"],
                        totals["failed_calls"],
                        totals["streaming_calls"],
                        totals["total_input_tokens"],
                        totals["total_cached_tokens"],
                        totals["total_output_tokens"],
                        totals["total_reasoning_tokens"],
                        totals["total_tokens"],
                        cost,
                        cost,
                        cost,
                        cycle["id"],
                    ),
                )

    def record_imported_event(
        self,
        event: UsageEvent,
        import_key: str,
        source: str,
    ) -> bool:
        """Insert one idempotent local/manual import in a single transaction."""

        safe_key = safe_text(import_key, 300)
        safe_source = safe_text(source, 64)
        if not safe_key or not safe_source:
            raise ValueError("invalid import identity")
        event.source = safe_source
        values = asdict(event)
        columns = list(values)
        placeholders = ",".join("?" for _ in columns)
        with self.connect() as conn:
            if conn.execute(
                "SELECT 1 FROM local_import_records WHERE import_key=?", (safe_key,)
            ).fetchone():
                return False
            cursor = conn.execute(
                f"INSERT INTO usage_events ({','.join(columns)}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )
            conn.execute(
                """INSERT INTO local_import_records
                   (import_key, source, usage_event_id, imported_at)
                   VALUES (?, ?, ?, ?)""",
                (safe_key, safe_source, int(cursor.lastrowid), utc_now()),
            )
        return True

    def import_status(self, source: str = "codex_app_local") -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS imported_events, MAX(imported_at) AS last_import_at
                     FROM local_import_records WHERE source=?""",
                (source,),
            ).fetchone()
        return dict(row)

    def local_import_file_state(self, path: Path | str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM local_import_files WHERE path=?", (str(path),)
            ).fetchone()
        return dict(row) if row is not None else None

    def save_local_import_file_state(self, state: Mapping[str, Any]) -> None:
        values = {
            "path": safe_text(state.get("path"), 4096),
            "size": as_nonnegative_int(state.get("size")) or 0,
            "mtime_ns": as_nonnegative_int(state.get("mtime_ns")) or 0,
            "offset": as_nonnegative_int(state.get("offset")) or 0,
            "session_id": safe_text(state.get("session_id"), 256),
            "model_provider": safe_text(state.get("model_provider"), 64),
            "model": safe_text(state.get("model"), 200),
            "turn_id": safe_text(state.get("turn_id"), 256),
            "updated_at": utc_now(),
        }
        if not values["path"]:
            raise ValueError("invalid local import path")
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO local_import_files
                   (path, size, mtime_ns, offset, session_id, model_provider,
                    model, turn_id, updated_at)
                   VALUES (:path, :size, :mtime_ns, :offset, :session_id,
                           :model_provider, :model, :turn_id, :updated_at)
                   ON CONFLICT(path) DO UPDATE SET
                     size=excluded.size, mtime_ns=excluded.mtime_ns,
                     offset=excluded.offset, session_id=excluded.session_id,
                     model_provider=excluded.model_provider, model=excluded.model,
                     turn_id=excluded.turn_id, updated_at=excluded.updated_at""",
                values,
            )

    def record_quota_hit(
        self,
        info: RequestInfo,
        ts: str,
        event_type: str,
        source: str,
        message: str | None,
        usage_event_id: int | None = None,
    ) -> None:
        with self.connect() as conn:
            last_reset = self._latest_event_ts(conn, info.identity_key, RESET_EVENT_TYPES)
            last_quota = self._latest_event_ts(conn, info.identity_key, QUOTA_EVENT_TYPES)
            first_for_cycle = not last_quota or (last_reset is not None and last_reset > last_quota)
            conn.execute(
                """INSERT INTO quota_events
                (ts, identity_key, account_id_hash, account_id_tail, usage_alias,
                 event_type, source, raw_message_redacted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts,
                    info.identity_key,
                    info.account_id_hash,
                    info.account_id_tail,
                    info.usage_alias,
                    event_type,
                    source,
                    redact_text(message),
                ),
            )
            if first_for_cycle:
                quota_value = self._close_cycle(
                    conn,
                    info.identity_key,
                    ts,
                    complete=True,
                    end_source=source,
                    info=info,
                )
                if usage_event_id is not None:
                    conn.execute(
                        "UPDATE usage_events SET api_equivalent_quota_usd=? WHERE id=?",
                        (quota_value, usage_event_id),
                    )

    def mark_reset(self, alias: str, resolver: AccountResolver) -> str:
        ts = utc_now()
        info = self._info_for_alias(alias, resolver)
        with self.connect() as conn:
            last_reset = self._latest_event_ts(conn, info.identity_key, RESET_EVENT_TYPES)
            last_quota = self._latest_event_ts(conn, info.identity_key, QUOTA_EVENT_TYPES)
            cycle_is_already_closed = bool(last_quota and (not last_reset or last_quota > last_reset))
            if not cycle_is_already_closed:
                self._close_cycle(conn, info.identity_key, ts, complete=False, end_source="manual", info=info)
            conn.execute(
                """INSERT INTO quota_events
                (ts, identity_key, account_id_hash, account_id_tail, usage_alias,
                 event_type, source, raw_message_redacted)
                VALUES (?, ?, ?, ?, ?, 'manual_reset', 'cli', NULL)""",
                (ts, info.identity_key, info.account_id_hash, info.account_id_tail, info.usage_alias),
            )
        return info.identity_key

    def mark_quota_hit(self, alias: str, resolver: AccountResolver) -> str:
        info = self._info_for_alias(alias, resolver)
        self.record_quota_hit(info, utc_now(), "manual_quota_hit", "cli", "manual quota-hit marker")
        return info.identity_key

    def _info_for_alias(self, alias: str, resolver: AccountResolver) -> RequestInfo:
        alias = safe_alias(alias)
        if not alias:
            raise ValueError("alias is empty")
        identity = resolver.resolve(alias, None)
        key = identity_key(identity.account_id_hash, alias, None, None, None)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM usage_events WHERE usage_alias=? ORDER BY ts DESC, id DESC LIMIT 1", (alias,)
            ).fetchone()
        if row:
            key = row["identity_key"] or key
            account_hash = row["account_id_hash"] or identity.account_id_hash
            account_tail = row["account_id_tail"] or identity.account_id_tail
        else:
            account_hash = identity.account_id_hash
            account_tail = identity.account_id_tail
        return RequestInfo("manual", "CLI", None, 0, None, None, None, None, None, alias, None, None, account_hash, account_tail, key)

    @staticmethod
    def _latest_event_ts(conn: sqlite3.Connection, key: str, event_types: set[str]) -> str | None:
        row = conn.execute(
            f"SELECT ts FROM quota_events WHERE identity_key=? AND event_type IN ({','.join('?' for _ in event_types)}) ORDER BY ts DESC, id DESC LIMIT 1",
            (key, *sorted(event_types)),
        ).fetchone()
        return row["ts"] if row else None

    def _close_cycle(
        self,
        conn: sqlite3.Connection,
        key: str,
        end_ts: str,
        complete: bool,
        end_source: str,
        info: RequestInfo,
    ) -> float | None:
        start_ts = self._latest_event_ts(conn, key, RESET_EVENT_TYPES)
        if start_ts is None:
            row = conn.execute(
                "SELECT MIN(ts) AS first_ts FROM usage_events WHERE identity_key=? AND ok=1 AND ts<=?", (key, end_ts)
            ).fetchone()
            if not row or row["first_ts"] is None:
                row = conn.execute(
                    "SELECT MIN(ts) AS first_ts FROM usage_events WHERE identity_key=? AND ts<=?", (key, end_ts)
                ).fetchone()
            start_ts = row["first_ts"] if row else None
        if start_ts is None:
            start_ts = end_ts
        duplicate = conn.execute(
            """SELECT id FROM account_quota_cycles
               WHERE identity_key=? AND cycle_start_ts=? AND is_complete_cycle=? LIMIT 1""",
            (key, start_ts, int(complete)),
        ).fetchone()
        if duplicate:
            row = conn.execute(
                "SELECT api_equivalent_quota_usd FROM account_quota_cycles WHERE id=?", (duplicate["id"],)
            ).fetchone()
            return row["api_equivalent_quota_usd"] if row else None
        totals = conn.execute(
            """
            SELECT
              COALESCE(SUM(call_count), 0) total_calls,
              COALESCE(SUM(CASE WHEN ok=1 THEN call_count ELSE 0 END), 0) successful_calls,
              COALESCE(SUM(CASE WHEN ok=0 THEN call_count ELSE 0 END), 0) failed_calls,
              COALESCE(SUM(CASE WHEN stream=1 THEN call_count ELSE 0 END), 0) streaming_calls,
              COALESCE(SUM(input_tokens), 0) total_input_tokens,
              COALESCE(SUM(cached_tokens), 0) total_cached_tokens,
              COALESCE(SUM(output_tokens), 0) total_output_tokens,
              COALESCE(SUM(reasoning_tokens), 0) total_reasoning_tokens,
              COALESCE(SUM(total_tokens), 0) total_tokens,
              SUM(estimated_api_cost_usd) estimated_api_cost_usd
            FROM usage_events WHERE identity_key=? AND ts>=? AND ts<=?
            """,
            (key, start_ts, end_ts),
        ).fetchone()
        cost = totals["estimated_api_cost_usd"]
        reset_source_row = conn.execute(
            f"SELECT source FROM quota_events WHERE identity_key=? AND event_type IN ({','.join('?' for _ in RESET_EVENT_TYPES)}) AND ts=? ORDER BY id DESC LIMIT 1",
            (key, *sorted(RESET_EVENT_TYPES), start_ts),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO account_quota_cycles (
              identity_key, account_id_hash, account_id_tail, usage_alias,
              cycle_start_ts, cycle_end_ts, reset_detected_by,
              quota_hit_detected_by, total_calls, successful_calls, failed_calls,
              streaming_calls, total_input_tokens, total_cached_tokens,
              total_output_tokens, total_reasoning_tokens, total_tokens,
              estimated_api_cost_usd, observed_floor_usd,
              api_equivalent_quota_usd, is_complete_cycle, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                info.account_id_hash,
                info.account_id_tail,
                info.usage_alias,
                start_ts,
                end_ts,
                reset_source_row["source"] if reset_source_row else "first_observed_request",
                end_source if complete else None,
                totals["total_calls"],
                totals["successful_calls"],
                totals["failed_calls"],
                totals["streaming_calls"],
                totals["total_input_tokens"],
                totals["total_cached_tokens"],
                totals["total_output_tokens"],
                totals["total_reasoning_tokens"],
                totals["total_tokens"],
                cost,
                cost,
                cost if complete else None,
                int(complete),
                None if complete else "cycle ended by reset before a quota-hit was observed",
            ),
        )
        return cost if complete else None

    def summary(self, period: str) -> dict[str, Any]:
        start = period_start(period)
        with self.connect() as conn:
            row = conn.execute(
                """
                WITH filtered AS (
                  SELECT * FROM usage_events WHERE ts>=?
                ), identified_requests AS (
                  SELECT request_id,
                         MAX(CASE WHEN ok=1 THEN 1 ELSE 0 END) logical_ok,
                         MAX(CASE WHEN stream=1 THEN 1 ELSE 0 END) logical_stream
                    FROM filtered
                   WHERE request_id IS NOT NULL
                   GROUP BY request_id
                )
                SELECT
                  COALESCE(SUM(call_count), 0) calls,
                  COALESCE(SUM(call_count), 0) account_attempts,
                  COALESCE(SUM(CASE WHEN ok=1 THEN call_count ELSE 0 END), 0) successful_calls,
                  COALESCE(SUM(CASE WHEN ok=0 THEN call_count ELSE 0 END), 0) failed_calls,
                  COALESCE(SUM(CASE WHEN stream=1 THEN call_count ELSE 0 END), 0) streaming_calls,
                  (SELECT COUNT(*) FROM identified_requests)
                    + COALESCE(SUM(CASE WHEN request_id IS NULL THEN call_count ELSE 0 END), 0)
                    logical_requests,
                  COALESCE((SELECT SUM(logical_ok) FROM identified_requests), 0)
                    + COALESCE(SUM(CASE WHEN request_id IS NULL AND ok=1 THEN call_count ELSE 0 END), 0)
                    successful_logical_requests,
                  COALESCE((SELECT SUM(CASE WHEN logical_ok=0 THEN 1 ELSE 0 END)
                              FROM identified_requests), 0)
                    + COALESCE(SUM(CASE WHEN request_id IS NULL AND ok=0 THEN call_count ELSE 0 END), 0)
                    failed_logical_requests,
                  COALESCE((SELECT SUM(logical_stream) FROM identified_requests), 0)
                    + COALESCE(SUM(CASE WHEN request_id IS NULL AND stream=1 THEN call_count ELSE 0 END), 0)
                    streaming_logical_requests,
                  COALESCE(SUM(input_tokens), 0) input_tokens,
                  COALESCE(SUM(output_tokens), 0) output_tokens,
                  COALESCE(SUM(cached_tokens), 0) cached_tokens,
                  COALESCE(SUM(reasoning_tokens), 0) reasoning_tokens,
                  COALESCE(SUM(total_tokens), 0) total_tokens,
                  COALESCE(SUM(CASE WHEN long_context_pricing_applied=1 THEN call_count ELSE 0 END), 0)
                    long_context_priced_calls,
                  COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)), 0)
                    non_cached_input_tokens,
                  COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)
                               + COALESCE(output_tokens, 0)), 0)
                    codex_status_tokens,
                  COALESCE(SUM(COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)), 0)
                    api_processed_tokens,
                  SUM(estimated_api_cost_usd) estimated_api_cost_usd,
                  SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                 AND cached_input_cost_usd IS NOT NULL
                                 AND output_cost_usd IS NOT NULL
                           THEN non_cached_input_cost_usd END) non_cached_input_cost_usd,
                  SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                 AND cached_input_cost_usd IS NOT NULL
                                 AND output_cost_usd IS NOT NULL
                           THEN cached_input_cost_usd END) cached_input_cost_usd,
                  SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                 AND cached_input_cost_usd IS NOT NULL
                                 AND output_cost_usd IS NOT NULL
                           THEN output_cost_usd END) output_cost_usd,
                  COALESCE(SUM(CASE
                    WHEN non_cached_input_cost_usd IS NOT NULL
                     AND cached_input_cost_usd IS NOT NULL
                     AND output_cost_usd IS NOT NULL
                    THEN call_count ELSE 0 END), 0) split_priced_events,
                  COALESCE(SUM(CASE WHEN estimated_api_cost_usd IS NOT NULL THEN call_count ELSE 0 END), 0) priced_calls,
                  COALESCE(SUM(CASE WHEN usage_missing=1 THEN call_count ELSE 0 END), 0) usage_missing_calls
                FROM filtered
                """,
                (start,),
            ).fetchone()
        result = dict(row)
        split_values = (
            result.get("non_cached_input_cost_usd"),
            result.get("cached_input_cost_usd"),
            result.get("output_cost_usd"),
        )
        result["split_cost_total_usd"] = (
            sum(float(value) for value in split_values if value is not None)
            if int(result.get("split_priced_events") or 0) > 0
            else None
        )
        input_tokens = int(result["input_tokens"] or 0)
        cached_tokens = int(result["cached_tokens"] or 0)
        result["cache_hit_rate_percent"] = (
            cached_tokens / input_tokens * 100.0 if input_tokens else None
        )
        result["retry_attempts"] = max(
            int(result["account_attempts"] or 0) - int(result["logical_requests"] or 0), 0
        )
        with self.connect() as conn:
            quota_row = conn.execute(
                """SELECT SUM(api_equivalent_quota_usd) AS api_equivalent_quota_usd
                   FROM account_quota_cycles
                   WHERE is_complete_cycle=1 AND cycle_end_ts>=?""",
                (start,),
            ).fetchone()
            quota_value = quota_row["api_equivalent_quota_usd"]
            if quota_value is None:
                # ``usage_events`` is intentionally committed before quota
                # transition bookkeeping so a proxy response is never held
                # up by SQLite.  A reader can therefore briefly observe the
                # event row before ``account_quota_cycles`` is committed.
                # Use the just-observed quota error as a conservative,
                # race-safe fallback until the cycle row appears.
                pending = conn.execute(
                    """SELECT identity_key, MAX(ts) AS ts
                         FROM quota_events
                        WHERE ts>=? AND event_type IN ({})
                        GROUP BY identity_key""".format(
                            ",".join("?" for _ in QUOTA_EVENT_TYPES)
                        ),
                    (start, *sorted(QUOTA_EVENT_TYPES)),
                ).fetchall()
                if pending:
                    fallback = 0.0
                    found = False
                    for item in pending:
                        row_cost = conn.execute(
                            """SELECT SUM(estimated_api_cost_usd) AS cost
                                 FROM usage_events
                                WHERE identity_key=? AND ts>=? AND ts<=?""",
                            (item["identity_key"], start, item["ts"]),
                        ).fetchone()
                        if row_cost["cost"] is not None:
                            fallback += float(row_cost["cost"])
                            found = True
                    quota_value = fallback if found else None
            if quota_value is None:
                # The quota_events insert itself can trail the usage-event
                # commit on a concurrent request.  Infer only the narrow,
                # provider-visible quota shapes from the event row as a
                # read-time fallback; the durable cycle remains authoritative.
                pending_events = conn.execute(
                    """SELECT identity_key, MAX(ts) AS ts
                         FROM usage_events
                        WHERE ts>=? AND (
                              status_code=429 OR
                              lower(COALESCE(error_type,'')) LIKE '%quota%' OR
                              lower(COALESCE(error_message_redacted,'')) LIKE '%usage limit%' OR
                              lower(COALESCE(error_message_redacted,'')) LIKE '%rate limit%'
                        )
                        GROUP BY identity_key""",
                    (start,),
                ).fetchall()
                if pending_events:
                    fallback = 0.0
                    found = False
                    for item in pending_events:
                        row_cost = conn.execute(
                            """SELECT SUM(estimated_api_cost_usd) AS cost
                                 FROM usage_events
                                WHERE identity_key=? AND ts>=? AND ts<=?""",
                            (item["identity_key"], start, item["ts"]),
                        ).fetchone()
                        if row_cost["cost"] is not None:
                            fallback += float(row_cost["cost"])
                            found = True
                    quota_value = fallback if found else None
        result["api_equivalent_quota_usd"] = quota_value
        result["period"] = period
        result["since"] = None if str(period).strip().lower() in ALL_TIME_PERIODS else start
        return result

    def cost_breakdown(self, period: str) -> dict[str, Any]:
        """Return the immutable per-event cost split from one SQLite snapshot."""

        start = period_start(period)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                      AND cached_input_cost_usd IS NOT NULL
                                      AND output_cost_usd IS NOT NULL
                                THEN non_cached_input_cost_usd END) non_cached_input_cost_usd,
                       SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                      AND cached_input_cost_usd IS NOT NULL
                                      AND output_cost_usd IS NOT NULL
                                THEN cached_input_cost_usd END) cached_input_cost_usd,
                       SUM(CASE WHEN non_cached_input_cost_usd IS NOT NULL
                                      AND cached_input_cost_usd IS NOT NULL
                                      AND output_cost_usd IS NOT NULL
                                THEN output_cost_usd END) output_cost_usd,
                       COALESCE(SUM(CASE
                         WHEN non_cached_input_cost_usd IS NOT NULL
                          AND cached_input_cost_usd IS NOT NULL
                          AND output_cost_usd IS NOT NULL
                         THEN call_count ELSE 0 END), 0) split_priced_events
                  FROM usage_events
                 WHERE ts>=?
                """,
                (start,),
            ).fetchone()
        result = dict(row)
        components = (
            result.get("non_cached_input_cost_usd"),
            result.get("cached_input_cost_usd"),
            result.get("output_cost_usd"),
        )
        result["split_cost_total_usd"] = (
            sum(float(value) for value in components if value is not None)
            if int(result.get("split_priced_events") or 0) > 0
            else None
        )
        return result

    def coverage(self) -> dict[str, Any]:
        """Return the locally recorded time span without exposing any secrets."""

        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS event_rows,
                       COALESCE(SUM(call_count), 0) AS calls,
                       COALESCE(SUM(call_count), 0) AS account_attempts,
                       COUNT(DISTINCT request_id)
                         + COALESCE(SUM(CASE WHEN request_id IS NULL THEN call_count ELSE 0 END), 0)
                         AS logical_requests,
                       COALESCE(SUM(CASE WHEN session_id IS NOT NULL THEN call_count ELSE 0 END), 0)
                         AS session_identified_attempts,
                       COALESCE(SUM(CASE WHEN request_id IS NOT NULL THEN call_count ELSE 0 END), 0)
                         AS request_id_identified_attempts,
                       MIN(ts) AS first_event_ts,
                       MAX(ts) AS last_event_ts
                FROM usage_events
                """
            ).fetchone()
        return dict(row)

    def token_breakdown(self, period: str) -> dict[str, Any]:
        summary = self.summary(period)
        return {
            "period": period,
            "input_tokens": summary["input_tokens"],
            "cached_tokens": summary["cached_tokens"],
            "non_cached_input_tokens": summary["non_cached_input_tokens"],
            "output_tokens": summary["output_tokens"],
            "reasoning_tokens": summary["reasoning_tokens"],
            "total_tokens": summary["total_tokens"],
            "codex_status_tokens": summary["codex_status_tokens"],
            "api_processed_tokens": summary["api_processed_tokens"],
            "cache_hit_rate_percent": summary["cache_hit_rate_percent"],
            "estimated_api_cost_usd": summary["estimated_api_cost_usd"],
            "non_cached_input_cost_usd": summary["non_cached_input_cost_usd"],
            "cached_input_cost_usd": summary["cached_input_cost_usd"],
            "output_cost_usd": summary["output_cost_usd"],
            "split_cost_total_usd": summary["split_cost_total_usd"],
            "split_priced_events": summary["split_priced_events"],
            "calls": summary["calls"],
            "account_attempts": summary["account_attempts"],
            "logical_requests": summary["logical_requests"],
            "retry_attempts": summary["retry_attempts"],
            "successful_logical_requests": summary["successful_logical_requests"],
            "failed_logical_requests": summary["failed_logical_requests"],
            "streaming_logical_requests": summary["streaming_logical_requests"],
            "successful_attempts": summary["successful_calls"],
            "failed_attempts": summary["failed_calls"],
            "streaming_attempts": summary["streaming_calls"],
        }

    def daily_usage(self, days: int = 7) -> list[dict[str, Any]]:
        """Return a dense local-date series, including zero-usage days."""

        days = max(1, min(int(days), 366))
        end = datetime.now().astimezone().date()
        start = end - timedelta(days=days - 1)
        start_local = datetime.combine(start, datetime.min.time()).astimezone()
        start_utc = start_local.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT date(ts, 'localtime') AS date,
                       COALESCE(SUM(call_count), 0) AS calls,
                       COALESCE(SUM(call_count), 0) AS account_attempts,
                       COUNT(DISTINCT request_id)
                         + COALESCE(SUM(CASE WHEN request_id IS NULL THEN call_count ELSE 0 END), 0)
                         AS logical_requests,
                       COALESCE(SUM(total_tokens), 0) AS total_tokens,
                       COALESCE(SUM(input_tokens), 0) AS input_tokens,
                       COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
                       COALESCE(SUM(output_tokens), 0) AS output_tokens,
                       COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
                       COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)), 0)
                         AS non_cached_input_tokens,
                       COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)
                                    + COALESCE(output_tokens, 0)), 0)
                         AS codex_status_tokens,
                       COALESCE(SUM(COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)), 0)
                         AS api_processed_tokens,
                       SUM(estimated_api_cost_usd) AS estimated_api_cost_usd,
                       SUM(non_cached_input_cost_usd) AS non_cached_input_cost_usd,
                       SUM(cached_input_cost_usd) AS cached_input_cost_usd,
                       SUM(output_cost_usd) AS output_cost_usd
                  FROM usage_events
                 WHERE ts>=?
                 GROUP BY date(ts, 'localtime')
                """,
                (start_utc,),
            ).fetchall()
        by_date = {row["date"]: dict(row) for row in rows}
        result: list[dict[str, Any]] = []
        for offset in range(days):
            day = (start + timedelta(days=offset)).isoformat()
            result.append(
                by_date.get(
                    day,
                    {
                        "date": day,
                        "calls": 0,
                        "account_attempts": 0,
                        "logical_requests": 0,
                        "total_tokens": 0,
                        "input_tokens": 0,
                        "cached_tokens": 0,
                        "output_tokens": 0,
                        "reasoning_tokens": 0,
                        "non_cached_input_tokens": 0,
                        "codex_status_tokens": 0,
                        "api_processed_tokens": 0,
                        "estimated_api_cost_usd": None,
                        "non_cached_input_cost_usd": None,
                        "cached_input_cost_usd": None,
                        "output_cost_usd": None,
                    },
                )
            )
        return result

    def insert_subscription_quota_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        allowed_windows = {"five_hour", "weekly", "monthly"}
        window_kind = safe_text(snapshot.get("window_kind"), 32)
        if window_kind not in allowed_windows:
            raise ValueError("invalid subscription quota window")
        used = snapshot.get("used_percent")
        remaining = snapshot.get("remaining_percent")
        used_value = min(max(float(used), 0.0), 100.0) if used is not None else None
        remaining_value = min(max(float(remaining), 0.0), 100.0) if remaining is not None else None
        values = {
            "fetched_at": normalize_timestamp(snapshot.get("fetched_at")),
            "identity_key": safe_text(snapshot.get("identity_key"), 300) or "unknown",
            "account_id_hash": safe_text(snapshot.get("account_id_hash"), 64),
            "account_id_tail": safe_text(snapshot.get("account_id_tail"), 16),
            "usage_alias": safe_alias(snapshot.get("usage_alias")),
            "plan_type": safe_text(snapshot.get("plan_type"), 64),
            "subscription_active_until": normalize_optional_timestamp(
                snapshot.get("subscription_active_until")
            ),
            "window_kind": window_kind,
            "used_percent": used_value,
            "remaining_percent": remaining_value,
            "window_seconds": as_nonnegative_int(snapshot.get("window_seconds")),
            "reset_at": normalize_optional_timestamp(snapshot.get("reset_at")),
            "estimated_full_quota_usd": snapshot.get("estimated_full_quota_usd"),
            "estimated_remaining_quota_usd": snapshot.get("estimated_remaining_quota_usd"),
            "estimate_method": safe_text(snapshot.get("estimate_method"), 120),
            "source": safe_text(snapshot.get("source"), 64) or "cliproxy_wham_usage",
        }
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO subscription_quota_snapshots (
                  fetched_at, identity_key, account_id_hash, account_id_tail,
                  usage_alias, plan_type, subscription_active_until, window_kind,
                  used_percent, remaining_percent, window_seconds, reset_at,
                  estimated_full_quota_usd, estimated_remaining_quota_usd,
                  estimate_method, source
                ) VALUES (
                  :fetched_at, :identity_key, :account_id_hash, :account_id_tail,
                  :usage_alias, :plan_type, :subscription_active_until, :window_kind,
                  :used_percent, :remaining_percent, :window_seconds, :reset_at,
                  :estimated_full_quota_usd, :estimated_remaining_quota_usd,
                  :estimate_method, :source
                )
                """,
                values,
            )

    def latest_subscription_quotas(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT q.*
                  FROM subscription_quota_snapshots q
                 WHERE NOT EXISTS (
                       SELECT 1
                         FROM subscription_quota_snapshots newer
                        WHERE newer.identity_key=q.identity_key
                          AND newer.window_kind=q.window_kind
                          AND (
                                newer.fetched_at > q.fetched_at
                                OR (newer.fetched_at=q.fetched_at AND newer.id > q.id)
                              )
                 )
                 ORDER BY COALESCE(q.usage_alias, q.account_id_tail, q.identity_key),
                          CASE q.window_kind
                            WHEN 'five_hour' THEN 0
                            WHEN 'weekly' THEN 1
                            ELSE 2
                          END
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def subscription_dashboard_rows(self) -> list[dict[str, Any]]:
        quotas = self.latest_subscription_quotas()
        by_key: dict[str, dict[str, Any]] = {}
        for quota in quotas:
            key = quota["identity_key"]
            entry = by_key.setdefault(
                key,
                {
                    "identity_key": key,
                    "usage_alias": quota.get("usage_alias"),
                    "account_id_tail": quota.get("account_id_tail"),
                    "account_id_hash": quota.get("account_id_hash"),
                    "plan_type": quota.get("plan_type"),
                    "subscription_active_until": quota.get("subscription_active_until"),
                    "fetched_at": quota.get("fetched_at"),
                    "windows": {},
                },
            )
            entry["windows"][quota["window_kind"]] = quota
            if (quota.get("fetched_at") or "") > (entry.get("fetched_at") or ""):
                entry["fetched_at"] = quota.get("fetched_at")

        all_accounts = {row["identity_key"]: row for row in self.grouped("all", "account")}
        quota_cycles = {row["identity_key"]: row for row in self.quota_summary("all")}
        # Estimate from one SQLite snapshot per dashboard render.  The WHAM
        # percentage is the authoritative subscription window signal; event
        # cycles remain a fallback because transient 429s can fragment them.
        with self.connect() as conn:
            for entry in by_key.values():
                windows = entry.get("windows") or {}
                preferred = windows.get("weekly") or windows.get("monthly")
                if not preferred:
                    continue
                estimate = self._subscription_window_estimate(conn, entry, preferred)
                entry.update(estimate)
        for key, account in all_accounts.items():
            entry = by_key.setdefault(
                key,
                {
                    "identity_key": key,
                    "usage_alias": account.get("usage_alias"),
                    "account_id_tail": account.get("account_id_tail"),
                    "account_id_hash": account.get("account_id_hash"),
                    "plan_type": None,
                    "subscription_active_until": None,
                    "fetched_at": None,
                    "windows": {},
                },
            )
            entry["all_time_calls"] = account.get("calls")
            entry["all_time_account_attempts"] = account.get("account_attempts")
            entry["all_time_logical_requests"] = account.get("logical_requests")
            entry["all_time_successful_calls"] = account.get("successful_calls")
            entry["all_time_failed_calls"] = account.get("failed_calls")
            entry["all_time_extra_calls"] = account.get("retry_attempts")
            entry["all_time_tokens"] = account.get("total_tokens")
            entry["all_time_codex_status_tokens"] = account.get("codex_status_tokens")
            entry["all_time_non_cached_input_tokens"] = account.get("non_cached_input_tokens")
            entry["all_time_output_tokens"] = account.get("output_tokens")
            entry["all_time_cached_tokens"] = account.get("cached_tokens")
            entry["all_time_api_processed_tokens"] = account.get("api_processed_tokens")
            entry["all_time_cost_usd"] = account.get("estimated_api_cost_usd")
            entry["all_time_non_cached_input_cost_usd"] = account.get(
                "non_cached_input_cost_usd"
            )
            entry["all_time_cached_input_cost_usd"] = account.get(
                "cached_input_cost_usd"
            )
            entry["all_time_output_cost_usd"] = account.get("output_cost_usd")
            cycle = quota_cycles.get(key, {})
            if entry.get("current_cycle_floor_usd") is None:
                entry["current_cycle_floor_usd"] = cycle.get("current_cycle_observed_floor_usd")
            entry["historical_complete_cycle_usd"] = cycle.get(
                "last_complete_cycle_api_equivalent_quota_usd"
            )
            if entry.get("current_window_full_quota_usd") is None and not entry.get("windows"):
                entry["current_window_full_quota_usd"] = entry["historical_complete_cycle_usd"]
        result = list(by_key.values())
        result.sort(
            key=lambda row: (
                0 if row.get("usage_alias") else 1,
                numeric_alias_key(row.get("usage_alias")),
                str(row.get("account_id_tail") or row.get("identity_key")),
            )
        )
        return result

    def _subscription_window_estimate(
        self,
        conn: sqlite3.Connection,
        entry: Mapping[str, Any],
        window: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return a conservative USD-equivalent estimate for one live window.

        ``used_percent`` is a provider quota signal, not an API-token ratio.
        It is therefore only used as a projection after 5% usage, and a
        a 100%-used window uses the observed spend as the strongest estimate;
        at 95% used (5% remaining) the normal percentage projection is still
        applied.  A freshly reset/low-use account deliberately remains
        ``观测中`` instead of extrapolating a noisy tiny denominator.
        """

        account_hash = safe_text(entry.get("account_id_hash"), 64)
        identity_key_value = safe_text(entry.get("identity_key"), 300)
        reset_text = normalize_optional_timestamp(window.get("reset_at"))
        # The provider percentage is sampled at ``fetched_at`` but queue rows
        # may arrive between polls.  Include them through render time so the
        # observed floor never lags the local collector by a full poll period.
        end_text = max(normalize_timestamp(window.get("fetched_at")), utc_now())
        start_text: str | None = None
        if reset_text and window.get("window_seconds"):
            try:
                reset_dt = datetime.fromisoformat(reset_text.replace("Z", "+00:00"))
                start_text = (
                    reset_dt - timedelta(seconds=int(window["window_seconds"]))
                ).isoformat(timespec="microseconds").replace("+00:00", "Z")
            except (TypeError, ValueError, OverflowError):
                start_text = None
        if account_hash:
            scope_sql = "account_id_hash=?"
            scope_value = account_hash
        else:
            scope_sql = "identity_key=?"
            scope_value = identity_key_value or "unknown"
        bounds = [scope_value]
        time_sql = ""
        if start_text:
            time_sql += " AND ts>=?"
            bounds.append(start_text)
        if end_text:
            time_sql += " AND ts<=?"
            bounds.append(end_text)
        row = conn.execute(
            f"""
            SELECT COALESCE(SUM(estimated_api_cost_usd), 0) observed_cost_usd,
                   COALESCE(SUM(call_count), 0) calls
              FROM usage_events
             WHERE {scope_sql} {time_sql}
            """,
            tuple(bounds),
        ).fetchone()
        observed = float(row["observed_cost_usd"] or 0.0)
        used = _percent_value(window.get("used_percent"))
        projected: float | None = None
        method = "observed_floor_only"
        confidence = "low"
        if observed > 0 and used is not None and used >= QUOTA_ESTIMATE_MIN_USED_PERCENT:
            fraction = max(used / 100.0, 0.01)
            projected = observed / fraction
            if used >= QUOTA_ESTIMATE_CAP_CONFIDENCE_PERCENT:
                # Only a provider-reported 100% is a hard cap.  At 95% used,
                # the percentage projection remains useful (5% is remaining).
                projected = observed
                method = "current_window_near_cap"
                confidence = "high"
            else:
                method = "current_window_percent_projection"
                confidence = (
                    "high"
                    if used >= 95.0
                    else ("medium" if used >= QUOTA_ESTIMATE_STABLE_USED_PERCENT else "initial")
                )
        if projected is None:
            previous = self._previous_provider_window_estimate(conn, entry, window)
            if previous is not None:
                projected, method, confidence = previous
        return {
            "current_window_observed_usd": observed,
            "current_window_calls": int(row["calls"] or 0),
            "quota_used_percent": used,
            "quota_estimate_method": method,
            "quota_estimate_confidence": confidence,
            "current_window_full_quota_usd": projected,
            "current_cycle_floor_usd": observed if observed > 0 else None,
        }

    @staticmethod
    def _previous_provider_window_estimate(
        conn: sqlite3.Connection,
        entry: Mapping[str, Any],
        current_window: Mapping[str, Any],
    ) -> tuple[float, str, str] | None:
        """Use a measured prior provider window as a conservative prior.

        This is intentionally separate from the current-window percentage
        projection.  A prior window can be used only when its own snapshot
        reached at least 50% and local event cost covers that snapshot.  The
        highest-usage prior observation wins; at 100% we use observed spend
        directly, otherwise we project from that prior percentage.  Missing
        prior events (for example, a collector started after the reset) do
        not create a fabricated quota.
        """

        current_reset_text = normalize_optional_timestamp(current_window.get("reset_at"))
        current_reset: datetime | None = None
        if current_reset_text:
            try:
                current_reset = datetime.fromisoformat(current_reset_text.replace("Z", "+00:00"))
            except ValueError:
                current_reset = None
        window_seconds = as_nonnegative_int(current_window.get("window_seconds"))
        if not window_seconds:
            return None
        account_hash = safe_text(entry.get("account_id_hash"), 64)
        identity_key_value = safe_text(entry.get("identity_key"), 300)
        if account_hash:
            scope_sql = "account_id_hash=?"
            scope_value = account_hash
        else:
            scope_sql = "identity_key=?"
            scope_value = identity_key_value or "unknown"
        rows = conn.execute(
            f"""
            SELECT reset_at, fetched_at, used_percent,
                   estimated_full_quota_usd
              FROM subscription_quota_snapshots
             WHERE {scope_sql}
               AND window_kind=?
               AND reset_at IS NOT NULL
             ORDER BY fetched_at DESC, id DESC
            """,
            (scope_value, current_window.get("window_kind")),
        ).fetchall()
        best: tuple[float, float, str, str, str] | None = None
        seen_resets: set[str] = set()
        for snapshot in rows:
            reset_text = normalize_optional_timestamp(snapshot["reset_at"])
            if not reset_text or reset_text in seen_resets or reset_text == current_reset_text:
                continue
            seen_resets.add(reset_text)
            try:
                reset_at = datetime.fromisoformat(reset_text.replace("Z", "+00:00"))
            except ValueError:
                continue
            if current_reset is not None and reset_at >= current_reset:
                continue
            used = _percent_value(snapshot["used_percent"])
            if used is None or used < 50.0:
                continue
            fetched_at = normalize_timestamp(snapshot["fetched_at"])
            start_at = reset_at - timedelta(seconds=window_seconds)
            persisted_full = snapshot["estimated_full_quota_usd"]
            observed: float | None = None
            if persisted_full is not None:
                try:
                    persisted_value = float(persisted_full)
                    if math.isfinite(persisted_value) and persisted_value > 0:
                        observed = persisted_value
                except (TypeError, ValueError, OverflowError):
                    observed = None
            if observed is None:
                event_row = conn.execute(
                    f"""
                    SELECT SUM(estimated_api_cost_usd) observed_cost_usd
                      FROM usage_events
                     WHERE {scope_sql}
                       AND ts>=? AND ts<=? AND estimated_api_cost_usd IS NOT NULL
                    """,
                    (scope_value, start_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                     min(datetime.fromisoformat(fetched_at.replace("Z", "+00:00")), reset_at)
                     .isoformat(timespec="microseconds").replace("+00:00", "Z")),
                ).fetchone()
                if event_row["observed_cost_usd"] is not None:
                    observed = float(event_row["observed_cost_usd"])
            if observed is None or not math.isfinite(observed) or observed <= 0:
                continue
            estimate = observed if used >= QUOTA_ESTIMATE_CAP_CONFIDENCE_PERCENT else observed / (used / 100.0)
            confidence = "high" if used >= QUOTA_ESTIMATE_CAP_CONFIDENCE_PERCENT else "medium"
            candidate = (used, estimate, confidence, reset_text, fetched_at)
            if best is None or (candidate[0], candidate[4]) > (best[0], best[4]):
                best = candidate
        if best is None:
            return None
        return best[1], "previous_window_transfer", best[2]

    def grouped(self, period: str, dimension: str) -> list[dict[str, Any]]:
        start = period_start(period)
        dimensions = {
            "account": (
                "identity_key",
                "identity_key, MAX(usage_alias) usage_alias, MAX(account_id_tail) account_id_tail, "
                "MAX(account_id_hash) account_id_hash, MAX(auth_fingerprint) auth_fingerprint",
            ),
            "model": ("COALESCE(model, '(unknown)')", "COALESCE(model, '(unknown)') model"),
            "session": ("COALESCE(session_id, '(unknown)')", "COALESCE(session_id, '(unknown)') session_id"),
            "date": ("date(ts, 'localtime')", "date(ts, 'localtime') date"),
        }
        if dimension not in dimensions:
            raise ValueError(f"unknown dimension: {dimension}")
        group_expression, select_expression = dimensions[dimension]
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {select_expression},
                  COALESCE(SUM(call_count), 0) calls,
                  COALESCE(SUM(call_count), 0) account_attempts,
                  COUNT(DISTINCT request_id)
                    + COALESCE(SUM(CASE WHEN request_id IS NULL THEN call_count ELSE 0 END), 0)
                    logical_requests,
                  COALESCE(SUM(CASE WHEN ok=1 THEN call_count ELSE 0 END), 0) successful_calls,
                  COALESCE(SUM(CASE WHEN ok=0 THEN call_count ELSE 0 END), 0) failed_calls,
                  COALESCE(SUM(input_tokens), 0) input_tokens,
                  COALESCE(SUM(cached_tokens), 0) cached_tokens,
                  COALESCE(SUM(output_tokens), 0) output_tokens,
                  COALESCE(SUM(reasoning_tokens), 0) reasoning_tokens,
                  COALESCE(SUM(total_tokens), 0) total_tokens,
                  COALESCE(SUM(CASE WHEN long_context_pricing_applied=1 THEN call_count ELSE 0 END), 0)
                    long_context_priced_calls,
                  COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)), 0)
                    non_cached_input_tokens,
                  COALESCE(SUM(MAX(COALESCE(input_tokens, 0) - COALESCE(cached_tokens, 0), 0)
                               + COALESCE(output_tokens, 0)), 0)
                    codex_status_tokens,
                  COALESCE(SUM(COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)), 0)
                    api_processed_tokens,
                  SUM(estimated_api_cost_usd) estimated_api_cost_usd,
                  SUM(non_cached_input_cost_usd) non_cached_input_cost_usd,
                  SUM(cached_input_cost_usd) cached_input_cost_usd,
                  SUM(output_cost_usd) output_cost_usd,
                  COALESCE(SUM(CASE WHEN usage_missing=1 THEN call_count ELSE 0 END), 0) usage_missing_calls
                FROM usage_events WHERE ts>=?
                GROUP BY {group_expression}
                ORDER BY calls DESC, total_tokens DESC
                """,
                (start,),
            ).fetchall()
        result = [dict(row) for row in rows]
        for row in result:
            input_tokens = int(row.get("input_tokens") or 0)
            cached_tokens = int(row.get("cached_tokens") or 0)
            row["cache_hit_rate_percent"] = (
                cached_tokens / input_tokens * 100.0 if input_tokens else None
            )
            row["retry_attempts"] = max(
                int(row.get("account_attempts") or 0) - int(row.get("logical_requests") or 0), 0
            )
        return result

    def recent(self, count: int) -> list[dict[str, Any]]:
        count = max(1, min(int(count), 500))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, usage_alias, account_id_tail, account_id_hash,
                  auth_fingerprint, session_id, model, endpoint, method,
                  status_code, ok, duration_ms, stream, input_tokens,
                  cached_tokens, cache_write_tokens, output_tokens, reasoning_tokens, total_tokens,
                  estimated_api_cost_usd, non_cached_input_cost_usd,
                  cached_input_cost_usd, output_cost_usd, long_context_pricing_applied,
                  usage_missing, error_type,
                  error_message_redacted, source, request_id
                FROM usage_events ORDER BY ts DESC, id DESC LIMIT ?
                """,
                (count,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _percentile(values: Sequence[float], fraction: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        if len(ordered) == 1:
            return ordered[0]
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1 - weight) + ordered[upper] * weight

    def quota_summary(self, period: str = "30d") -> list[dict[str, Any]]:
        start = period_start(period)
        with self.connect() as conn:
            identities = conn.execute(
                """
                SELECT identity_key, MAX(usage_alias) usage_alias,
                       MAX(account_id_tail) account_id_tail,
                       MAX(account_id_hash) account_id_hash,
                       MAX(auth_fingerprint) auth_fingerprint
                FROM (
                  SELECT identity_key, usage_alias, account_id_tail, account_id_hash, auth_fingerprint, ts
                    FROM usage_events WHERE identity_key IS NOT NULL
                  UNION ALL
                  SELECT identity_key, usage_alias, account_id_tail, account_id_hash, NULL, ts
                    FROM quota_events WHERE identity_key IS NOT NULL
                  UNION ALL
                  SELECT identity_key, usage_alias, account_id_tail, account_id_hash, NULL, cycle_end_ts AS ts
                    FROM account_quota_cycles WHERE identity_key IS NOT NULL
                )
                GROUP BY identity_key ORDER BY MAX(ts) DESC
                """
            ).fetchall()
            results: list[dict[str, Any]] = []
            for identity in identities:
                key = identity["identity_key"]
                reset_ts = self._latest_event_ts(conn, key, RESET_EVENT_TYPES)
                if reset_ts is None:
                    first = conn.execute(
                        "SELECT MIN(ts) first_ts FROM usage_events WHERE identity_key=? AND ok=1", (key,)
                    ).fetchone()
                    if not first or first["first_ts"] is None:
                        first = conn.execute(
                            "SELECT MIN(ts) first_ts FROM usage_events WHERE identity_key=?", (key,)
                        ).fetchone()
                    reset_ts = first["first_ts"] if first else None
                hit_ts = self._latest_event_ts(conn, key, QUOTA_EVENT_TYPES)
                current = conn.execute(
                    """
                    SELECT COALESCE(SUM(call_count), 0) calls,
                           COALESCE(SUM(total_tokens), 0) total_tokens,
                           SUM(estimated_api_cost_usd) observed_floor_usd
                    FROM usage_events
                    WHERE identity_key=? AND ts>=?
                      AND (? IS NULL OR ts<=?)
                    """,
                    (
                        key,
                        reset_ts or "",
                        hit_ts if hit_ts and (not reset_ts or hit_ts >= reset_ts) else None,
                        hit_ts if hit_ts and (not reset_ts or hit_ts >= reset_ts) else None,
                    ),
                ).fetchone()
                if str(period).strip().lower() in ALL_TIME_PERIODS:
                    complete = conn.execute(
                        """SELECT * FROM account_quota_cycles
                           WHERE identity_key=? AND is_complete_cycle=1
                           ORDER BY cycle_end_ts DESC, id DESC""",
                        (key,),
                    ).fetchall()
                else:
                    complete = conn.execute(
                        """SELECT * FROM account_quota_cycles
                           WHERE identity_key=? AND is_complete_cycle=1 AND cycle_end_ts>=?
                           ORDER BY cycle_end_ts DESC, id DESC""",
                        (key, start),
                    ).fetchall()
                values = [
                    float(row["api_equivalent_quota_usd"])
                    for row in complete
                    if row["api_equivalent_quota_usd"] is not None
                ]
                results.append(
                    {
                        "identity_key": key,
                        "usage_alias": identity["usage_alias"],
                        "account_id_tail": identity["account_id_tail"],
                        "account_id_hash": identity["account_id_hash"],
                        "auth_fingerprint": identity["auth_fingerprint"],
                        "current_cycle_start_ts": reset_ts,
                        "current_cycle_calls": current["calls"],
                        "current_cycle_tokens": current["total_tokens"],
                        "current_cycle_observed_floor_usd": current["observed_floor_usd"],
                        "currently_quota_hit": int(bool(hit_ts and (not reset_ts or hit_ts >= reset_ts))),
                        "complete_cycles_in_period": len(complete),
                        "last_complete_cycle_api_equivalent_quota_usd": (
                            complete[0]["api_equivalent_quota_usd"] if complete else None
                        ),
                        "historical_min_usd": min(values) if values else None,
                        "historical_p20_usd": self._percentile(values, 0.20),
                        "historical_p50_usd": self._percentile(values, 0.50),
                        "historical_p80_usd": self._percentile(values, 0.80),
                        "historical_max_usd": max(values) if values else None,
                    }
                )
        return results


class OfficialPriceSyncError(RuntimeError):
    """A safe, user-facing official pricing fetch/parse failure."""


class _PricingHTMLParser(HTMLParser):
    """Extract rows from one server-rendered OpenAI pricing table.

    The public page is server-rendered and has changed its surrounding Astro
    component markup a few times.  This parser intentionally depends only on
    ordinary ``table``/``tr``/``td`` elements, not on generated CSS classes or
    JavaScript bundles.  The caller selects the standard-tier table fragment.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self._table_depth = 0
        self._table_done = False
        self._cell_tag: str | None = None
        self._cell_parts: list[str] = []
        self._row: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "table" and not self._table_done:
            self._table_depth += 1
            return
        if self._table_depth == 0 or self._table_done:
            return
        if tag == "tr":
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell_tag = tag
            self._cell_parts = []
        elif tag == "br" and self._cell_tag is not None:
            self._cell_parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._table_depth == 0 or self._table_done:
            return
        if tag in {"td", "th"} and self._cell_tag is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell_parts).split()))
            self._cell_tag = None
            self._cell_parts = []
        elif tag == "tr":
            if self._row:
                self.rows.append(self._row)
            self._row = None
        elif tag == "table":
            self._table_depth -= 1
            if self._table_depth == 0:
                self._table_done = True

    def handle_data(self, data: str) -> None:
        if self._cell_tag is not None:
            self._cell_parts.append(data)


def _pricing_number(value: str | None) -> float | None:
    if not value:
        return None
    text = value.strip().replace(",", "")
    if text.lower() in {"-", "—", "–", "n/a", "na", "none", "null"}:
        return None
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        number = float(match.group(0))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _normalize_official_model(value: str | None) -> str | None:
    if not value:
        return None
    text = " ".join(value.split())
    # The standard table annotates some rows with a context-length parenthesis;
    # the model id itself is the stable prefix used in API requests.
    text = re.sub(r"\s*\([^)]*context(?:\s+length)?[^)]*\)", "", text, flags=re.IGNORECASE)
    text = text.strip()
    if not text or text.lower() in {"model", "models"}:
        return None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", text):
        return None
    return text


def _parse_pricing_props_rows(fragment: str) -> list[dict[str, Any]]:
    """Read the complete model list from the page's SSR pricing props.

    The rendered table intentionally shows only a few rows until the browser
    expands it, while the Astro props retain the complete standard-tier list.
    This small, deliberately constrained matcher handles the tagged scalar
    representation used by the page and falls back to rendered rows when the
    representation changes.
    """

    row_pattern = re.compile(
        r'\[1,\[\[0,"((?:\\.|[^"\\])*)"\],'
        r'((?:\[0,(?:"(?:\\.|[^"\\])*"|null|-?\d+(?:\.\d+)?)\],?)+)\]\]',
        re.DOTALL,
    )
    scalar_pattern = re.compile(r'\[0,("(?:\\.|[^"\\])*"|null|-?\d+(?:\.\d+)?)\]')
    parsed: dict[str, dict[str, Any]] = {}
    for match in row_pattern.finditer(fragment):
        raw_model = match.group(1)
        try:
            model = json.loads(f'"{raw_model}"')
        except (json.JSONDecodeError, TypeError):
            continue
        model = _normalize_official_model(model)
        if not model:
            continue
        values: list[Any] = []
        for raw in scalar_pattern.findall(match.group(2)):
            if raw == "null":
                values.append(None)
            elif raw.startswith('"'):
                try:
                    values.append(json.loads(raw))
                except json.JSONDecodeError:
                    values.append(None)
            else:
                try:
                    values.append(float(raw))
                except ValueError:
                    values.append(None)
        if len(values) < 3:
            continue
        input_rate = _pricing_number(str(values[0]) if values[0] is not None else None)
        cached_rate = _pricing_number(str(values[1]) if values[1] is not None else None)
        cache_write_rate = (
            _pricing_number(str(values[2]) if values[2] is not None else None)
            if len(values) >= 4
            else None
        )
        output_index = 3 if len(values) >= 4 else 2
        output_rate = _pricing_number(str(values[output_index]) if values[output_index] is not None else None)
        if input_rate is None and output_rate is None:
            continue
        parsed.setdefault(
            model,
            {
                "model_pattern": model,
                "input_per_million": input_rate,
                "output_per_million": output_rate,
                "cached_input_per_million": cached_rate,
                "cache_write_per_million": cache_write_rate,
            },
        )
    return list(parsed.values())


def _complete_context_tiers(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Derive documented Standard long tiers when the page omits props fields.

    OpenAI model pages state that GPT-5.4/5.5 1.05M models and the GPT-5.6
    family charge 2x input and 1.5x output above 272K input tokens.  The same
    pricing page defines cache writes as 1.25x input and cached reads as their
    own input category.  Apply this only to the explicitly documented model
    IDs, never to similarly named mini/nano/cyber variants.
    """

    eligible = {
        "gpt-5.4",
        "gpt-5.4-pro",
        "gpt-5.5",
        "gpt-5.5-pro",
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    }
    completed: list[dict[str, Any]] = []
    for source in rows:
        row = dict(source)
        model = row.get("model_pattern")
        if model not in eligible:
            completed.append(row)
            continue
        input_rate = row.get("input_per_million")
        cached_rate = row.get("cached_input_per_million")
        output_rate = row.get("output_per_million")
        cache_write_rate = row.get("cache_write_per_million")
        row["long_context_threshold_tokens"] = LONG_CONTEXT_THRESHOLD_TOKENS
        row["long_input_per_million"] = (
            float(input_rate) * 2.0 if input_rate is not None else None
        )
        row["long_cached_input_per_million"] = (
            float(cached_rate) * 2.0 if cached_rate is not None else None
        )
        if cache_write_rate is None and input_rate is not None and str(model).startswith("gpt-5.6-"):
            cache_write_rate = float(input_rate) * 1.25
            row["cache_write_per_million"] = cache_write_rate
        row["long_cache_write_per_million"] = (
            float(cache_write_rate) * 2.0 if cache_write_rate is not None else None
        )
        row["long_output_per_million"] = (
            float(output_rate) * 1.5 if output_rate is not None else None
        )
        completed.append(row)
    return completed


def _parse_grouped_context_pricing_rows(fragment: str) -> list[dict[str, Any]]:
    """Read the Standard grouped short/long-context table from Astro props."""

    if "Short context input" not in fragment or "Long context input" not in fragment:
        return []
    heading_pos = fragment.find("Short context input")
    island_start = fragment.rfind("<astro-island", 0, heading_pos)
    # In raw HTML the heading text lives inside &quot; entities, so callers
    # that unescape first can move it before the literal opening tag boundary.
    # When that happens, take the first island containing the heading.
    if island_start < 0:
        island_start = fragment.find("<astro-island")
    island_end = fragment.find("</astro-island>", heading_pos)
    if island_start >= 0 and island_start < heading_pos and island_end > island_start:
        fragment = fragment[island_start : island_end + len("</astro-island>")]
    group_pattern = re.compile(
        r'"model":\[0,"((?:\\.|[^"\\])*)"\].*?'
        r'"rows":\[1,\[\[1,\[(.*?)\]\]\]\]',
        re.DOTALL,
    )
    scalar_pattern = re.compile(r'\[0,("(?:\\.|[^"\\])*"|null|-?\d+(?:\.\d+)?)\]')
    parsed: dict[str, dict[str, Any]] = {}
    for match in group_pattern.finditer(fragment):
        try:
            model = _normalize_official_model(json.loads(f'"{match.group(1)}"'))
        except (json.JSONDecodeError, TypeError):
            continue
        if not model:
            continue
        values: list[Any] = []
        values_fragment = match.group(2)
        if values_fragment and not values_fragment.endswith("]"):
            values_fragment += "]"
        for raw in scalar_pattern.findall(values_fragment):
            if raw == "null":
                values.append(None)
            elif raw.startswith('"'):
                try:
                    values.append(json.loads(raw))
                except json.JSONDecodeError:
                    values.append(None)
            else:
                try:
                    values.append(float(raw))
                except ValueError:
                    values.append(None)
        if len(values) < 8:
            continue
        rates = [_pricing_number(str(value) if value is not None else None) for value in values[:8]]
        if rates[0] is None and rates[3] is None:
            continue
        has_long_tier = any(value is not None for value in rates[4:8])
        parsed[model] = {
            "model_pattern": model,
            "input_per_million": rates[0],
            "cached_input_per_million": rates[1],
            "cache_write_per_million": rates[2],
            "output_per_million": rates[3],
            "long_context_threshold_tokens": (
                LONG_CONTEXT_THRESHOLD_TOKENS if has_long_tier else None
            ),
            "long_input_per_million": rates[4],
            "long_cached_input_per_million": rates[5],
            "long_cache_write_per_million": rates[6],
            "long_output_per_million": rates[7],
        }
    return list(parsed.values())


def parse_official_pricing_html(document: str | bytes) -> list[dict[str, Any]]:
    """Parse Standard short- and long-context prices from the official page.

    Returned prices are USD per million tokens.  The sidecar does not infer a
    price for a model absent from this table.  Long-context pricing is enabled
    only when the official table provides a complete tier for that model.
    """

    if isinstance(document, bytes):
        try:
            text = document.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OfficialPriceSyncError("pricing page is not UTF-8 HTML") from exc
    else:
        text = document
    if not text or len(text) > 20 * 1024 * 1024:
        raise OfficialPriceSyncError("pricing page is empty or too large")

    standard_marker = 'data-content-switcher-pane="true" data-value="standard"'
    standard_pos = text.find(standard_marker)
    # The current page renders the compact TextTokenPricingTables and the
    # complete grouped context table as separate islands.  Locate the unique
    # grouped table by its explicit headings instead of assuming adjacency.
    grouped_rows = _parse_grouped_context_pricing_rows(html.unescape(text))

    marker = 'component-export="TextTokenPricingTables"'
    marker_pos = text.find(marker, max(0, standard_pos)) if standard_pos >= 0 else -1
    if marker_pos < 0:
        marker_pos = text.find(marker)
    if marker_pos >= 0:
        start = text.rfind("<astro-island", 0, marker_pos)
        end = text.find("</astro-island>", marker_pos)
        fragment = text[start : end + len("</astro-island>")] if start >= 0 and end >= 0 else text
    else:
        fragment = text

    unescaped_fragment = html.unescape(fragment)
    props_rows = _parse_pricing_props_rows(unescaped_fragment)
    if grouped_rows:
        by_model = {row["model_pattern"]: row for row in props_rows}
        for grouped_row in grouped_rows:
            model = grouped_row["model_pattern"]
            by_model[model] = grouped_row
        return _complete_context_tiers(list(by_model.values()))
    if props_rows:
        return _complete_context_tiers(props_rows)

    parser = _PricingHTMLParser()
    try:
        parser.feed(fragment)
        parser.close()
    except Exception as exc:  # HTMLParser should be forgiving; make failure explicit.
        raise OfficialPriceSyncError("pricing HTML parser failed") from exc
    rows = parser.rows
    if not rows:
        raise OfficialPriceSyncError("standard pricing table not found")

    header: list[str] | None = None
    for row in rows:
        lowered = [cell.strip().lower() for cell in row]
        if lowered and lowered[0] == "model" and any("output" in cell for cell in lowered):
            header = lowered
            break
    if header is None:
        # A compact/future page may omit explicit headers in the fragment; the
        # current standard table's first data layout remains model,input,cached,
        # cache-writes,output (or model,input,cached,output).
        header = ["model", "input", "cached input", "cache writes", "output"]

    try:
        model_index = header.index("model")
    except ValueError:
        model_index = 0
    input_indexes = [index for index, value in enumerate(header) if value == "input"]
    cached_indexes = [index for index, value in enumerate(header) if value.startswith("cached input")]
    output_indexes = [index for index, value in enumerate(header) if value == "output"]
    input_index = input_indexes[0] if input_indexes else 1
    cached_index = cached_indexes[0] if cached_indexes else 2
    output_index = output_indexes[0] if output_indexes else (4 if len(header) >= 5 else 3)

    parsed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row is header:
            continue
        if model_index >= len(row):
            continue
        model = _normalize_official_model(row[model_index])
        if not model:
            continue
        if max(input_index, cached_index, output_index) >= len(row):
            continue
        input_rate = _pricing_number(row[input_index])
        output_rate = _pricing_number(row[output_index])
        cached_rate = _pricing_number(row[cached_index])
        # A row with no numeric input/output is a malformed/header row, not a
        # usable official price.  Retain a legitimate '-' output as NULL only
        # when the input side is present (e.g. pro variants).
        if input_rate is None and output_rate is None:
            continue
        parsed.setdefault(
            model,
            {
                "model_pattern": model,
                "input_per_million": input_rate,
                "output_per_million": output_rate,
                "cached_input_per_million": cached_rate,
            },
        )
    if not parsed:
        raise OfficialPriceSyncError("standard pricing table contained no usable model rows")
    return _complete_context_tiers(list(parsed.values()))


def _validate_official_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in OFFICIAL_PRICING_HOSTS:
        raise OfficialPriceSyncError("pricing URL must be an HTTPS official OpenAI documentation URL")
    if parsed.username or parsed.password:
        raise OfficialPriceSyncError("pricing URL must not contain credentials")
    return url


def fetch_official_pricing_html(url: str = OFFICIAL_PRICING_URL, timeout: float = 20.0) -> tuple[str, bytes, str]:
    """Fetch an official pricing page with bounded size and host validation."""

    _validate_official_url(url)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "cliproxy-usage-meter-official-price-sync/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=max(float(timeout), 1.0)) as response:
            final_url = response.geturl() or url
            _validate_official_url(final_url)
            body = response.read(20 * 1024 * 1024 + 1)
    except OfficialPriceSyncError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OfficialPriceSyncError(f"official pricing fetch error: {type(exc).__name__}") from exc
    if len(body) > 20 * 1024 * 1024:
        raise OfficialPriceSyncError("official pricing page exceeds size limit")
    return final_url, body, hashlib.sha256(body).hexdigest()


def sync_official_prices(
    repo: UsageRepository,
    *,
    url: str = OFFICIAL_PRICING_URL,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Fetch, parse, and atomically install official prices.

    Any fetch/parse failure records redacted metadata and leaves the previous
    model price rows untouched.  This function is deliberately explicit; the
    long-running proxy never performs network I/O at startup.
    """

    requested_at = utc_now()
    content_sha256: str | None = None
    final_url = url
    try:
        final_url, body, content_sha256 = fetch_official_pricing_html(url, timeout)
        rows = parse_official_pricing_html(body)
        repriced_events = repo.replace_official_prices(
            rows,
            source_url=final_url,
            fetched_at=requested_at,
            content_sha256=content_sha256,
            parser_version=OFFICIAL_PRICE_PARSER_VERSION,
        )
        return {
            "status": "ok",
            "source_url": final_url,
            "fetched_at": requested_at,
            "content_sha256": content_sha256,
            "parser_version": OFFICIAL_PRICE_PARSER_VERSION,
            "model_count": len(rows),
            "repriced_events": repriced_events,
        }
    except Exception as exc:
        try:
            repo.record_price_sync(
                source_url=final_url,
                fetched_at=requested_at,
                content_sha256=content_sha256,
                parser_version=OFFICIAL_PRICE_PARSER_VERSION,
                status="error",
                model_count=0,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
        except Exception:
            # Preserve the original sync failure; database diagnostics must not
            # leak or mask it.
            pass
        if isinstance(exc, OfficialPriceSyncError):
            raise
        raise OfficialPriceSyncError(f"official pricing sync error: {type(exc).__name__}") from exc


def detect_quota_event(status_code: int, error_type: str | None, message: str | None) -> str | None:
    combined = f"{error_type or ''} {message or ''}".lower()
    if "auth_unavailable" in combined and not any(
        word in combined for word in ("quota", "usage limit", "cooldown", "rate limit", "limit reached")
    ):
        return None
    if "cooldown" in combined:
        return "cooldown_hit"
    if "usage limit" in combined or "usage_limit" in combined or "limit reached" in combined or "额度" in combined:
        return "usage_limit_hit"
    if "insufficient_quota" in combined or "quota" in combined:
        return "quota_hit"
    if "rate limited" in combined or "rate-limit" in combined or "rate limit" in combined or status_code == 429:
        return "rate_limit_hit"
    return None


def _queue_headers_are_streaming(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    for key, raw in value.items():
        if str(key).lower() != "content-type":
            continue
        values = raw if isinstance(raw, list) else [raw]
        return any("text/event-stream" in str(item).lower() for item in values)
    return False


def queue_record_event(
    record: Mapping[str, Any],
    resolver: AccountResolver,
    repo: UsageRepository,
) -> tuple[UsageEvent, RequestInfo] | None:
    """Convert one CLIProxyAPI usage-queue record into the local safe schema.

    The upstream payload contains an ``api_key`` field.  It is intentionally
    never read, copied, logged, or passed to any identity resolver.
    """

    if not isinstance(record, Mapping):
        return None
    token_block = record.get("tokens")
    if not isinstance(token_block, Mapping):
        token_block = record.get("token_breakdown") if isinstance(record.get("token_breakdown"), Mapping) else {}
    usage = NormalizedUsage(
        input_tokens=as_nonnegative_int(token_block.get("input_tokens")),
        output_tokens=as_nonnegative_int(token_block.get("output_tokens")),
        cached_tokens=as_nonnegative_int(
            token_block.get("cached_tokens")
            if token_block.get("cached_tokens") is not None
            else token_block.get("cache_read_tokens")
        ),
        cache_write_tokens=as_nonnegative_int(token_block.get("cache_write_tokens")),
        reasoning_tokens=as_nonnegative_int(token_block.get("reasoning_tokens")),
        total_tokens=as_nonnegative_int(token_block.get("total_tokens")),
    )
    model = safe_text(record.get("model") or record.get("alias"), 200)
    endpoint = safe_text(record.get("endpoint"), 300) or "/v1/unknown"
    if not endpoint.startswith("/"):
        endpoint = "/v1/unknown"
    auth_index = safe_text(record.get("auth_index"), 512)
    digest_raw = safe_text(record.get("access_token_sha256"), 128)
    digest = digest_raw.lower() if digest_raw and re.fullmatch(r"[0-9a-f]{64}", digest_raw.lower()) else None
    auth_fingerprint = digest[:16] if digest else None
    identity = resolver.resolve_queue(auth_index, digest, safe_text(record.get("alias"), 200))
    usage_alias = identity.usage_alias or (f"auth:{auth_fingerprint}" if auth_fingerprint else None)
    key = identity_key(identity.account_id_hash, usage_alias, auth_fingerprint, None, None)
    metadata = record.get("client_request_metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    session_id = safe_text(metadata.get("session_id"), 256)
    thread_id = safe_text(metadata.get("thread_id"), 256)
    turn_id = safe_text(metadata.get("turn_id"), 256)
    installation_id = safe_text(metadata.get("installation_id"), 256)
    window_id = safe_text(metadata.get("window_id"), 256)
    info = RequestInfo(
        endpoint=endpoint,
        method="POST",
        model=model,
        stream=int(_queue_headers_are_streaming(record.get("response_headers"))),
        session_id=session_id,
        thread_id=thread_id,
        turn_id=turn_id,
        installation_id=installation_id,
        window_id=window_id,
        usage_alias=usage_alias,
        usage_project=None,
        auth_fingerprint=auth_fingerprint,
        account_id_hash=identity.account_id_hash,
        account_id_tail=identity.account_id_tail,
        identity_key=key,
    )
    fail_block = record.get("fail") if isinstance(record.get("fail"), Mapping) else {}
    failed = bool(record.get("failed"))
    status_value = as_nonnegative_int(fail_block.get("status_code"))
    status_code = status_value if status_value and status_value >= 100 else (500 if failed else 200)
    error_message = redact_text(fail_block.get("body")) if failed else None
    components = repo.price_components_for(model, usage)
    event = UsageEvent(
        ts=normalize_timestamp(record.get("timestamp")),
        identity_key=key,
        endpoint=endpoint,
        method="POST",
        model=model,
        status_code=status_code,
        ok=int(not failed and 200 <= status_code < 300),
        duration_ms=as_nonnegative_int(record.get("latency_ms")) or 0,
        stream=info.stream,
        session_id=session_id,
        thread_id=thread_id,
        turn_id=turn_id,
        installation_id=installation_id,
        window_id=window_id,
        usage_alias=usage_alias,
        usage_project=None,
        auth_fingerprint=auth_fingerprint,
        account_id_hash=identity.account_id_hash,
        account_id_tail=identity.account_id_tail,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cached_tokens=usage.cached_tokens,
        cache_write_tokens=usage.cache_write_tokens,
        reasoning_tokens=usage.reasoning_tokens,
        total_tokens=usage.total_tokens,
        estimated_api_cost_usd=components.total_cost_usd if components else None,
        non_cached_input_cost_usd=(
            components.non_cached_input_cost_usd if components else None
        ),
        cached_input_cost_usd=components.cached_input_cost_usd if components else None,
        output_cost_usd=components.output_cost_usd if components else None,
        long_context_pricing_applied=int(
            components.long_context_pricing_applied if components else False
        ),
        subscription_amortized_cost_usd=None,
        api_equivalent_quota_usd=None,
        usage_missing=int(usage.missing),
        error_type="upstream_error" if failed else None,
        error_message_redacted=error_message,
        request_bytes=0,
        response_bytes=0,
        source="usage_queue",
        request_id=short_hash(safe_text(record.get("request_id"), 256)),
    )
    return event, info


def _percent_value(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 0 <= number <= 100:
        return None
    return number


def parse_codex_quota_windows(payload: Any, fetched_at: str | None = None) -> list[dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    rate_limit = first_present(payload, ("rate_limit", "rateLimit"))
    if not isinstance(rate_limit, Mapping):
        return []
    primary = first_present(rate_limit, ("primary_window", "primaryWindow"))
    secondary = first_present(rate_limit, ("secondary_window", "secondaryWindow"))
    candidates = [primary, secondary]
    windows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(candidates):
        if not isinstance(raw, Mapping):
            continue
        window_seconds = as_nonnegative_int(
            first_present(raw, ("limit_window_seconds", "limitWindowSeconds"))
        )
        if window_seconds == 18_000:
            kind = "five_hour"
        elif window_seconds and 2_419_200 <= window_seconds <= 2_678_400:
            kind = "monthly"
        elif window_seconds == 604_800:
            kind = "weekly"
        else:
            kind = "five_hour" if index == 0 else "weekly"
        if kind in seen:
            continue
        used = _percent_value(first_present(raw, ("used_percent", "usedPercent")))
        if used is None:
            limit_reached = first_present(rate_limit, ("limit_reached", "limitReached"))
            allowed = rate_limit.get("allowed")
            if limit_reached is True or allowed is False:
                used = 100.0
        reset_value = first_present(raw, ("reset_at", "resetAt"))
        if reset_value is None:
            reset_after = as_nonnegative_int(
                first_present(raw, ("reset_after_seconds", "resetAfterSeconds"))
            )
            if reset_after is not None:
                reset_value = datetime.now(timezone.utc).timestamp() + reset_after
        windows.append(
            {
                "fetched_at": fetched_at or utc_now(),
                "window_kind": kind,
                "used_percent": used,
                "remaining_percent": 100.0 - used if used is not None else None,
                "window_seconds": window_seconds,
                "reset_at": normalize_optional_timestamp(reset_value),
            }
        )
        seen.add(kind)
    return windows


def parse_codex_app_rate_windows(
    rate_limits: Any,
    fetched_at: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize the non-secret rate-limit block written to Codex JSONL."""

    if not isinstance(rate_limits, Mapping):
        return []
    windows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, name in enumerate(("primary", "secondary")):
        raw = rate_limits.get(name)
        if not isinstance(raw, Mapping):
            continue
        minutes = as_nonnegative_int(
            first_present(raw, ("window_minutes", "windowMinutes"))
        )
        seconds = minutes * 60 if minutes is not None else None
        if seconds == 18_000:
            kind = "five_hour"
        elif seconds and 2_419_200 <= seconds <= 2_678_400:
            kind = "monthly"
        elif seconds == 604_800:
            kind = "weekly"
        else:
            kind = "five_hour" if index == 0 else "weekly"
        if kind in seen:
            continue
        used = _percent_value(first_present(raw, ("used_percent", "usedPercent")))
        windows.append(
            {
                "fetched_at": fetched_at or utc_now(),
                "window_kind": kind,
                "used_percent": used,
                "remaining_percent": 100.0 - used if used is not None else None,
                "window_seconds": seconds,
                "reset_at": normalize_optional_timestamp(
                    first_present(raw, ("resets_at", "resetsAt", "reset_at", "resetAt"))
                ),
            }
        )
        seen.add(kind)
    return windows


class CodexAppLocalImporter:
    """Incrementally import safe usage fields from ChatGPT Codex JSONL files.

    Only ``session_meta``, ``turn_context``, ``task_started`` and
    ``token_count`` metadata is inspected.  Message, reasoning and tool payloads
    are ignored and never persisted.  Direct OpenAI sessions are selected by
    ``model_provider=openai`` and matched to the configured alias by local
    account id, preventing CLIProxyAPI sessions from being double counted.
    """

    def __init__(
        self,
        repo: UsageRepository,
        resolver: AccountResolver,
        codex_home: Path | str = DEFAULT_CODEX_APP_HOME,
        alias: str = DEFAULT_CODEX_APP_ALIAS,
        poll_seconds: float = DEFAULT_CODEX_APP_POLL_SECONDS,
        max_files: int = DEFAULT_CODEX_APP_MAX_FILES,
    ) -> None:
        self.repo = repo
        self.resolver = resolver
        self.codex_home = Path(codex_home).expanduser().resolve()
        self.alias = safe_alias(alias) or DEFAULT_CODEX_APP_ALIAS
        self.poll_seconds = max(5.0, float(poll_seconds))
        self.max_files = max(1, min(int(max_files), 10_000))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_poll_at: str | None = None
        self._last_success_at: str | None = None
        self._last_error_type: str | None = None
        self._last_imported = 0
        self._last_scanned_files = 0
        self._account_match: bool | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="codex-app-local-import", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._thread = None

    def status(self) -> dict[str, Any]:
        persisted = self.repo.import_status("codex_app_local")
        return {
            "enabled": True,
            "codex_home": str(self.codex_home),
            "usage_alias": self.alias,
            "account_match": self._account_match,
            "last_poll_at": self._last_poll_at,
            "last_success_at": self._last_success_at,
            "last_error_type": self._last_error_type,
            "last_imported": self._last_imported,
            "last_scanned_files": self._last_scanned_files,
            **persisted,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                result = self.import_once()
                self._last_poll_at = utc_now()
                self._last_success_at = self._last_poll_at
                self._last_error_type = None
                self._last_imported = result["imported"]
                self._last_scanned_files = result["scanned_files"]
            except Exception as exc:
                self._last_poll_at = utc_now()
                self._last_error_type = type(exc).__name__
                LOG.warning("Codex app local import failed: %s", type(exc).__name__)
            self._stop.wait(self.poll_seconds)

    @staticmethod
    def _read_auth_identity(path: Path) -> tuple[str | None, str | None, str | None]:
        data = AccountResolver._read_json(path)
        if not isinstance(data, Mapping):
            return None, None, None
        nested = data.get("tokens") if isinstance(data.get("tokens"), Mapping) else {}
        account = safe_text(nested.get("account_id") or data.get("account_id"), 256)
        claims = _decode_jwt_claims_unverified(
            nested.get("id_token") or data.get("id_token")
        )
        auth_claims = claims.get("https://api.openai.com/auth")
        auth_claims = auth_claims if isinstance(auth_claims, Mapping) else {}
        plan = safe_text(
            auth_claims.get("chatgpt_plan_type")
            or claims.get("chatgpt_plan_type")
            or claims.get("plan_type"),
            64,
        )
        active_until = normalize_optional_timestamp(
            auth_claims.get("chatgpt_subscription_active_until")
            or claims.get("chatgpt_subscription_active_until")
        )
        return account, plan, active_until

    @staticmethod
    def _usage_from_token_count(payload: Mapping[str, Any]) -> NormalizedUsage:
        info = payload.get("info") if isinstance(payload.get("info"), Mapping) else {}
        raw = info.get("last_token_usage")
        if not isinstance(raw, Mapping):
            return NormalizedUsage()
        return NormalizedUsage(
            input_tokens=as_nonnegative_int(raw.get("input_tokens")),
            output_tokens=as_nonnegative_int(raw.get("output_tokens")),
            cached_tokens=as_nonnegative_int(raw.get("cached_input_tokens")),
            cache_write_tokens=as_nonnegative_int(raw.get("cache_write_input_tokens")),
            reasoning_tokens=as_nonnegative_int(raw.get("reasoning_output_tokens")),
            total_tokens=as_nonnegative_int(raw.get("total_tokens")),
        )

    def import_once(self) -> dict[str, int]:
        app_account, default_plan, active_until = self._read_auth_identity(
            self.codex_home / "auth.json"
        )
        alias_identity = self.resolver.resolve(self.alias, None)
        alias_account_hash = alias_identity.account_id_hash
        self._account_match = bool(
            app_account
            and alias_account_hash
            and short_hash(app_account) == alias_account_hash
        )
        if not self._account_match:
            raise ValueError("codex app account does not match configured alias")
        sessions = self.codex_home / "sessions"
        try:
            paths = sorted(
                sessions.rglob("*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True
            )[: self.max_files]
        except OSError:
            paths = []
        imported = 0
        quota_rows = 0
        for path in paths:
            try:
                if not path.is_file() or path.stat().st_size > MAX_CODEX_APP_JSONL_BYTES:
                    continue
            except OSError:
                continue
            imported_delta, quota_delta = self._import_file(
                path, alias_identity, default_plan, active_until
            )
            imported += imported_delta
            quota_rows += quota_delta
        return {
            "imported": imported,
            "quota_rows": quota_rows,
            "scanned_files": len(paths),
        }

    def _import_file(
        self,
        path: Path,
        identity: AccountIdentity,
        default_plan: str | None,
        active_until: str | None,
    ) -> tuple[int, int]:
        session_id: str | None = None
        model_provider: str | None = None
        model: str | None = None
        turn_id: str | None = None
        imported = 0
        quota_rows = 0
        record_index = 0
        resolved_path = path.resolve()
        try:
            stat = path.stat()
            state = self.repo.local_import_file_state(resolved_path) or {}
            unchanged = (
                int(state.get("size") or -1) == int(stat.st_size)
                and int(state.get("mtime_ns") or -1) == int(stat.st_mtime_ns)
                and int(state.get("offset") or -1) == int(stat.st_size)
            )
            if unchanged:
                return 0, 0
            can_resume = (
                state
                and int(state.get("offset") or 0) > 0
                and int(stat.st_size) >= int(state.get("offset") or 0)
                and int(state.get("size") or 0) <= int(stat.st_size)
            )
            start_offset = int(state.get("offset") or 0) if can_resume else 0
            if can_resume:
                session_id = safe_text(state.get("session_id"), 256)
                model_provider = safe_text(state.get("model_provider"), 64)
                model = safe_text(state.get("model"), 200)
                turn_id = safe_text(state.get("turn_id"), 256)
            handle = path.open("r", encoding="utf-8", errors="replace")
            if start_offset:
                handle.seek(start_offset)
        except OSError:
            return 0, 0
        with handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(record, Mapping):
                    continue
                record_type = record.get("type")
                payload = record.get("payload")
                if not isinstance(payload, Mapping):
                    continue
                if record_type == "session_meta":
                    session_id = safe_text(
                        payload.get("session_id") or payload.get("id"), 256
                    )
                    model_provider = safe_text(payload.get("model_provider"), 64)
                    continue
                if record_type == "turn_context":
                    model = safe_text(payload.get("model"), 200) or model
                    turn_id = safe_text(payload.get("turn_id"), 256) or turn_id
                    continue
                if record_type == "event_msg" and payload.get("type") == "task_started":
                    turn_id = safe_text(payload.get("turn_id"), 256) or turn_id
                    continue
                if record_type != "event_msg" or payload.get("type") != "token_count":
                    continue
                record_index += 1
                if (model_provider or "").lower() != "openai":
                    continue
                usage = self._usage_from_token_count(payload)
                if usage.missing:
                    continue
                timestamp = normalize_timestamp(record.get("timestamp"))
                key = identity_key(
                    identity.account_id_hash, self.alias, None, None, session_id
                )
                components = self.repo.price_components_for(model, usage)
                # The ordinal is stable in Codex JSONL.  Include a bounded
                # fallback index for older files that omit it.
                ordinal = record.get("ordinal")
                ordinal_key = str(ordinal) if ordinal is not None else f"line-{record_index}"
                import_key = "codex-app:" + (short_hash(
                    f"{resolved_path}\n{ordinal_key}\n{timestamp}"
                ) or short_hash(f"{resolved_path}\n{record_index}") or "unknown")
                event = UsageEvent(
                    ts=timestamp,
                    identity_key=key,
                    endpoint="local://chatgpt-codex",
                    method="LOCAL",
                    model=model,
                    status_code=200,
                    ok=1,
                    duration_ms=0,
                    stream=0,
                    session_id=session_id,
                    thread_id=session_id,
                    turn_id=turn_id,
                    installation_id=None,
                    window_id=None,
                    usage_alias=self.alias,
                    usage_project="ChatGPT Codex",
                    auth_fingerprint=None,
                    account_id_hash=identity.account_id_hash,
                    account_id_tail=identity.account_id_tail,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cached_tokens=usage.cached_tokens,
                    cache_write_tokens=usage.cache_write_tokens,
                    reasoning_tokens=usage.reasoning_tokens,
                    total_tokens=usage.total_tokens,
                    estimated_api_cost_usd=components.total_cost_usd if components else None,
                    non_cached_input_cost_usd=(
                        components.non_cached_input_cost_usd if components else None
                    ),
                    cached_input_cost_usd=(
                        components.cached_input_cost_usd if components else None
                    ),
                    output_cost_usd=components.output_cost_usd if components else None,
                    long_context_pricing_applied=int(
                        components.long_context_pricing_applied if components else False
                    ),
                    subscription_amortized_cost_usd=None,
                    api_equivalent_quota_usd=None,
                    usage_missing=0,
                    error_type=None,
                    error_message_redacted=None,
                    request_bytes=0,
                    response_bytes=0,
                    source="codex_app_local",
                    request_id=import_key,
                )
                if self.repo.record_imported_event(
                    event, import_key, "codex_app_local"
                ):
                    imported += 1
                rate_limits = payload.get("rate_limits")
                plan = (
                    safe_text(rate_limits.get("plan_type"), 64)
                    if isinstance(rate_limits, Mapping)
                    else None
                ) or default_plan
                # Quota snapshots have their own uniqueness key.  Re-reading
                # an unchanged JSONL line must not create a new snapshot row;
                # ``insert_subscription_quota_snapshot`` intentionally uses
                # INSERT OR IGNORE for this reason.
                for window in parse_codex_app_rate_windows(rate_limits, timestamp):
                    window.update(
                        {
                            "identity_key": key,
                            "account_id_hash": identity.account_id_hash,
                            "account_id_tail": identity.account_id_tail,
                            "usage_alias": self.alias,
                            "plan_type": plan,
                            "subscription_active_until": active_until,
                            "source": "codex_app_local",
                        }
                    )
                    self.repo.insert_subscription_quota_snapshot(window)
                    quota_rows += 1
            final_offset = handle.tell()
        try:
            final_stat = path.stat()
        except OSError:
            return imported, quota_rows
        self.repo.save_local_import_file_state(
            {
                "path": resolved_path,
                "size": final_stat.st_size,
                "mtime_ns": final_stat.st_mtime_ns,
                "offset": min(final_offset, final_stat.st_size),
                "session_id": session_id,
                "model_provider": model_provider,
                "model": model,
                "turn_id": turn_id,
            }
        )
        return imported, quota_rows


class CodexQuotaPoller:
    """Low-frequency, read-only Codex subscription quota snapshots via 8317."""

    def __init__(
        self,
        repo: UsageRepository,
        resolver: AccountResolver,
        upstream,
        *,
        key_loader,
        poll_seconds: float = DEFAULT_QUOTA_POLL_SECONDS,
        timeout: float = DEFAULT_QUOTA_POLL_TIMEOUT,
    ) -> None:
        self.repo = repo
        self.resolver = resolver
        self.upstream = upstream
        self.key_loader = key_loader
        self.poll_seconds = max(60.0, float(poll_seconds))
        self.timeout = max(3.0, float(timeout))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_poll_at: str | None = None
        self._last_success_at: str | None = None
        self._last_error_type: str | None = None
        self._account_count = 0
        self._window_count = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="cliproxy-codex-quota", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._thread = None

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.key_loader()),
            "last_poll_at": self._last_poll_at,
            "last_success_at": self._last_success_at,
            "last_error_type": self._last_error_type,
            "account_count": self._account_count,
            "window_count": self._window_count,
            "poll_seconds": self.poll_seconds,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            key = self.key_loader()
            if not key:
                self._stop.wait(30.0)
                continue
            try:
                accounts, windows = self.poll_once(key)
                self._last_poll_at = utc_now()
                self._last_success_at = self._last_poll_at
                self._last_error_type = None
                self._account_count = accounts
                self._window_count = windows
            except Exception as exc:
                self._last_poll_at = utc_now()
                self._last_error_type = type(exc).__name__
                LOG.warning("Codex quota snapshot failed: %s", type(exc).__name__)
            self._stop.wait(self.poll_seconds)

    def _management_request(
        self,
        key: str,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        port = self.upstream.port or (443 if self.upstream.scheme == "https" else 80)
        if self.upstream.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.upstream.hostname,
                port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(self.upstream.hostname, port, timeout=self.timeout)
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
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
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("management response too large")
            try:
                parsed = json.loads(raw) if raw else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
            return response.status, parsed
        finally:
            connection.close()

    def poll_once(self, key: str) -> tuple[int, int]:
        status, auth_payload = self._management_request(key, "GET", "/v0/management/auth-files")
        if status != 200 or not isinstance(auth_payload, Mapping):
            raise RuntimeError(f"auth_files_http_{status}")
        raw_files = auth_payload.get("files")
        files = raw_files if isinstance(raw_files, list) else []
        fetched_at = utc_now()
        account_count = 0
        window_count = 0
        seen_accounts: set[str] = set()
        for item in files:
            if not isinstance(item, Mapping):
                continue
            provider = safe_text(item.get("provider") or item.get("type"), 64)
            if not provider or provider.lower() != "codex" or item.get("disabled") is True:
                continue
            auth_index = safe_text(item.get("auth_index") or item.get("authIndex"), 512)
            claims = item.get("id_token") if isinstance(item.get("id_token"), Mapping) else {}
            account_id = safe_text(
                claims.get("chatgpt_account_id") or item.get("account"), 256
            )
            if not auth_index or not account_id or account_id in seen_accounts:
                continue
            seen_accounts.add(account_id)
            identity = self.resolver.resolve_account_id(account_id)
            headers = {
                "Authorization": "Bearer $TOKEN$",
                "Content-Type": "application/json",
                "User-Agent": "codex_cli_rs/0.76.0 (Darwin; arm64)",
                "Chatgpt-Account-Id": account_id,
            }
            call = {
                "auth_index": auth_index,
                "method": "GET",
                "url": CODEX_USAGE_URL,
                "header": headers,
            }
            outer_status, outer = self._management_request(
                key, "POST", "/v0/management/api-call", call
            )
            if outer_status != 200 or not isinstance(outer, Mapping):
                continue
            upstream_status = as_nonnegative_int(outer.get("status_code"))
            if upstream_status != 200:
                continue
            raw_body = outer.get("body")
            try:
                usage_payload = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
            except json.JSONDecodeError:
                continue
            if not isinstance(usage_payload, Mapping):
                continue
            plan = safe_text(
                usage_payload.get("plan_type")
                or usage_payload.get("planType")
                or claims.get("plan_type"),
                64,
            )
            active_until = claims.get("chatgpt_subscription_active_until")
            windows = parse_codex_quota_windows(usage_payload, fetched_at)
            if not windows:
                continue
            account_count += 1
            for window in windows:
                window.update(
                    {
                        "identity_key": identity_key(
                            identity.account_id_hash,
                            identity.usage_alias,
                            None,
                            None,
                            None,
                        ),
                        "account_id_hash": identity.account_id_hash,
                        "account_id_tail": identity.account_id_tail,
                        "usage_alias": identity.usage_alias,
                        "plan_type": plan,
                        "subscription_active_until": active_until,
                        "source": "cliproxy_wham_usage",
                    }
                )
                self.repo.insert_subscription_quota_snapshot(window)
                window_count += 1
        return account_count, window_count


class UsageQueuePoller:
    """Safely drain CLIProxyAPI's local management usage queue.

    The poller is opt-in: without a key file or explicitly named environment
    variable it does nothing.  Authentication failures are backed off instead
    of retried in a tight loop, which protects CLIProxyAPI's five-failure IP
    ban from being triggered by a misconfigured sidecar.
    """

    def __init__(
        self,
        repo: UsageRepository,
        resolver: AccountResolver,
        upstream,
        *,
        key_file: str | None = None,
        key_env: str = "CLIPROXY_MANAGEMENT_KEY",
        queue_path: str = DEFAULT_USAGE_QUEUE_PATH,
        count: int = DEFAULT_USAGE_QUEUE_COUNT,
        poll_seconds: float = DEFAULT_USAGE_QUEUE_POLL_SECONDS,
        timeout: float = 10.0,
    ) -> None:
        self.repo = repo
        self.resolver = resolver
        self.upstream = upstream
        self.key_file = Path(key_file).expanduser() if key_file else None
        self.key_env = safe_text(key_env, 128) if key_env is not None else "CLIPROXY_MANAGEMENT_KEY"
        self.queue_path = queue_path if queue_path.startswith("/") else "/" + queue_path
        self.count = max(1, min(int(count), 1000))
        self.poll_seconds = max(0.5, float(poll_seconds))
        self.timeout = max(1.0, float(timeout))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._warned_no_key = False
        self._warned_permissions = False
        self._backoff = self.poll_seconds
        self._last_status: int | None = None
        self._last_success_at: str | None = None
        self._last_error_type: str | None = None
        self._last_poll_at: str | None = None
        self._accepted = 0
        self._skipped = 0

    @property
    def configured(self) -> bool:
        return bool(self.key_file or (self.key_env and os.environ.get(self.key_env, "").strip()))

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="cliproxy-usage-queue", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._thread = None

    def status(self) -> dict[str, Any]:
        key_loaded = bool(self._load_key())
        env_configured = bool(self.key_env and os.environ.get(self.key_env, "").strip())
        configured = bool(self.key_file or env_configured)
        return {
            "enabled": key_loaded,
            "configured": configured,
            "key_source": "file" if self.key_file else ("env" if env_configured else "none"),
            "key_loaded": key_loaded,
            "last_status": self._last_status,
            "last_poll_at": self._last_poll_at,
            "last_success_at": self._last_success_at,
            "last_error_type": self._last_error_type,
            "accepted": self._accepted,
            "skipped": self._skipped,
            "backoff_seconds": self._backoff,
        }

    def _load_key(self) -> str | None:
        if self.key_file:
            try:
                file_stat = self.key_file.stat()
                mode = file_stat.st_mode & 0o777
                if mode & 0o077:
                    if not self._warned_permissions:
                        LOG.error("management key file must be owner-only (mode 600): %s", self.key_file)
                        self._warned_permissions = True
                    return None
                if file_stat.st_size > 4096:
                    return None
                with self.key_file.open("r", encoding="utf-8") as handle:
                    value = handle.read(4097).strip()
            except (OSError, UnicodeError):
                value = ""
            if value:
                return value if len(value) <= 4096 else None
        value = os.environ.get(self.key_env, "").strip() if self.key_env else ""
        return value if value and len(value) <= 4096 else None

    def _run(self) -> None:
        while not self._stop.is_set():
            key = self._load_key()
            if not key:
                if not self._warned_no_key:
                    LOG.info("usage queue poller idle: no management key file/environment configured")
                    self._warned_no_key = True
                self._stop.wait(30.0)
                continue
            self._warned_no_key = False
            try:
                status, body, retry_after = self._poll_once(key)
                self._last_status = status
                self._last_poll_at = utc_now()
                self._last_error_type = None if status == 200 else f"http_{status}"
                if status == 200:
                    self._last_success_at = self._last_poll_at
                    self._backoff = self.poll_seconds
                elif status in {401, 403}:
                    # 403 is also the response used during CLIProxyAPI's IP
                    # ban; use a long backoff and never inspect/log the body.
                    self._backoff = MAX_MANAGEMENT_BACKOFF_SECONDS if status == 403 else DEFAULT_MANAGEMENT_BACKOFF_SECONDS
                elif status == 429:
                    self._backoff = min(max(retry_after or DEFAULT_MANAGEMENT_BACKOFF_SECONDS, self.poll_seconds), MAX_MANAGEMENT_BACKOFF_SECONDS)
                else:
                    self._backoff = min(max(self._backoff * 2, self.poll_seconds), MAX_MANAGEMENT_BACKOFF_SECONDS)
            except Exception as exc:
                self._last_poll_at = utc_now()
                self._last_error_type = type(exc).__name__
                self._backoff = min(max(self._backoff * 2, 5.0), MAX_MANAGEMENT_BACKOFF_SECONDS)
                LOG.warning("usage queue poll failed: %s", type(exc).__name__)
            self._stop.wait(self._backoff)

    def _poll_once(self, key: str) -> tuple[int, bytes, float | None]:
        parsed = self.upstream
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection: http.client.HTTPConnection
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                parsed.hostname, port, timeout=self.timeout, context=ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(parsed.hostname, port, timeout=self.timeout)
        target = self.queue_path + f"?count={self.count}"
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            body = response.read(4 * 1024 * 1024 + 1)
            status = response.status
            retry_after = None
            raw_retry = response.getheader("Retry-After")
            if raw_retry:
                try:
                    retry_after = float(raw_retry)
                except ValueError:
                    retry_after = None
            if status == 200:
                self._consume(body)
            return status, body, retry_after
        finally:
            connection.close()

    def _consume(self, body: bytes) -> None:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            LOG.warning("usage queue returned invalid JSON; records skipped")
            return
        if not isinstance(payload, list):
            LOG.warning("usage queue returned a non-array payload; records skipped")
            return
        accepted = 0
        skipped = 0
        for item in payload:
            converted = queue_record_event(item, self.resolver, self.repo) if isinstance(item, Mapping) else None
            if converted is None:
                skipped += 1
                continue
            event, info = converted
            try:
                self.repo.record_event(event, info, source="usage_queue")
                accepted += 1
            except Exception as exc:
                skipped += 1
                LOG.error("usage queue event persistence failed: %s", type(exc).__name__)
        if accepted or skipped:
            self._accepted += accepted
            self._skipped += skipped
            LOG.info("usage queue drained: accepted=%d skipped=%d", accepted, skipped)


def display_identity(row: Mapping[str, Any]) -> str:
    if row.get("usage_alias"):
        return str(row["usage_alias"])
    if row.get("account_id_tail"):
        return f"account …{row['account_id_tail']}"
    if row.get("account_id_hash"):
        return f"account {row['account_id_hash']}"
    if row.get("auth_fingerprint"):
        return f"auth {row['auth_fingerprint']}"
    return str(row.get("identity_key") or "unknown")


def identity_badge(row: Mapping[str, Any]) -> tuple[str, str]:
    """Return a meaningful one-letter account class for the dashboard.

    C means the account is attached to a named local ``codex-N`` home/alias.
    A means it is only identified from an auth/account mapping (anonymous
    fallback or queue-derived identity), so it has no stable local alias.
    """

    alias = safe_text(row.get("usage_alias"), 128) or ""
    if re.fullmatch(r"codex-\d+", alias, re.IGNORECASE):
        return "C", "C = Codex alias（已映射本机 CODEX_HOME）"
    return "A", "A = Auth account（仅凭账号身份识别，未绑定本机 alias）"


def fmt_money(value: Any) -> str:
    if value is None:
        return "—"
    number = float(value)
    return f"${number:,.2f}" if abs(number) >= 0.01 else f"${number:,.6f}"


def fmt_rate_per_million(cost: Any, tokens: Any) -> str:
    token_count = int(tokens or 0)
    if cost is None or token_count <= 0:
        return "—"
    rate = float(cost) * 1_000_000 / token_count
    return f"${rate:,.4f}/M" if abs(rate) < 0.1 else f"${rate:,.2f}/M"


def fmt_int(value: Any) -> str:
    return f"{int(value or 0):,}"


def fmt_compact(value: Any) -> str:
    number = float(value or 0)
    for divisor, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if abs(number) >= divisor:
            return f"{number / divisor:.2f}{suffix}"
    return f"{int(number):,}"


def fmt_percent(value: Any) -> str:
    if value is None:
        return "待获取"
    number = float(value)
    return f"{number:.0f}%" if number.is_integer() else f"{number:.1f}%"


def fmt_ratio(numerator: Any, denominator: Any) -> str:
    total = int(denominator or 0)
    if total <= 0:
        return "—"
    return f"{int(numerator or 0) / total * 100:.1f}%"


def fmt_local_time(value: Any) -> str:
    text = safe_text(value, 128)
    if not text:
        return "—"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone().strftime("%m-%d %H:%M")


def token_mix_html(summary: Mapping[str, Any]) -> str:
    components = [
        (
            "非缓存输入",
            int(summary.get("non_cached_input_tokens") or 0),
            summary.get("non_cached_input_cost_usd"),
            "cyan",
        ),
        (
            "缓存输入",
            int(summary.get("cached_tokens") or 0),
            summary.get("cached_input_cost_usd"),
            "violet",
        ),
        (
            "输出",
            int(summary.get("output_tokens") or 0),
            summary.get("output_cost_usd"),
            "amber",
        ),
    ]
    denominator = sum(value for _, value, _, _ in components) or 1
    bars = "".join(
        f'<span class="mix-segment {tone}" style="width:{value / denominator * 100:.4f}%"></span>'
        for _, value, _, tone in components
        if value
    )
    legend = "".join(
        f'<div class="mix-item"><i class="dot {tone}"></i><span>{html.escape(label)}</span>'
        f'<strong>{fmt_compact(value)} · {fmt_money(cost)}</strong></div>'
        for label, value, cost, tone in components
    )
    reasoning = fmt_compact(summary.get("reasoning_tokens"))
    return (
        f'<div class="mix-bar">{bars}</div><div class="mix-legend">{legend}'
        f'<div class="mix-item"><i class="dot mint"></i><span>推理（输出子集）</span><strong>{reasoning}</strong></div>'
        "</div>"
    )


def period_card_html(label: str, data: Mapping[str, Any]) -> str:
    return (
        '<article class="period-card">'
        '<div class="period-head"><div>'
        f'<span>{html.escape(label)}</span>'
        f'<strong>{fmt_compact(data.get("codex_status_tokens"))} tokens</strong>'
        '</div>'
        f'<em>{fmt_money(data.get("split_cost_total_usd"))}</em></div>'
        '<div class="period-meta">'
        f'<span>非缓存输入：{fmt_int(data.get("non_cached_input_tokens"))} · '
        f'{fmt_money(data.get("non_cached_input_cost_usd"))}</span>'
        f'<span>输出：{fmt_int(data.get("output_tokens"))} · '
        f'{fmt_money(data.get("output_cost_usd"))}</span>'
        f'<span>缓存输入：{fmt_int(data.get("cached_tokens"))} · '
        f'{fmt_money(data.get("cached_input_cost_usd"))}</span>'
        f'<span>API 原始处理：{fmt_int(data.get("api_processed_tokens"))}</span>'
        f'<span>缓存命中率：{fmt_percent(data.get("cache_hit_rate_percent"))}</span>'
        f'<span>逻辑请求/账号调用：{fmt_int(data.get("logical_requests"))}/'
        f'{fmt_int(data.get("account_attempts"))}</span>'
        f'<span>失败调用：{fmt_int(data.get("failed_attempts"))}</span>'
        '</div>'
        f'{token_mix_html(data)}'
        '</article>'
    )


def window_meter_html(window: Mapping[str, Any] | None, label: str) -> str:
    if not window:
        return (
            f'<div class="quota-row muted-row"><div><b>{html.escape(label)}</b>'
            '<span>尚未获取窗口数据</span></div><strong>—</strong></div>'
        )
    remaining = window.get("remaining_percent")
    pct = min(max(float(remaining), 0.0), 100.0) if remaining is not None else 0.0
    used = window.get("used_percent")
    tone = "critical" if pct <= 10 else ("warning" if pct <= 30 else "healthy")
    reset = fmt_local_time(window.get("reset_at"))
    return (
        f'<div class="quota-row"><div class="quota-copy"><div><b>{html.escape(label)}</b>'
        f'<span>已用 {fmt_percent(used)} · 剩余 {fmt_percent(remaining)} · {html.escape(reset)} 重置</span></div>'
        f'<strong class="{tone}">{fmt_percent(remaining)}</strong></div>'
        f'<div class="meter"><span class="{tone}" style="width:{pct:.2f}%"></span></div></div>'
    )


def html_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    head = "".join(f"<th>{html.escape(str(item))}</th>" for item in headers)
    body_rows = []
    for row in rows:
        body_rows.append("<tr>" + "".join(f"<td>{html.escape(str(item if item is not None else '—'))}</td>" for item in row) + "</tr>")
    body = "".join(body_rows) or f'<tr><td colspan="{len(headers)}" class="empty">No data yet</td></tr>'
    return f"<div class=table-wrap><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def dashboard_html(
    repo: UsageRepository,
    queue_status: Mapping[str, Any] | None = None,
    quota_status: Mapping[str, Any] | None = None,
    codex_app_status: Mapping[str, Any] | None = None,
    account_resolver: AccountResolver | None = None,
) -> str:
    today = repo.token_breakdown("today")
    week = repo.token_breakdown("7d")
    all_time = repo.token_breakdown("all")
    daily = repo.daily_usage(7)
    subscriptions = repo.subscription_dashboard_rows()
    persisted_quota_accounts = sum(1 for row in subscriptions if row.get("windows"))
    models = repo.grouped("7d", "model")
    recent = repo.recent(50)
    coverage = repo.coverage()
    price_sync = repo.price_sync_status()
    queue_status = queue_status or {}
    quota_status = quota_status or {}
    codex_app_status = codex_app_status or {}

    hero_metrics = "".join(
        f'<article class="hero-card {tone}"><span>{html.escape(label)}</span>'
        f'<strong>{html.escape(value)}</strong><small>{html.escape(note)}</small></article>'
        for label, value, note, tone in (
            (
                "非缓存输入 Tokens",
                fmt_compact(all_time["non_cached_input_tokens"]),
                f"输入成本 {fmt_money(all_time['non_cached_input_cost_usd'])} · "
                f"有效 {fmt_rate_per_million(all_time['non_cached_input_cost_usd'], all_time['non_cached_input_tokens'])} · "
                f"{fmt_int(all_time['non_cached_input_tokens'])}",
                "cyan-card",
            ),
            (
                "输出 Tokens",
                fmt_compact(all_time["output_tokens"]),
                f"输出成本 {fmt_money(all_time['output_cost_usd'])} · "
                f"有效 {fmt_rate_per_million(all_time['output_cost_usd'], all_time['output_tokens'])} · "
                f"{fmt_int(all_time['output_tokens'])}",
                "output-card",
            ),
            (
                "缓存命中 Tokens",
                fmt_compact(all_time["cached_tokens"]),
                f"缓存成本 {fmt_money(all_time['cached_input_cost_usd'])} · "
                f"有效 {fmt_rate_per_million(all_time['cached_input_cost_usd'], all_time['cached_tokens'])} · "
                f"命中率 {fmt_percent(all_time['cache_hit_rate_percent'])}",
                "mint-card",
            ),
            (
                "API 原始处理量",
                fmt_compact(all_time["api_processed_tokens"]),
                "输入（含缓存）+ 输出 · 用于吞吐与计费",
                "blue-card",
            ),
            (
                "API 等价成本",
                fmt_money(all_time["estimated_api_cost_usd"]),
                "非缓存输入 + 缓存输入 + 输出 · 按官方单价",
                "violet-card",
            ),
            (
                "逻辑请求",
                fmt_int(all_time["logical_requests"]),
                f"账号调用 {fmt_int(all_time['account_attempts'])} · 额外调用 {fmt_int(all_time['retry_attempts'])}",
                "amber-card",
            ),
        )
    )

    period_cards = "".join(
        period_card_html(label, data)
        for label, data in (("今天", today), ("近 7 天", week), ("全部记录", all_time))
    )

    max_tokens = max((int(row["codex_status_tokens"] or 0) for row in daily), default=0) or 1
    trend_bars = "".join(
        f'<div class="trend-column"><div class="bar-tooltip">实际消耗 {fmt_int(row["codex_status_tokens"])}<br>'
        f'非缓存输入 {fmt_int(row["non_cached_input_tokens"])}<br>'
        f'输出 {fmt_int(row["output_tokens"])}<br>'
        f'缓存命中 {fmt_int(row["cached_tokens"])}<br>'
        f'原始处理 {fmt_int(row["api_processed_tokens"])}<br>'
        f'{fmt_money(row["estimated_api_cost_usd"])}</div><div class="trend-track">'
        f'<span style="height:{max(3.0, int(row["codex_status_tokens"] or 0) / max_tokens * 100):.2f}%"></span></div>'
        f'<b>{html.escape(row["date"][5:])}</b><small>{fmt_compact(row["codex_status_tokens"])}</small></div>'
        for row in daily
    )

    subscription_cards: list[str] = []
    for row in subscriptions:
        windows = row.get("windows") or {}
        weekly = windows.get("weekly") or windows.get("monthly")
        five_hour = windows.get("five_hour")
        full_quota = row.get("current_window_full_quota_usd")
        floor = row.get("current_cycle_floor_usd")
        badge, badge_title = identity_badge(row)
        quota_text = (
            fmt_money(full_quota)
            if full_quota is not None else "观测中"
        )
        quota_note = (
            f"{row.get('quota_estimate_method') or '历史事件'} · "
            f"{row.get('quota_estimate_confidence') or 'unknown'}"
            if full_quota is not None else f"当前已观测 ≥ {fmt_money(floor)} · 低置信度"
        )
        alias = display_identity(row)
        plan = str(row.get("plan_type") or "unknown").upper()
        status_text = "实时额度" if row.get("fetched_at") else "等待额度快照"
        account_email: str | None = None
        if account_resolver is not None:
            identity = account_resolver.resolve_account_hash(row.get("account_id_hash"))
            if not identity.account_email and row.get("usage_alias"):
                identity = account_resolver.resolve(str(row["usage_alias"]), None)
            account_email = identity.account_email
        account_email_html = (
            f'<span class="account-email">{html.escape(account_email)}</span>'
            if account_email else '<span class="account-email unavailable">邮箱未获取</span>'
        )
        quota_label = (
            "上周期满额 API 等价参考"
            if row.get("quota_estimate_method") == "previous_window_transfer"
            and float(row.get("quota_used_percent") or 0.0) == 0.0
            else "API 等价额度估算"
        )
        subscription_cards.append(
            f'<article class="subscription-card"><div class="account-head"><div class="avatar" title="{html.escape(badge_title)}">{badge}</div>'
            f'<div class="account-copy"><h3>{html.escape(alias)}</h3>{account_email_html}'
            f'<span class="account-meta">{html.escape(plan)} · …{html.escape(str(row.get("account_id_tail") or "未知"))} · {html.escape(badge_title)}</span></div>'
            f'<i>{html.escape(status_text)}</i></div>'
            f'{window_meter_html(five_hour, "5 小时额度")}{window_meter_html(weekly, "周额度" if not windows.get("monthly") else "月额度")}'
            f'<div class="account-usage"><span>总调用 <b>{fmt_int(row.get("all_time_account_attempts"))}</b></span>'
            f'<span class="account-success">成功 <b>{fmt_int(row.get("all_time_successful_calls"))}</b></span>'
            f'<span class="account-failure">失败 <b>{fmt_int(row.get("all_time_failed_calls"))}</b></span>'
            f'<span>非缓存输入 <b>{fmt_compact(row.get("all_time_non_cached_input_tokens"))}</b></span>'
            f'<span>输出 <b>{fmt_compact(row.get("all_time_output_tokens"))}</b></span>'
            f'<span>额外调用 <b>{fmt_int(row.get("all_time_extra_calls"))}</b></span></div>'
            f'<div class="quota-value"><div><span>{html.escape(quota_label)}</span><strong>{quota_text}</strong></div>'
            f'<small>{html.escape(quota_note)}<br>累计消费 {fmt_money(row.get("all_time_cost_usd"))}</small></div></article>'
        )
    subscriptions_html = "".join(subscription_cards) or (
        '<div class="empty-state">额度快照尚未就绪。collector 会低频、安全地从 8317 获取。</div>'
    )

    model_rows = "".join(
        f'<tr><td><b>{html.escape(str(row["model"]))}</b></td><td>{fmt_int(row["logical_requests"])}</td>'
        f'<td>{fmt_int(row["account_attempts"])}</td><td>{fmt_int(row["non_cached_input_tokens"])}</td>'
        f'<td>{fmt_int(row["output_tokens"])}</td><td>{fmt_int(row["cached_tokens"])}</td>'
        f'<td>{fmt_int(row["long_context_priced_calls"])}</td>'
        f'<td>{fmt_money(row["non_cached_input_cost_usd"])}</td>'
        f'<td>{fmt_money(row["output_cost_usd"])}</td>'
        f'<td>{fmt_money(row["cached_input_cost_usd"])}</td>'
        f'<td>{fmt_money(row["estimated_api_cost_usd"])}</td></tr>'
        for row in models
    ) or '<tr><td colspan="11" class="empty">暂无数据</td></tr>'
    account_rows = "".join(
        f'<tr><td><b>{html.escape(display_identity(row))}</b></td>'
        f'<td>{fmt_int(row.get("all_time_logical_requests"))}</td>'
        f'<td>{fmt_int(row.get("all_time_account_attempts"))}</td>'
        f'<td>{fmt_int(row.get("all_time_non_cached_input_tokens"))}</td>'
        f'<td>{fmt_int(row.get("all_time_output_tokens"))}</td>'
        f'<td>{fmt_int(row.get("all_time_cached_tokens"))}</td>'
        f'<td>{fmt_money(row.get("all_time_non_cached_input_cost_usd"))}</td>'
        f'<td>{fmt_money(row.get("all_time_output_cost_usd"))}</td>'
        f'<td>{fmt_money(row.get("all_time_cached_input_cost_usd"))}</td>'
        f'<td>{fmt_money(row.get("all_time_cost_usd"))}</td></tr>'
        for row in subscriptions
    ) or '<tr><td colspan="10" class="empty">暂无数据</td></tr>'
    def _status_class(row: Mapping[str, Any]) -> str:
        return "ok" if row.get("ok") else "bad"

    recent_rows = "".join(
        f'<tr><td>{html.escape(fmt_local_time(row["ts"]))}</td><td>{html.escape(display_identity(row))}</td>'
        f'<td>{html.escape(str(row["model"] or "—"))}</td><td><span class="status-pill {_status_class(row)}">{row["status_code"]}</span></td>'
        f'<td>{fmt_int(max(int(row["input_tokens"] or 0) - int(row["cached_tokens"] or 0), 0))}</td>'
        f'<td>{fmt_int(row["output_tokens"])}</td><td>{fmt_int(row["cached_tokens"])}</td>'
        f'<td>{"长上下文" if row.get("long_context_pricing_applied") else "短上下文"}</td>'
        f'<td>{fmt_money(row["non_cached_input_cost_usd"])}</td>'
        f'<td>{fmt_money(row["output_cost_usd"])}</td>'
        f'<td>{fmt_money(row["cached_input_cost_usd"])}</td>'
        f'<td>{fmt_money(row["estimated_api_cost_usd"])}</td></tr>'
        for row in recent
    ) or '<tr><td colspan="12" class="empty">暂无数据</td></tr>'

    session_notice = (
        '<div class="notice warning-notice"><b>当前不能按 Codex session 精确拆分</b>'
        f'<span>8317 queue 的 session_id 覆盖 {fmt_ratio(coverage.get("session_identified_attempts"), coverage.get("account_attempts"))}。'
        '本页是全部账号与全部 session 的采集总计，不能直接与某个 tmux /status 做同范围比较；'
        '“实际消耗”只统一了 token 算法（非缓存输入 + 输出）。</span></div>'
        if int(coverage.get("session_identified_attempts") or 0) < int(coverage.get("account_attempts") or 0)
        else ""
    )

    collector_ok = queue_status.get("key_loaded") and queue_status.get("last_status") == 200
    quota_ok = quota_status.get("last_success_at") is not None or persisted_quota_accounts > 0
    codex_app_ok = codex_app_status.get("last_success_at") is not None
    price_ok = price_sync.get("status") == "ok"
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30"><title>Usage Observatory</title>
<script>(()=>{{try{{const t=localStorage.getItem('cliproxy-usage-theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}}catch(e){{}}}})()</script>
<style>
:root{{--paper:#fff4dd;--ink:#26201a;--ink-2:#5c5347;--ink-3:#877b6b;--card:#fffdf7;--sun:#ffd84d;--rose:#ffb9cc;--sky:#a5dcff;--mint:#a8edc4;--orange:#ff6b3d;--lavender:#cabdff;--cream:#f1e3c4;--watch:#fff0bd;--shadow-ink:#26201a;--dot:rgba(38,32,26,.08);--on-color:#26201a;--border:2px solid var(--ink);--shadow:5px 5px 0 var(--shadow-ink);--shadow-sm:3px 3px 0 var(--shadow-ink);--radius:14px;--font-display:"Arial Rounded MT Bold",ui-rounded,system-ui,-apple-system,sans-serif;--font-body:system-ui,-apple-system,"Segoe UI",sans-serif;--font-mono:ui-monospace,"SF Mono",Menlo,monospace}}
:root[data-theme="dark"]{{--paper:#211d19;--ink:#f5ead9;--ink-2:#c8baa8;--ink-3:#a69784;--card:#302a24;--sun:#e1bd45;--rose:#ce839a;--sky:#75b5dc;--mint:#78c899;--orange:#e9613b;--lavender:#a395da;--cream:#44392c;--watch:#3f351f;--shadow-ink:#080706;--dot:rgba(245,234,217,.07);--on-color:#211d19}}
*{{box-sizing:border-box}}html{{color-scheme:light}}:root[data-theme="dark"]{{color-scheme:dark}}body{{margin:0;min-width:0;min-height:100vh;color:var(--ink);font:14px/1.48 var(--font-body);background-color:var(--paper);background-image:radial-gradient(var(--dot) 1px,transparent 1px);background-size:22px 22px;overflow-x:hidden}}button{{font:inherit}}main{{width:100%;max-width:1440px;margin:auto;padding:40px 30px 74px}}
header{{display:flex;min-width:0;align-items:center;justify-content:space-between;gap:22px;margin-bottom:30px}}.brand-lockup{{display:flex;min-width:0;align-items:center;gap:15px}}.brand-lockup>div:last-child{{min-width:0}}.brand-mark{{display:grid;place-items:center;width:54px;height:54px;flex:0 0 auto;border:var(--border);border-radius:50%;background:var(--orange);color:var(--on-color);box-shadow:var(--shadow-sm);font:900 16px/1 var(--font-display);transform:rotate(-4deg)}}.eyebrow{{color:var(--ink-3);font:700 10px/1.2 var(--font-mono);letter-spacing:.14em;text-transform:uppercase}}h1{{font:900 clamp(32px,4vw,54px)/.95 var(--font-display);margin:5px 0 7px;letter-spacing:-.035em;overflow-wrap:anywhere}}.subtitle{{max-width:780px;color:var(--ink-2);overflow-wrap:anywhere}}.header-actions{{display:flex;flex:0 0 auto;align-items:center;gap:12px}}.live,.theme-toggle{{border:var(--border);background:var(--card);color:var(--ink);box-shadow:var(--shadow-sm)}}.live{{display:flex;align-items:center;gap:8px;padding:9px 13px;border-radius:999px;font:800 11px/1 var(--font-mono);white-space:nowrap}}.live:before{{content:"";width:9px;height:9px;border:1.5px solid var(--ink);border-radius:50%;background:var(--mint)}}.theme-toggle{{display:grid;place-items:center;width:39px;height:39px;border-radius:50%;cursor:pointer;transition:.12s transform,.12s box-shadow}}.theme-toggle:hover{{transform:translate(-1px,-1px);box-shadow:4px 4px 0 var(--shadow-ink)}}.theme-toggle:active{{transform:translate(2px,2px);box-shadow:none}}.theme-toggle svg{{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round}}.theme-icon-sun{{display:none}}:root[data-theme="dark"] .theme-icon-moon{{display:none}}:root[data-theme="dark"] .theme-icon-sun{{display:block}}
.hero-grid{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:15px}}.hero-grid>*,.period-grid>*,.subscription-grid>*,.two-col>*{{min-width:0}}.hero-card,.period-card,.subscription-card,.panel{{position:relative;min-width:0;border:var(--border);border-radius:var(--radius);box-shadow:var(--shadow);background:var(--card);overflow:hidden}}.hero-card{{min-height:164px;padding:21px;color:var(--on-color);transition:.14s transform,.14s box-shadow}}.hero-card:hover,.period-card:hover,.subscription-card:hover{{transform:translate(-2px,-2px);box-shadow:7px 7px 0 var(--shadow-ink)}}.hero-card.cyan-card{{background:var(--sun)}}.hero-card.output-card{{background:var(--orange)}}.hero-card.mint-card{{background:var(--mint)}}.hero-card.blue-card{{background:var(--sky)}}.hero-card.violet-card{{background:var(--rose)}}.hero-card.amber-card{{background:var(--lavender)}}.hero-card span,.period-head span,.quota-value span{{font:800 10px/1.2 var(--font-mono);letter-spacing:.09em;text-transform:uppercase}}.hero-card span{{opacity:.68}}.hero-card strong{{display:block;margin:18px 0 9px;font:900 clamp(27px,2.7vw,42px)/1 var(--font-display);letter-spacing:-.035em}}.hero-card small{{display:block;opacity:.72;font-size:10px}}
.notice{{display:flex;gap:12px;align-items:flex-start;margin:18px 0 0;padding:13px 15px;border:var(--border);border-radius:12px;background:var(--watch);box-shadow:var(--shadow-sm)}}.notice b{{white-space:nowrap;font-family:var(--font-display)}}.notice span{{color:var(--ink-2);font-size:12px}}.notice:before{{content:"!";display:grid;place-items:center;width:21px;height:21px;flex:0 0 auto;border:1.5px solid var(--ink);border-radius:50%;background:var(--orange);color:var(--on-color);font-weight:900}}
.app-import-notice{{background:color-mix(in srgb,var(--mint) 36%,var(--card))}}.app-import-notice:before{{content:"✓";background:var(--mint)}}.manual-import{{margin-top:15px;border:var(--border);border-radius:12px;background:var(--card);box-shadow:var(--shadow-sm);overflow:hidden}}.manual-import summary{{padding:13px 15px;cursor:pointer;font-family:var(--font-display)}}.manual-import summary span{{margin-left:8px;color:var(--ink-3);font:600 10px/1.2 var(--font-mono)}}.manual-import form{{padding:16px;border-top:1.5px solid var(--ink)}}.form-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}.manual-import label{{display:grid;gap:5px;color:var(--ink-2);font:700 10px/1.2 var(--font-mono)}}.manual-import input{{min-width:0;padding:9px 10px;border:1.5px solid var(--ink);border-radius:8px;background:var(--paper);color:var(--ink);font:600 12px/1.2 var(--font-mono)}}.note-label{{margin-top:12px}}.manual-import button{{margin-top:12px;padding:9px 14px;border:var(--border);border-radius:9px;background:var(--orange);color:var(--on-color);box-shadow:var(--shadow-sm);font-weight:900;cursor:pointer}}.manual-import p{{margin:11px 0 0;color:var(--ink-3);font-size:11px}}
.section-title{{display:flex;justify-content:space-between;align-items:end;margin:38px 0 14px}}.section-title h2{{margin:0;font:900 22px/1.1 var(--font-display);letter-spacing:-.015em}}.section-title p{{margin:5px 0 0;color:var(--ink-2)}}.section-title small{{color:var(--ink-3);font-family:var(--font-mono)}}.period-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px}}.period-card{{padding:20px;transition:.14s transform,.14s box-shadow}}.period-card:nth-child(1) .period-head span{{background:var(--sun)}}.period-card:nth-child(2) .period-head span{{background:var(--rose)}}.period-card:nth-child(3) .period-head span{{background:var(--sky)}}.period-head{{display:flex;min-width:0;align-items:end;justify-content:space-between;gap:14px}}.period-head>div{{min-width:0}}.period-head span{{display:inline-block;padding:5px 7px;border:1.5px solid var(--ink);border-radius:7px;color:var(--on-color)}}.period-head strong{{display:block;margin-top:9px;font:900 25px/1 var(--font-display);overflow-wrap:anywhere}}.period-head em{{flex:0 0 auto;font:900 20px/1 var(--font-display);font-style:normal;color:var(--ink)}}.period-meta{{display:flex;flex-wrap:wrap;gap:6px 8px;margin-top:14px;color:var(--ink-3);font:600 9px/1.3 var(--font-mono)}}.period-meta span{{max-width:100%;padding:4px 6px;border:1px solid color-mix(in srgb,var(--ink) 38%,transparent);border-radius:6px;background:var(--paper);overflow-wrap:anywhere}}.mix-bar{{display:flex;height:11px;margin:16px 0 14px;border:1.5px solid var(--ink);border-radius:999px;overflow:hidden;background:var(--cream)}}.mix-segment.cyan,.dot.cyan{{background:var(--sky)}}.mix-segment.violet,.dot.violet{{background:var(--lavender)}}.mix-segment.amber,.dot.amber{{background:var(--orange)}}.dot.mint{{background:var(--mint)}}.mix-legend{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:9px 18px}}.mix-item{{display:grid;min-width:0;grid-template-columns:9px minmax(0,1fr) auto;align-items:center;gap:7px;color:var(--ink-2);font-size:11px}}.mix-item span{{min-width:0;overflow-wrap:anywhere}}.mix-item strong{{color:var(--ink);font-family:var(--font-mono)}}.dot{{width:8px;height:8px;border:1px solid var(--ink);border-radius:3px}}
.trend-panel{{padding:22px 22px 17px;background-color:var(--card);background-image:radial-gradient(var(--dot) 1px,transparent 1px);background-size:16px 16px}}.trend{{height:230px;display:grid;grid-template-columns:repeat(7,1fr);gap:14px;align-items:end;padding-top:24px}}.trend-column{{position:relative;display:grid;grid-template-rows:160px auto auto;text-align:center;gap:5px;min-width:0}}.trend-track{{height:160px;display:flex;align-items:end;border:1.5px solid var(--ink);border-radius:9px;background:var(--cream);overflow:hidden}}.trend-track span{{width:100%;min-height:3px;border-top:1.5px solid var(--ink);background:var(--orange)}}.trend-column:nth-child(3n+2) .trend-track span{{background:var(--sun)}}.trend-column:nth-child(3n+3) .trend-track span{{background:var(--sky)}}.trend-column b{{font:700 10px/1 var(--font-mono);color:var(--ink-3)}}.trend-column small{{font:900 11px/1 var(--font-mono)}}.bar-tooltip{{position:absolute;z-index:3;bottom:190px;left:50%;transform:translate(-50%,8px);opacity:0;pointer-events:none;white-space:nowrap;padding:8px 10px;border:var(--border);border-radius:8px;background:var(--card);box-shadow:var(--shadow-sm);font:700 10px/1.45 var(--font-mono);transition:.16s}}.trend-column:hover .bar-tooltip{{opacity:1;transform:translate(-50%,0)}}
.subscription-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(310px,100%),1fr));gap:15px}}.subscription-card{{padding:18px;transition:.14s transform,.14s box-shadow}}.subscription-card:nth-child(4n+1){{border-top:8px solid var(--sun)}}.subscription-card:nth-child(4n+2){{border-top:8px solid var(--rose)}}.subscription-card:nth-child(4n+3){{border-top:8px solid var(--sky)}}.subscription-card:nth-child(4n+4){{border-top:8px solid var(--mint)}}.account-head{{display:grid;min-width:0;grid-template-columns:44px minmax(0,1fr) auto;gap:11px;align-items:center;margin-bottom:18px}}.account-copy{{min-width:0}}.avatar{{display:grid;place-items:center;width:42px;height:42px;border:var(--border);border-radius:50%;background:var(--sun);box-shadow:var(--shadow-sm);color:var(--on-color);font:900 18px/1 var(--font-display)}}.subscription-card:nth-child(4n+2) .avatar{{background:var(--rose)}}.subscription-card:nth-child(4n+3) .avatar{{background:var(--sky)}}.subscription-card:nth-child(4n+4) .avatar{{background:var(--mint)}}.account-head h3{{margin:0;font:900 17px/1.1 var(--font-display);overflow-wrap:anywhere}}.account-head span{{display:block;overflow-wrap:anywhere}}.account-head .account-email{{margin-top:4px;color:var(--ink-2);font:700 10px/1.3 var(--font-mono)}}.account-head .account-email.unavailable{{color:var(--ink-3);font-weight:600}}.account-head .account-meta{{margin-top:3px;color:var(--ink-3);font:600 9px/1.3 var(--font-mono)}}.account-head i{{padding:5px 7px;border:1.5px solid var(--ink);border-radius:999px;background:var(--mint);color:var(--on-color);font:800 9px/1 var(--font-mono);font-style:normal}}.quota-row{{margin:14px 0}}.quota-copy{{display:flex;justify-content:space-between;align-items:end}}.quota-copy b{{display:block;font-size:12px}}.quota-copy span,.muted-row span{{display:block;margin-top:2px;color:var(--ink-3);font:600 9px/1.3 var(--font-mono)}}.quota-copy strong{{font:900 17px/1 var(--font-display)}}.healthy{{color:#18824c}}.warning{{color:#b06b00}}.critical{{color:#d6324f}}:root[data-theme="dark"] .healthy{{color:#8ce7af}}:root[data-theme="dark"] .warning{{color:#ffd36b}}:root[data-theme="dark"] .critical{{color:#ff91a3}}.meter{{height:10px;margin-top:8px;border:1.5px solid var(--ink);border-radius:999px;background:var(--cream);overflow:hidden}}.meter span{{display:block;height:100%;border-right:1.5px solid var(--ink);background:currentColor}}.muted-row{{display:flex;justify-content:space-between;color:var(--ink-3)}}.account-usage{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin:15px 0 5px}}.account-usage span{{min-width:0;padding:8px;border:1.5px solid var(--ink);border-radius:8px;background:var(--paper);color:var(--ink-3);font:700 8px/1.3 var(--font-mono);overflow-wrap:anywhere}}.account-usage b{{display:block;margin-top:3px;color:var(--ink);font-size:11px}}.quota-value{{display:flex;justify-content:space-between;align-items:end;margin-top:14px;padding-top:15px;border-top:2px solid var(--ink)}}.quota-value span{{color:var(--ink-3)}}.quota-value strong{{display:block;margin-top:5px;font:900 22px/1 var(--font-display)}}.quota-value small{{text-align:right;color:var(--ink-3);font:600 9px/1.4 var(--font-mono)}}
.two-col{{display:grid;grid-template-columns:1fr 1.2fr;gap:15px}}.panel{{padding:0}}.panel h3{{margin:0;padding:15px 18px;border-bottom:2px solid var(--ink);background:var(--sun);color:var(--on-color);font:900 15px/1 var(--font-display)}}.two-col .panel:nth-child(2) h3{{background:var(--sky)}}.table-wrap{{overflow:auto;max-height:520px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px 14px;text-align:left;border-bottom:1.5px solid color-mix(in srgb,var(--ink) 48%,transparent);white-space:nowrap}}th{{position:sticky;top:0;z-index:2;background:var(--cream);color:var(--ink-2);font:800 9px/1.2 var(--font-mono);letter-spacing:.06em;text-transform:uppercase}}tbody tr:nth-child(even){{background:color-mix(in srgb,var(--sky) 12%,var(--card))}}tr:last-child td{{border-bottom:0}}.status-pill{{display:inline-block;min-width:42px;padding:3px 7px;border:1.5px solid var(--ink);border-radius:999px;text-align:center;color:var(--on-color);font:900 9px/1 var(--font-mono)}}.status-pill.ok{{background:var(--mint)}}.status-pill.bad{{background:var(--rose)}}.empty,.empty-state{{padding:25px;text-align:center;color:var(--ink-3)}}
.system-strip{{display:flex;flex-wrap:wrap;gap:9px;margin-top:27px}}.system-strip span{{padding:7px 10px;border:1.5px solid var(--ink);border-radius:999px;background:var(--card);box-shadow:2px 2px 0 var(--shadow-ink);color:var(--ink-2);font:700 9px/1 var(--font-mono)}}.system-strip span:nth-child(1){{background:var(--mint);color:var(--on-color)}}.system-strip span:nth-child(2){{background:var(--sky);color:var(--on-color)}}.system-strip span:nth-child(3){{background:var(--sun);color:var(--on-color)}}.system-strip b{{color:inherit}}footer{{margin-top:24px;padding-top:16px;border-top:2px solid var(--ink);color:var(--ink-3);font:600 9px/1.65 var(--font-mono)}}
@media(max-width:1320px){{.hero-grid{{grid-template-columns:repeat(3,minmax(0,1fr))}}}}@media(max-width:920px){{main{{padding:26px 16px 55px}}header{{align-items:flex-start}}.brand-mark{{width:46px;height:46px}}.subtitle{{max-width:560px}}.hero-grid,.period-grid,.two-col{{grid-template-columns:minmax(0,1fr)}}.form-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.trend{{gap:7px}}.notice{{display:grid;grid-template-columns:auto minmax(0,1fr)}}.notice b{{white-space:normal}}.notice span{{grid-column:2;overflow-wrap:anywhere}}}}@media(max-width:620px){{header{{align-items:flex-start;flex-direction:column}}.brand-lockup{{align-items:flex-start}}h1{{font-size:clamp(28px,9vw,38px)}}.header-actions{{width:100%;justify-content:space-between}}.hero-grid,.subscription-grid,.form-grid{{grid-template-columns:minmax(0,1fr)}}.period-head{{flex-wrap:wrap}}.mix-legend{{grid-template-columns:minmax(0,1fr)}}.account-usage{{grid-template-columns:repeat(3,minmax(0,1fr))}}.trend-column small{{display:none}}.section-title{{align-items:flex-start;flex-direction:column;gap:6px}}}}@media(prefers-reduced-motion:reduce){{*{{scroll-behavior:auto!important;transition:none!important}}}}
</style></head><body><main>
<header><div class="brand-lockup"><div class="brand-mark" aria-hidden="true">UM</div><div><div class="eyebrow">Local · Private · Token Safe</div><h1>Usage Observatory</h1><div class="subtitle">跨 Codex 订阅账号的 token、API 等价成本与实时额度；主口径与 Codex /status 对齐。</div></div></div><div class="header-actions"><div class="live">8327 LIVE</div><button class="theme-toggle" type="button" data-role="theme-toggle" aria-label="切换明暗主题" title="切换明暗主题"><svg class="theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 15.2A8.5 8.5 0 0 1 8.8 4 8.5 8.5 0 1 0 20 15.2Z"/></svg><svg class="theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button></div></header>
<section class="hero-grid">{hero_metrics}</section>
<div class="notice app-import-notice"><b>ChatGPT Codex 本地监控</b><span>codex-13 · …fa79c563 已映射到默认 CODEX_HOME；只读取本机会话中的 token_count / rate_limits 元数据，不读取或保存提示词、代码、推理、工具输出和凭据。已自动导入 {fmt_int(codex_app_status.get('imported_events'))} 条，最近扫描 {fmt_local_time(codex_app_status.get('last_import_at'))}。下方“API 等价成本”仅是按模型 API 单价估算，不是 Pro 订阅实际扣款。</span></div>
<details class="manual-import"><summary>手动补录用量 <span>跨设备或本地日志缺失时使用</span></summary><form method="post" action="/usage/manual-import"><div class="form-grid"><label>账号<input name="usage_alias" value="codex-13" readonly></label><label>模型<input name="model" value="gpt-5.6-sol" maxlength="200" required></label><label>时间<input name="ts" type="datetime-local"></label><label>调用数<input name="call_count" type="number" value="1" min="1" max="100000" required></label><label>输入 tokens<input name="input_tokens" type="number" min="0" required></label><label>缓存 tokens<input name="cached_tokens" type="number" value="0" min="0" required></label><label>输出 tokens<input name="output_tokens" type="number" min="0" required></label><label>推理 tokens<input name="reasoning_tokens" type="number" value="0" min="0"></label></div><label class="note-label">备注（不填写提示词或代码）<input name="note" maxlength="120" placeholder="例如：另一台设备的 Codex 用量"></label><button type="submit">导入并估价</button><p>输入应包含缓存 token，系统按 max(输入−缓存, 0) + 缓存 + 输出分别套用价格。重复提交不会自动去重，请按汇总区间录入一次。</p></form></details>
{session_notice}
<div class="notice"><b>长上下文计费已启用</b><span>按每次调用完整 input tokens 判断：≤272K 使用短上下文价，&gt;272K 使用长上下文价；cached tokens 是 input 子集，计入阈值且仍按 cached-input 档计费。长上下文请求的输入档（含缓存）与输出档按官方对应费率整次计算。</span></div>
<div class="section-title"><div><h2>Token 消费总览</h2><p>输入、缓存、输出与推理 token，一眼看清今天、7 天和累计。</p></div></div>
<section class="period-grid">{period_cards}</section>
<div class="section-title"><div><h2>近 7 天趋势</h2><p>柱高为非缓存输入 + 输出；悬停可看缓存和 API 原始处理量。</p></div></div>
<section class="panel trend-panel"><div class="trend">{trend_bars}</div></section>
<div class="section-title"><div><h2>订阅额度雷达</h2><p>剩余百分比来自 Codex 真实 5 小时/周窗口；美元额度优先按 provider 当前窗口估算，低使用量只显示观测下限。</p></div><small>{fmt_int(persisted_quota_accounts)} 个账号已刷新</small></div>
<section class="subscription-grid">{subscriptions_html}</section>
<div class="section-title"><div><h2>消费明细</h2><p>近 7 天模型分布与最近调用。</p></div></div>
  <section class="two-col"><article class="panel"><h3>模型消费 · 7 天</h3><div class="table-wrap"><table><thead><tr><th>模型</th><th>逻辑请求</th><th>账号尝试</th><th>非缓存输入</th><th>输出</th><th>缓存</th><th>长上下文调用</th><th>输入成本</th><th>输出成本</th><th>缓存成本</th><th>总成本</th></tr></thead><tbody>{model_rows}</tbody></table></div></article><article class="panel"><h3>最近 50 次账号尝试</h3><div class="table-wrap"><table><thead><tr><th>时间</th><th>账号</th><th>模型</th><th>状态</th><th>非缓存输入</th><th>输出</th><th>缓存</th><th>计费档</th><th>输入成本</th><th>输出成本</th><th>缓存成本</th><th>总成本</th></tr></thead><tbody>{recent_rows}</tbody></table></div></article></section>
<div class="section-title"><div><h2>账号累计</h2><p>每个订阅自本地 collector 启用以来的 token、请求和 API 等价成本。</p></div></div>
  <section class="panel"><div class="table-wrap"><table><thead><tr><th>账号</th><th>逻辑请求</th><th>账号尝试</th><th>非缓存输入</th><th>输出</th><th>缓存</th><th>输入成本</th><th>输出成本</th><th>缓存成本</th><th>总成本</th></tr></thead><tbody>{account_rows}</tbody></table></div></section>
<div class="system-strip"><span>8317 collector <b>{'正常' if collector_ok else '等待'}</b></span><span>ChatGPT App <b>{'本地监控中' if codex_app_ok else '等待'}</b></span><span>Quota snapshot <b>{'正常' if quota_ok else '等待'}</b></span><span>Official prices <b>{'已同步' if price_ok else '待同步'}</b></span><span>逻辑请求/尝试 <b>{fmt_int(all_time['logical_requests'])}/{fmt_int(all_time['account_attempts'])}</b></span><span>覆盖 <b>{fmt_local_time(coverage.get('first_event_ts'))} → {fmt_local_time(coverage.get('last_event_ts'))}</b></span></div>
<footer>自动刷新 30 秒 · 页面生成 {html.escape(generated)} · 实际消耗 = max(输入−缓存, 0)+输出，接近 Codex /status；输入、缓存输入和输出成本分别按对应模型的 OpenAI 官方费率逐条计算。长上下文档仅在完整 input tokens &gt; 272K 时启用（272K 本身仍是短档），缓存命中计入这个输入阈值。API 原始处理量 = 输入（含缓存）+输出。reasoning 是输出子集，不重复相加。“API 等价成本/额度”不代表订阅现金余额。</footer>
</main><script>(()=>{{const b=document.querySelector('[data-role="theme-toggle"]');if(!b)return;b.addEventListener('click',()=>{{const r=document.documentElement;const next=r.dataset.theme==='dark'?'light':'dark';r.dataset.theme=next;try{{localStorage.setItem('cliproxy-usage-theme',next)}}catch(e){{}}}})}})()</script></body></html>"""


class MeterHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        repo: UsageRepository,
        upstream: str,
        resolver: AccountResolver,
        upstream_timeout: float,
        *,
        management_key_file: str | None = None,
        management_key_env: str = "CLIPROXY_MANAGEMENT_KEY",
        usage_queue_path: str = DEFAULT_USAGE_QUEUE_PATH,
        usage_queue_count: int = DEFAULT_USAGE_QUEUE_COUNT,
        usage_queue_poll_seconds: float = DEFAULT_USAGE_QUEUE_POLL_SECONDS,
        usage_queue_timeout: float = 10.0,
        quota_poll_seconds: float = DEFAULT_QUOTA_POLL_SECONDS,
        quota_poll_timeout: float = DEFAULT_QUOTA_POLL_TIMEOUT,
        codex_app_home: str | Path = DEFAULT_CODEX_APP_HOME,
        codex_app_alias: str = DEFAULT_CODEX_APP_ALIAS,
        codex_app_poll_seconds: float = DEFAULT_CODEX_APP_POLL_SECONDS,
        codex_app_max_files: int = DEFAULT_CODEX_APP_MAX_FILES,
        codex_app_import_enabled: bool = True,
    ):
        super().__init__(address, UsageMeterHandler)
        parsed = urlsplit(upstream)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("upstream must be an http(s) URL")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("upstream URL must not contain query, fragment, or userinfo")
        self.repo = repo
        self.upstream = parsed
        self.resolver = resolver
        self.upstream_timeout = upstream_timeout
        self.queue_poller = UsageQueuePoller(
            repo,
            resolver,
            parsed,
            key_file=management_key_file,
            key_env=management_key_env,
            queue_path=usage_queue_path,
            count=usage_queue_count,
            poll_seconds=usage_queue_poll_seconds,
            timeout=usage_queue_timeout,
        )
        self.quota_poller = CodexQuotaPoller(
            repo,
            resolver,
            parsed,
            key_loader=self.queue_poller._load_key,
            poll_seconds=quota_poll_seconds,
            timeout=quota_poll_timeout,
        )
        self.codex_app_importer = CodexAppLocalImporter(
            repo,
            resolver,
            codex_home=codex_app_home,
            alias=codex_app_alias,
            poll_seconds=codex_app_poll_seconds,
            max_files=codex_app_max_files,
        )
        self.codex_app_import_enabled = bool(codex_app_import_enabled)

    def start_queue_poller(self) -> None:
        self.queue_poller.start()
        self.quota_poller.start()
        # The local ChatGPT importer is independent of the optional 8317
        # management queue and must remain active when both are enabled.
        if self.codex_app_import_enabled:
            self.codex_app_importer.start()

    def start_local_importer(self) -> None:
        if self.codex_app_import_enabled:
            self.codex_app_importer.start()

    def server_close(self) -> None:
        self.codex_app_importer.stop()
        self.quota_poller.stop()
        self.queue_poller.stop()
        super().server_close()


class UsageMeterHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cliproxy-usage-meter/0.1"

    @property
    def meter_server(self) -> MeterHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Deliberately suppress BaseHTTPRequestHandler's request-line logging:
        # query strings can contain credentials in poorly behaved clients.
        return

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _dispatch(self) -> None:
        path = urlsplit(self.path).path
        if path in {"/usage", "/__usage"}:
            if self.command not in {"GET", "HEAD"}:
                self._plain_response(405, b"method not allowed\n")
                return
            try:
                rebound = self.meter_server.repo.reconcile_auth_identities(self.meter_server.resolver)
                if rebound:
                    LOG.info("reconciled %d provisional auth identity event(s)", rebound)
                body = dashboard_html(
                    self.meter_server.repo,
                    self.meter_server.queue_poller.status(),
                    self.meter_server.quota_poller.status(),
                    self.meter_server.codex_app_importer.status(),
                    self.meter_server.resolver,
                ).encode("utf-8")
            except Exception as exc:  # dashboard failure must not expose DB internals
                LOG.error("dashboard rendering failed: %s", type(exc).__name__)
                self._plain_response(500, b"dashboard unavailable\n")
                return
            self._send_bytes(200, "OK", [("Content-Type", "text/html; charset=utf-8")], body)
            return
        if path == "/usage/manual-import":
            if self.command != "POST":
                self._plain_response(405, b"method not allowed\n")
                return
            self._manual_import()
            return
        if path == "/healthz":
            body = json.dumps(
                {
                    "ok": True,
                    "upstream": self.meter_server.upstream.geturl(),
                    "usage_queue": self.meter_server.queue_poller.status(),
                    "subscription_quota": self.meter_server.quota_poller.status(),
                    "codex_app_local": self.meter_server.codex_app_importer.status(),
                }
            ).encode()
            self._send_bytes(200, "OK", [("Content-Type", "application/json")], body)
            return
        if path == "/v1" or path.startswith("/v1/"):
            self._proxy(path)
            return
        self._plain_response(404, b"not found\n")

    def _manual_import(self) -> None:
        try:
            body = self._read_request_body()
            if len(body) > MAX_MANUAL_IMPORT_BYTES:
                raise ValueError("form too large")
            fields = urllib.parse.parse_qs(
                body.decode("utf-8"), keep_blank_values=True, max_num_fields=20
            )
            value = lambda name: fields.get(name, [""])[0]
            alias = safe_alias(value("usage_alias"))
            if alias != self.meter_server.codex_app_importer.alias:
                raise ValueError("unsupported alias")
            model = safe_text(value("model"), 200)
            if not model:
                raise ValueError("model is required")
            input_tokens = as_nonnegative_int(value("input_tokens"))
            cached_tokens = as_nonnegative_int(value("cached_tokens"))
            output_tokens = as_nonnegative_int(value("output_tokens"))
            reasoning_tokens = as_nonnegative_int(value("reasoning_tokens"))
            call_count = as_nonnegative_int(value("call_count"))
            if input_tokens is None or cached_tokens is None or output_tokens is None:
                raise ValueError("token fields are required")
            if cached_tokens > input_tokens:
                raise ValueError("cached tokens exceed input tokens")
            if not call_count or call_count > 100_000:
                raise ValueError("invalid call count")
            raw_ts = safe_text(value("ts"), 64)
            ts = normalize_timestamp(raw_ts) if raw_ts else utc_now()
            identity = self.meter_server.resolver.resolve(alias, None)
            if not identity.account_id_hash:
                raise ValueError("alias is not mapped to a local account")
            usage = NormalizedUsage(
                input_tokens=input_tokens,
                cached_tokens=cached_tokens,
                output_tokens=output_tokens,
                reasoning_tokens=reasoning_tokens,
                total_tokens=input_tokens + output_tokens,
            )
            components = self.meter_server.repo.price_components_for(model, usage)
            import_key = "manual:" + short_hash(
                f"{utc_now()}\n{alias}\n{model}\n{input_tokens}\n{cached_tokens}\n{output_tokens}"
            )
            event = UsageEvent(
                ts=ts,
                identity_key=identity_key(
                    identity.account_id_hash, alias, None, None, None
                ),
                endpoint="manual://chatgpt-codex",
                method="MANUAL",
                model=model,
                status_code=200,
                ok=1,
                duration_ms=0,
                stream=0,
                session_id=None,
                thread_id=None,
                turn_id=None,
                installation_id=None,
                window_id=None,
                usage_alias=alias,
                usage_project=safe_text(value("note"), 120) or "ChatGPT Codex 手动补录",
                auth_fingerprint=None,
                account_id_hash=identity.account_id_hash,
                account_id_tail=identity.account_id_tail,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cached_tokens=usage.cached_tokens,
                cache_write_tokens=0,
                reasoning_tokens=usage.reasoning_tokens,
                total_tokens=usage.total_tokens,
                estimated_api_cost_usd=components.total_cost_usd if components else None,
                non_cached_input_cost_usd=(
                    components.non_cached_input_cost_usd if components else None
                ),
                cached_input_cost_usd=(
                    components.cached_input_cost_usd if components else None
                ),
                output_cost_usd=components.output_cost_usd if components else None,
                long_context_pricing_applied=int(
                    components.long_context_pricing_applied if components else False
                ),
                subscription_amortized_cost_usd=None,
                api_equivalent_quota_usd=None,
                usage_missing=0,
                error_type=None,
                error_message_redacted=None,
                request_bytes=0,
                response_bytes=0,
                call_count=call_count,
                source="manual_codex_app",
                request_id=import_key,
            )
            self.meter_server.repo.record_imported_event(
                event, import_key, "manual_codex_app"
            )
        except (ValueError, UnicodeDecodeError) as exc:
            LOG.info("manual import rejected: %s", type(exc).__name__)
            self._plain_response(400, b"invalid manual usage import\n")
            return
        self.send_response_only(303, "See Other")
        self.send_header("Location", "/usage")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _read_request_body(self) -> bytes:
        transfer = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" not in transfer:
            raw_length = self.headers.get("Content-Length")
            if not raw_length:
                return b""
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("invalid Content-Length") from exc
            if length < 0:
                raise ValueError("invalid Content-Length")
            return self.rfile.read(length)

        chunks = bytearray()
        while True:
            size_line = self.rfile.readline(128)
            if not size_line:
                raise ConnectionError("unexpected EOF in chunked request")
            try:
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise ValueError("invalid chunk size") from exc
            if size == 0:
                while True:
                    trailer = self.rfile.readline(65537)
                    if trailer in {b"\r\n", b"\n", b""}:
                        break
                break
            chunks.extend(self.rfile.read(size))
            ending = self.rfile.read(2)
            if ending != b"\r\n":
                raise ValueError("invalid chunk terminator")
        return bytes(chunks)

    def _proxy(self, endpoint: str) -> None:
        started = time.monotonic()
        try:
            body = self._read_request_body()
        except Exception as exc:
            self._plain_response(400, b"invalid request body\n")
            LOG.warning("rejected malformed request body: %s", type(exc).__name__)
            try:
                malformed_info = request_info(endpoint, self.command, self.headers, b"", self.meter_server.resolver)
                self._record_event(
                    self._make_event(
                        malformed_info,
                        malformed_info.model,
                        400,
                        NormalizedUsage(),
                        "invalid_request",
                        type(exc).__name__,
                        0,
                        0,
                        started,
                        force_failed=True,
                    ),
                    malformed_info,
                )
            except Exception as record_exc:
                LOG.error("meter persistence failed: %s", type(record_exc).__name__)
            return
        info = request_info(endpoint, self.command, self.headers, body, self.meter_server.resolver)
        response_started = False
        upstream_response: http.client.HTTPResponse | None = None
        connection: http.client.HTTPConnection | None = None
        try:
            connection = self._connection()
            target = self._upstream_target()
            headers = self._forward_headers(len(body))
            connection.request(self.command, target, body=body if body else None, headers=headers)
            upstream_response = connection.getresponse()
            response_content_type = upstream_response.getheader("Content-Type", "").lower()
            is_stream = bool(info.stream or "text/event-stream" in response_content_type)
            info.stream = int(is_stream)
            if is_stream and self.command != "HEAD":
                response_started = True
                self._proxy_stream(upstream_response, info, len(body), started)
            else:
                response_body = b"" if self.command == "HEAD" else upstream_response.read()
                usage = find_usage(parse_json_bytes(response_body))
                model = info.model or find_model(parse_json_bytes(response_body))
                error_type, error_message = extract_error(response_body, upstream_response.status)
                response_started = True
                self._send_upstream_bytes(upstream_response, response_body)
                event = self._make_event(
                    info,
                    model,
                    upstream_response.status,
                    usage,
                    error_type,
                    error_message,
                    len(body),
                    len(response_body),
                    started,
                )
                self._record_event(event, info)
        except (BrokenPipeError, ConnectionResetError) as exc:
            if not response_started:
                self._plain_response(502, b"upstream unavailable\n")
            event = self._make_event(
                info,
                info.model,
                upstream_response.status if upstream_response else 502,
                NormalizedUsage(),
                "client_disconnect",
                type(exc).__name__,
                len(body),
                0,
                started,
                force_failed=True,
            )
            self._record_event(event, info)
        except Exception as exc:
            if not response_started:
                self._plain_response(502, b"upstream unavailable\n")
            event = self._make_event(
                info,
                info.model,
                upstream_response.status if upstream_response else 502,
                NormalizedUsage(),
                "upstream_error",
                type(exc).__name__,
                len(body),
                0,
                started,
                force_failed=True,
            )
            self._record_event(event, info)
            LOG.warning("upstream request failed: %s", type(exc).__name__)
        finally:
            if connection is not None:
                connection.close()

    def _connection(self) -> http.client.HTTPConnection:
        parsed = self.meter_server.upstream
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "https":
            return http.client.HTTPSConnection(
                parsed.hostname, port, timeout=self.meter_server.upstream_timeout, context=ssl.create_default_context()
            )
        return http.client.HTTPConnection(parsed.hostname, port, timeout=self.meter_server.upstream_timeout)

    def _upstream_target(self) -> str:
        base_path = self.meter_server.upstream.path.rstrip("/")
        request = urlsplit(self.path)
        target = f"{base_path}{request.path}"
        if request.query:
            target += f"?{request.query}"
        return target or "/"

    def _forward_headers(self, body_length: int) -> dict[str, str]:
        connection_tokens = {
            item.strip().lower() for item in self.headers.get("Connection", "").split(",") if item.strip()
        }
        skipped = HOP_BY_HOP_HEADERS | METER_ONLY_HEADERS | connection_tokens | {"host", "content-length"}
        headers = {key: value for key, value in self.headers.items() if key.lower() not in skipped}
        headers["Content-Length"] = str(body_length)
        return headers

    def _proxy_stream(
        self,
        response: http.client.HTTPResponse,
        info: RequestInfo,
        request_bytes: int,
        started: float,
    ) -> None:
        self.send_response_only(response.status, response.reason)
        for key, value in self._response_headers(response.getheaders(), streaming=True):
            self.send_header(key, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        inspector = SSEInspector()
        response_bytes = 0
        error_capture = bytearray()
        body_capture = bytearray()
        client_error: Exception | None = None
        try:
            while True:
                chunk = response.read1(64 * 1024)
                if not chunk:
                    break
                response_bytes += len(chunk)
                inspector.feed(chunk)
                if len(body_capture) < MAX_INSPECT_BYTES:
                    body_capture.extend(chunk[: MAX_INSPECT_BYTES - len(body_capture)])
                if response.status >= 300 and len(error_capture) < MAX_ERROR_BYTES:
                    error_capture.extend(chunk[: MAX_ERROR_BYTES - len(error_capture)])
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError) as exc:
            client_error = exc
        finally:
            inspector.finish()
        if inspector.usage.missing:
            fallback_usage = find_usage(parse_json_bytes(bytes(body_capture)))
            if not fallback_usage.missing:
                inspector.usage = fallback_usage
                inspector.model = inspector.model or find_model(parse_json_bytes(bytes(body_capture)))
        error_type, error_message = extract_error(bytes(error_capture), response.status)
        if client_error:
            error_type = "client_disconnect"
            error_message = type(client_error).__name__
        event = self._make_event(
            info,
            info.model or inspector.model,
            response.status,
            inspector.usage,
            error_type,
            error_message,
            request_bytes,
            response_bytes,
            started,
            force_failed=bool(client_error),
        )
        self._record_event(event, info)

    def _make_event(
        self,
        info: RequestInfo,
        model: str | None,
        status_code: int,
        usage: NormalizedUsage,
        error_type: str | None,
        error_message: str | None,
        request_bytes: int,
        response_bytes: int,
        started: float,
        force_failed: bool = False,
    ) -> UsageEvent:
        components = self.meter_server.repo.price_components_for(model, usage)
        return UsageEvent(
            ts=utc_now(),
            identity_key=info.identity_key,
            endpoint=info.endpoint,
            method=info.method,
            model=model,
            status_code=status_code,
            ok=int(200 <= status_code < 300 and not force_failed),
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            stream=info.stream,
            session_id=info.session_id,
            thread_id=info.thread_id,
            turn_id=info.turn_id,
            installation_id=info.installation_id,
            window_id=info.window_id,
            usage_alias=info.usage_alias,
            usage_project=info.usage_project,
            auth_fingerprint=info.auth_fingerprint,
            account_id_hash=info.account_id_hash,
            account_id_tail=info.account_id_tail,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cached_tokens=usage.cached_tokens,
            cache_write_tokens=usage.cache_write_tokens,
            reasoning_tokens=usage.reasoning_tokens,
            total_tokens=usage.total_tokens,
            estimated_api_cost_usd=components.total_cost_usd if components else None,
            non_cached_input_cost_usd=(
                components.non_cached_input_cost_usd if components else None
            ),
            cached_input_cost_usd=components.cached_input_cost_usd if components else None,
            output_cost_usd=components.output_cost_usd if components else None,
            long_context_pricing_applied=int(
                components.long_context_pricing_applied if components else False
            ),
            subscription_amortized_cost_usd=None,
            api_equivalent_quota_usd=None,
            usage_missing=int(usage.missing),
            error_type=safe_text(error_type, 120),
            error_message_redacted=redact_text(error_message),
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )

    def _record_event(self, event: UsageEvent, info: RequestInfo) -> None:
        try:
            self.meter_server.repo.record_event(event, info, source="sidecar")
        except Exception as exc:
            # Metering is best-effort; never corrupt a completed proxy response.
            LOG.error("meter persistence failed: %s", type(exc).__name__)

    @staticmethod
    def _response_headers(headers: Sequence[tuple[str, str]], streaming: bool) -> list[tuple[str, str]]:
        connection_tokens: set[str] = set()
        for key, value in headers:
            if key.lower() == "connection":
                connection_tokens.update(item.strip().lower() for item in value.split(",") if item.strip())
        skipped = HOP_BY_HOP_HEADERS | connection_tokens | {"content-length"}
        return [(key, value) for key, value in headers if key.lower() not in skipped]

    def _send_upstream_bytes(self, response: http.client.HTTPResponse, body: bytes) -> None:
        self.send_response_only(response.status, response.reason)
        for key, value in self._response_headers(response.getheaders(), streaming=False):
            self.send_header(key, value)
        if self.command == "HEAD":
            original_length = response.getheader("Content-Length")
            if original_length:
                self.send_header("Content-Length", original_length)
        else:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _send_bytes(
        self, status: int, reason: str, headers: Sequence[tuple[str, str]], body: bytes
    ) -> None:
        self.send_response_only(status, reason)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _plain_response(self, status: int, body: bytes) -> None:
        self._send_bytes(status, "", [("Content-Type", "text/plain; charset=utf-8")], body)


def create_server(
    host: str,
    port: int,
    upstream: str,
    db_path: Path | str,
    *,
    account_resolver: AccountResolver | None = None,
    upstream_timeout: float = 900.0,
    management_key_file: str | None = None,
    management_key_env: str = "CLIPROXY_MANAGEMENT_KEY",
    usage_queue_path: str = DEFAULT_USAGE_QUEUE_PATH,
    usage_queue_count: int = DEFAULT_USAGE_QUEUE_COUNT,
    usage_queue_poll_seconds: float = DEFAULT_USAGE_QUEUE_POLL_SECONDS,
    usage_queue_timeout: float = 10.0,
    quota_poll_seconds: float = DEFAULT_QUOTA_POLL_SECONDS,
    quota_poll_timeout: float = DEFAULT_QUOTA_POLL_TIMEOUT,
    codex_app_home: str | Path = DEFAULT_CODEX_APP_HOME,
    codex_app_alias: str = DEFAULT_CODEX_APP_ALIAS,
    codex_app_poll_seconds: float = DEFAULT_CODEX_APP_POLL_SECONDS,
    codex_app_max_files: int = DEFAULT_CODEX_APP_MAX_FILES,
    codex_app_import_enabled: bool = True,
) -> MeterHTTPServer:
    repo = UsageRepository(db_path)
    resolver = account_resolver or AccountResolver(
        enabled=os.environ.get("CLIPROXY_USAGE_ACCOUNT_SCAN", "1").lower() not in {"0", "false", "no"}
    )
    return MeterHTTPServer(
        (host, port),
        repo,
        upstream,
        resolver,
        upstream_timeout,
        management_key_file=management_key_file,
        management_key_env=management_key_env,
        usage_queue_path=usage_queue_path,
        usage_queue_count=usage_queue_count,
        usage_queue_poll_seconds=usage_queue_poll_seconds,
        usage_queue_timeout=usage_queue_timeout,
        quota_poll_seconds=quota_poll_seconds,
        quota_poll_timeout=quota_poll_timeout,
        codex_app_home=codex_app_home,
        codex_app_alias=codex_app_alias,
        codex_app_poll_seconds=codex_app_poll_seconds,
        codex_app_max_files=codex_app_max_files,
        codex_app_import_enabled=codex_app_import_enabled,
    )


def print_rows(rows: Sequence[Mapping[str, Any]], json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(list(rows), ensure_ascii=False, indent=2, default=str))
        return
    if not rows:
        print("No data.")
        return
    columns = list(rows[0].keys())
    rendered = [["—" if row.get(column) is None else str(row.get(column)) for column in columns] for row in rows]
    widths = [
        min(48, max(len(column), *(len(row[index]) for row in rendered))) for index, column in enumerate(columns)
    ]
    print("  ".join(column[: widths[index]].ljust(widths[index]) for index, column in enumerate(columns)))
    print("  ".join("-" * width for width in widths))
    for row in rendered:
        print("  ".join(value[: widths[index]].ljust(widths[index]) for index, value in enumerate(row)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local token-safe usage meter for cliproxyapi")
    parser.add_argument(
        "--db", default=os.environ.get("CLIPROXY_USAGE_DB", str(DEFAULT_DB)), help="SQLite database path"
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON for queries")
    actions = parser.add_mutually_exclusive_group(required=False)
    actions.add_argument("--serve", action="store_true", help="Run the sidecar HTTP server")
    actions.add_argument("--summary", metavar="PERIOD", help="Summary for today, all, or Nd")
    actions.add_argument("--by-account", metavar="PERIOD", help="Group by account/alias (today, all, or Nd)")
    actions.add_argument("--by-model", metavar="PERIOD", help="Group by model (today, all, or Nd)")
    actions.add_argument("--by-session", metavar="PERIOD", help="Group by session (today, all, or Nd)")
    actions.add_argument("--by-date", metavar="PERIOD", help="Group by local date (today, all, or Nd)")
    actions.add_argument("--recent", metavar="N", type=int, help="Show recent N calls")
    actions.add_argument("--quota-summary", metavar="PERIOD", help="Quota-cycle summary for Nd")
    actions.add_argument("--quota-summary-by-account", action="store_true", help="Quota summary by account (30d)")
    actions.add_argument("--mark-reset", metavar="ALIAS", help="Mark a reset for an alias")
    actions.add_argument("--mark-quota-hit", metavar="ALIAS", help="Mark a quota hit for an alias")
    actions.add_argument(
        "--set-price", nargs=3, metavar=("MODEL_PATTERN", "INPUT_PER_M", "OUTPUT_PER_M"), help="Set a USD pricing row"
    )
    actions.add_argument("--list-prices", action="store_true", help="List configured model prices")
    actions.add_argument(
        "--sync-official-prices",
        action="store_true",
        help="Fetch and safely sync the standard token prices from the official OpenAI pricing page",
    )
    actions.add_argument(
        "--price-sync-status", action="store_true", help="Show the latest official pricing sync metadata"
    )
    parser.add_argument("--host", default=os.environ.get("CLIPROXY_USAGE_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", DEFAULT_PORT)))
    parser.add_argument("--upstream", default=os.environ.get("UPSTREAM", DEFAULT_UPSTREAM))
    parser.add_argument("--upstream-timeout", type=float, default=float(os.environ.get("UPSTREAM_TIMEOUT", "900")))
    parser.add_argument(
        "--management-key-file",
        default=os.environ.get("CLIPROXY_MANAGEMENT_KEY_FILE", ""),
        help="Owner-only file containing the CLIProxyAPI management key (never logged)",
    )
    parser.add_argument(
        "--management-key-env",
        default=os.environ.get("CLIPROXY_MANAGEMENT_KEY_ENV", "CLIPROXY_MANAGEMENT_KEY"),
        help="Environment variable name for the management key (file is preferred)",
    )
    parser.add_argument(
        "--usage-queue-path",
        default=os.environ.get("CLIPROXY_USAGE_QUEUE_PATH", DEFAULT_USAGE_QUEUE_PATH),
        help="CLIProxyAPI management usage-queue path",
    )
    parser.add_argument(
        "--usage-queue-count",
        type=int,
        default=int(os.environ.get("CLIPROXY_USAGE_QUEUE_COUNT", str(DEFAULT_USAGE_QUEUE_COUNT))),
    )
    parser.add_argument(
        "--usage-queue-poll-seconds",
        type=float,
        default=float(os.environ.get("CLIPROXY_USAGE_QUEUE_POLL_SECONDS", str(DEFAULT_USAGE_QUEUE_POLL_SECONDS))),
    )
    parser.add_argument(
        "--usage-queue-timeout",
        type=float,
        default=float(os.environ.get("CLIPROXY_USAGE_QUEUE_TIMEOUT", "10")),
    )
    parser.add_argument(
        "--quota-poll-seconds",
        type=float,
        default=float(os.environ.get("CLIPROXY_QUOTA_POLL_SECONDS", str(DEFAULT_QUOTA_POLL_SECONDS))),
        help="Seconds between read-only Codex subscription quota snapshots (minimum 60)",
    )
    parser.add_argument(
        "--quota-poll-timeout",
        type=float,
        default=float(os.environ.get("CLIPROXY_QUOTA_POLL_TIMEOUT", str(DEFAULT_QUOTA_POLL_TIMEOUT))),
    )
    parser.add_argument(
        "--codex-app-home",
        default=os.environ.get("CODEX_APP_HOME", str(DEFAULT_CODEX_APP_HOME)),
        help="ChatGPT/Codex local home whose safe token_count metadata is imported",
    )
    parser.add_argument(
        "--codex-app-alias",
        default=os.environ.get("CODEX_APP_USAGE_ALIAS", DEFAULT_CODEX_APP_ALIAS),
        help="Existing local alias that must match the ChatGPT app account",
    )
    parser.add_argument(
        "--codex-app-poll-seconds",
        type=float,
        default=float(
            os.environ.get(
                "CODEX_APP_USAGE_POLL_SECONDS", str(DEFAULT_CODEX_APP_POLL_SECONDS)
            )
        ),
    )
    parser.add_argument(
        "--codex-app-max-files",
        type=int,
        default=int(
            os.environ.get("CODEX_APP_USAGE_MAX_FILES", str(DEFAULT_CODEX_APP_MAX_FILES))
        ),
        help="Maximum most-recent local session JSONL files scanned per poll",
    )
    parser.add_argument(
        "--no-codex-app-import",
        action="store_true",
        help="Disable read-only import from local ChatGPT/Codex session metadata",
    )
    parser.add_argument("--no-usage-queue", action="store_true", help="Disable direct 8317 usage-queue polling")
    parser.add_argument("--cached-input-price", type=float, help="Cached input USD/M; defaults to input price")
    parser.add_argument("--price-source-note", help="Human-readable provenance for a manually supplied price")
    parser.add_argument(
        "--official-pricing-url",
        default=os.environ.get("OPENAI_PRICING_URL", OFFICIAL_PRICING_URL),
        help="Official OpenAI pricing URL used by --sync-official-prices",
    )
    parser.add_argument(
        "--official-pricing-timeout",
        type=float,
        default=float(os.environ.get("OPENAI_PRICING_TIMEOUT", "20")),
        help="Network timeout in seconds for --sync-official-prices",
    )
    parser.add_argument("--no-account-scan", action="store_true", help="Disable read-only local Codex auth mapping")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if not any(
        (
            args.serve,
            args.summary,
            args.by_account,
            args.by_model,
            args.by_session,
            args.by_date,
            args.recent is not None,
            args.quota_summary,
            args.quota_summary_by_account,
            args.mark_reset,
            args.mark_quota_hit,
            args.set_price,
            args.list_prices,
            args.sync_official_prices,
            args.price_sync_status,
        )
    ):
        parser.print_help()
        return 2

    repo = UsageRepository(args.db)
    resolver = AccountResolver(enabled=not args.no_account_scan)
    rebound = repo.reconcile_auth_identities(resolver)
    if rebound:
        LOG.info("reconciled %d provisional auth identity event(s)", rebound)
    if args.serve:
        server = MeterHTTPServer(
            (args.host, args.port),
            repo,
            args.upstream,
            resolver,
            args.upstream_timeout,
            management_key_file=None if args.no_usage_queue else (args.management_key_file or None),
            management_key_env="" if args.no_usage_queue else args.management_key_env,
            usage_queue_path=args.usage_queue_path,
            usage_queue_count=args.usage_queue_count,
            usage_queue_poll_seconds=args.usage_queue_poll_seconds,
            usage_queue_timeout=args.usage_queue_timeout,
            quota_poll_seconds=args.quota_poll_seconds,
            quota_poll_timeout=args.quota_poll_timeout,
            codex_app_home=args.codex_app_home,
            codex_app_alias=args.codex_app_alias,
            codex_app_poll_seconds=args.codex_app_poll_seconds,
            codex_app_max_files=args.codex_app_max_files,
            codex_app_import_enabled=not args.no_codex_app_import,
        )
        LOG.info(
            "usage meter listening on http://%s:%d; upstream=%s; db=%s",
            args.host,
            server.server_address[1],
            args.upstream,
            repo.path,
        )
        if not args.no_usage_queue:
            server.start_queue_poller()
        else:
            server.start_local_importer()
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    if args.summary:
        result = repo.summary(args.summary)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            for key, value in result.items():
                print(f"{key}: {value if value is not None else '—'}")
        return 0
    if args.by_account:
        print_rows(repo.grouped(args.by_account, "account"), args.json)
        return 0
    if args.by_model:
        print_rows(repo.grouped(args.by_model, "model"), args.json)
        return 0
    if args.by_session:
        print_rows(repo.grouped(args.by_session, "session"), args.json)
        return 0
    if args.by_date:
        print_rows(repo.grouped(args.by_date, "date"), args.json)
        return 0
    if args.recent is not None:
        print_rows(repo.recent(args.recent), args.json)
        return 0
    if args.quota_summary or args.quota_summary_by_account:
        print_rows(repo.quota_summary(args.quota_summary or "30d"), args.json)
        return 0
    if args.mark_reset:
        key = repo.mark_reset(args.mark_reset, resolver)
        print(f"marked reset: alias={args.mark_reset} identity={key}")
        return 0
    if args.mark_quota_hit:
        key = repo.mark_quota_hit(args.mark_quota_hit, resolver)
        print(f"marked quota hit: alias={args.mark_quota_hit} identity={key}")
        return 0
    if args.set_price:
        pattern, input_value, output_value = args.set_price
        input_rate = float(input_value)
        output_rate = float(output_value)
        cached_rate = args.cached_input_price if args.cached_input_price is not None else input_rate
        repo.set_price(pattern, input_rate, output_rate, cached_rate, args.price_source_note)
        print(f"price configured for {pattern}; USD per million input={input_rate}, cached={cached_rate}, output={output_rate}")
        return 0
    if args.list_prices:
        print_rows(repo.list_prices(), args.json)
        return 0
    if args.price_sync_status:
        result = repo.price_sync_status()
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            for key, value in result.items():
                print(f"{key}: {value if value is not None else '—'}")
        return 0
    if args.sync_official_prices:
        try:
            result = sync_official_prices(
                repo,
                url=args.official_pricing_url,
                timeout=args.official_pricing_timeout,
            )
        except OfficialPriceSyncError as exc:
            print(f"official price sync failed: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            print(
                f"official prices synced: {result['model_count']} models; "
                f"repriced_events={result['repriced_events']}; "
                f"sha256={result['content_sha256']} fetched_at={result['fetched_at']}"
            )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
