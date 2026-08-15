#!/usr/bin/env python3
"""Read and health-check Cockpit Tools' local Codex API service.

The helper deliberately keeps the API key in memory.  ``--token`` is meant to
be used as Codex's provider auth command; every other command emits only the
local endpoint or redacted health information.

Cockpit has kept the local service contract stable while adding fields to its
state document.  The reader therefore probes the small set of capability
fields it needs (endpoint and key), accepts common snake/camel-case aliases,
and does not compare an application version string.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


DEFAULT_COCKPIT_TOOLS_DIR = Path.home() / ".antigravity_cockpit"
STATE_FILE_NAMES = (
    "codex_local_access.json",
    "codex-local-access.json",
    "codex_local_access_state.json",
)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_TIMEOUT_SECONDS = 5.0
EX_CONFIG = 78
EX_UNAVAILABLE = 69


class CockpitApiError(RuntimeError):
    """A safe, user-actionable local API configuration error."""


@dataclass(frozen=True)
class CockpitApiConfig:
    """The minimum runtime data needed by a Codex client."""

    base_url: str
    host: str
    port: int
    enabled: Optional[bool]
    state_path: Optional[Path]
    key: str = ""

    def __repr__(self) -> str:  # pragma: no cover - prevents accidental leaks
        return (
            "CockpitApiConfig("
            f"base_url={self.base_url!r}, host={self.host!r}, port={self.port!r}, "
            f"enabled={self.enabled!r}, state_path={self.state_path!r}, key=<redacted>)"
        )


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _objects(root: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    """Yield likely state containers without depending on a version number."""

    yielded: set[int] = set()
    pending: list[Mapping[str, Any]] = [root]
    while pending:
        current = pending.pop(0)
        marker = id(current)
        if marker in yielded:
            continue
        yielded.add(marker)
        yield current
        for name in (
            "collection",
            "state",
            "data",
            "config",
            "service",
            "codexLocalAccess",
            "codex_local_access",
            "apiService",
            "api_service",
            "localAccess",
            "local_access",
        ):
            nested = current.get(name)
            if isinstance(nested, Mapping):
                pending.append(nested)


def _first_value(objects: Iterable[Mapping[str, Any]], names: Sequence[str]) -> Any:
    for obj in objects:
        for name in names:
            if name in obj and obj[name] not in (None, ""):
                return obj[name]
    return None


def _state_path(data_dir: Optional[Path]) -> Optional[Path]:
    root = data_dir or Path(
        os.environ.get("COCKPIT_TOOLS_DATA_DIR", str(DEFAULT_COCKPIT_TOOLS_DIR))
    ).expanduser()
    explicit = _text(os.environ.get("COCKPIT_TOOLS_API_STATE_FILE"))
    if explicit:
        return Path(explicit).expanduser()
    for name in STATE_FILE_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return root / STATE_FILE_NAMES[0]


def _read_state(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CockpitApiError(
            "Cockpit API state file is unavailable; enable Codex API Service in Cockpit Tools"
        ) from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CockpitApiError("Cockpit API state file is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise CockpitApiError("Cockpit API state has an unsupported shape")
    return value


def _api_key(root: Mapping[str, Any]) -> str:
    direct_names = (
        "apiKey",
        "api_key",
        "clientApiKey",
        "client_api_key",
        "accessKey",
        "access_key",
    )
    list_names = ("apiKeys", "api_keys", "keys")
    for obj in _objects(root):
        for name in direct_names:
            value = _text(obj.get(name))
            if value:
                return value
        for name in list_names:
            values = obj.get(name)
            if not isinstance(values, list):
                continue
            fallback = ""
            for item in values:
                item_map = _mapping(item)
                value = _text(
                    item_map.get("key")
                    or item_map.get("apiKey")
                    or item_map.get("api_key")
                )
                if not value:
                    continue
                if not fallback:
                    fallback = value
                if item_map.get("enabled", True) is not False:
                    return value
            if fallback:
                return fallback
    raise CockpitApiError("Cockpit API key is missing; create or enable a Cockpit client key")


def _port(root: Mapping[str, Any]) -> int:
    value = _first_value(
        _objects(root),
        ("port", "apiPort", "api_port", "localPort", "local_port"),
    )
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise CockpitApiError("Cockpit API port is missing or invalid") from exc
    if not 1 <= port <= 65535:
        raise CockpitApiError("Cockpit API port is outside the valid range")
    return port


def _host(root: Mapping[str, Any]) -> str:
    value = _text(
        _first_value(
            _objects(root),
            (
                "clientBaseUrlHost",
                "client_base_url_host",
                "host",
                "bindHost",
                "bind_host",
            ),
        )
    ).lower()
    host = value or "localhost"
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host not in LOCAL_HOSTS:
        raise CockpitApiError(
            "Cockpit API is not bound to a loopback host; refusing to expose its key"
        )
    return host


def _enabled(root: Mapping[str, Any]) -> Optional[bool]:
    value = _first_value(_objects(root), ("enabled", "isEnabled", "is_enabled"))
    return value if isinstance(value, bool) else None


def _normalize_base_url(raw: str) -> tuple[str, str, int]:
    value = raw.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CockpitApiError("COCKPIT_TOOLS_API_URL must be an http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CockpitApiError(
            "COCKPIT_TOOLS_API_URL must not contain credentials or query data"
        )
    host = (parsed.hostname or "").lower()
    if host not in LOCAL_HOSTS:
        raise CockpitApiError(
            "COCKPIT_TOOLS_API_URL must point to a loopback host"
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise CockpitApiError("COCKPIT_TOOLS_API_URL has an invalid port") from exc
    path = parsed.path.rstrip("/") or "/v1"
    if not path.endswith("/v1"):
        path = f"{path}/v1" if path != "/" else "/v1"
    netloc = f"[{host}]" if ":" in host else host
    if (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
        netloc = f"{netloc}:{port}"
    return f"{parsed.scheme}://{netloc}{path}", host, port


def load_config(
    data_dir: Optional[Path] = None,
    *,
    state_file: Optional[Path] = None,
    api_url: Optional[str] = None,
) -> CockpitApiConfig:
    """Load endpoint/key information without printing credential data."""

    override = _text(api_url) or _text(os.environ.get("COCKPIT_TOOLS_API_URL"))
    path = state_file.expanduser() if state_file else _state_path(data_dir)
    root: Mapping[str, Any] = {}
    if path is not None and path.is_file():
        root = _read_state(path)

    key = _api_key(root) if root else ""
    state_url = _text(
        _first_value(
            _objects(root),
            (
                "baseUrl",
                "base_url",
                "clientBaseUrl",
                "client_base_url",
                "apiUrl",
                "api_url",
            ),
        )
    )
    if override:
        base_url, host, port = _normalize_base_url(override)
    else:
        if not root:
            # _read_state gives the safe, actionable error for a missing file.
            assert path is not None
            root = _read_state(path)
        if state_url:
            base_url, host, port = _normalize_base_url(state_url)
        else:
            host = _host(root)
            port = _port(root)
            netloc = f"[{host}]" if ":" in host else host
            base_url = f"http://{netloc}:{port}/v1"
    if not key:
        raise CockpitApiError("Cockpit API key is missing; create or enable a Cockpit client key")
    return CockpitApiConfig(
        base_url=base_url,
        host=host,
        port=port,
        enabled=_enabled(root) if root else None,
        state_path=path,
        key=key,
    )


def _models_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/models"


def check_service(config: CockpitApiConfig, timeout: float) -> int:
    """Probe the authenticated models endpoint while bypassing proxy env vars."""

    request = urllib.request.Request(
        _models_url(config.base_url),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {config.key}",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(2 * 1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise CockpitApiError("Cockpit API rejected its local client key") from exc
        if exc.code == 404:
            raise CockpitApiError("Cockpit API models endpoint was not found") from exc
        raise CockpitApiError(f"Cockpit API returned HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise CockpitApiError(
            "Cockpit API is not reachable; enable Codex API Service and check its local port"
        ) from exc
    if status < 200 or status >= 300:
        raise CockpitApiError(f"Cockpit API returned HTTP {status}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CockpitApiError("Cockpit API models response is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise CockpitApiError("Cockpit API models response has an unsupported shape")
    models = payload.get("data")
    if not isinstance(models, list):
        models = payload.get("models")
    if not isinstance(models, list):
        raise CockpitApiError("Cockpit API models response has no model list")
    state_note = ""
    if config.enabled is False:
        # A live authenticated endpoint is authoritative during Cockpit's
        # enable/disable write race; do not reject it solely on a stale flag.
        state_note = "; state flag is currently disabled"
    print(
        f"Cockpit API ready: {config.base_url} ({len(models)} models{state_note})"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read the local Cockpit Tools Codex API endpoint safely"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--token", action="store_true", help="print the current API key")
    mode.add_argument("--endpoint", action="store_true", help="print the current base URL")
    mode.add_argument("--check", action="store_true", help="probe /v1/models")
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--state-file", type=Path, default=None)
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(
            args.data_dir,
            state_file=args.state_file,
            api_url=args.api_url,
        )
        if args.token:
            sys.stdout.write(config.key)
            return 0
        if args.endpoint:
            print(config.base_url)
            return 0
        return check_service(config, max(0.1, args.timeout))
    except CockpitApiError as exc:
        print(f"cockpit-tools-api: {exc}", file=sys.stderr)
        return EX_CONFIG if args.token or args.endpoint else EX_UNAVAILABLE


if __name__ == "__main__":
    raise SystemExit(main())
