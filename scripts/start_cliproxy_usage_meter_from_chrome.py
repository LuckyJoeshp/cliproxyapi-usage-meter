#!/usr/bin/env python3
"""Start the meter with the management key already held by Chrome.

CLIProxyAPI's management page stores its key in Chrome Local Storage using the
small XOR obfuscation implemented by the page.  This helper decodes that value
in memory and immediately ``exec``s the normal sidecar launcher.  It never
prints, writes, or logs the decoded key.

This is intentionally a local-machine convenience for the user's existing
localhost management session; a normal owner-only key file or environment
variable remains the preferred portable deployment mechanism.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import plistlib
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
START_SCRIPT = ROOT / "scripts" / "start_cliproxy_usage_meter.sh"
STORAGE_MARKER = b"enc::v1::"
STORAGE_PREFIX = "cli-proxy-api-webui::secure-storage"
BASE64_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
DEFAULT_HOSTS = ("localhost:8317", "127.0.0.1:8317")


def chrome_version() -> str:
    plist_path = Path("/Applications/Google Chrome.app/Contents/Info.plist")
    try:
        with plist_path.open("rb") as handle:
            value = plistlib.load(handle).get("CFBundleShortVersionString", "")
    except (OSError, ValueError, plistlib.InvalidFileException):
        value = ""
    return str(value).strip()


def user_agent_variants() -> tuple[str, ...]:
    version = chrome_version()
    variants = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    ]
    if version and re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
        variants.append(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{version} Safari/537.36"
        )
    return tuple(dict.fromkeys(variants))


def storage_roots() -> Iterable[Path]:
    chrome_root = Path.home() / "Library/Application Support/Google/Chrome"
    for profile in ("Default", "Guest Profile"):
        yield chrome_root / profile / "Local Storage" / "leveldb"
        yield chrome_root / profile / "Session Storage" / "leveldb"
    try:
        for profile in chrome_root.glob("Profile *"):
            yield profile / "Local Storage" / "leveldb"
            yield profile / "Session Storage" / "leveldb"
    except OSError:
        return


def _decoded_objects(cipher: bytes, hosts: Iterable[str], uas: Iterable[str]) -> Iterable[Any]:
    for host in hosts:
        for user_agent in uas:
            mask = f"{STORAGE_PREFIX}|{host}|{user_agent}".encode("utf-8")
            plain = bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(cipher))
            try:
                yield json.loads(plain.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue


def iter_management_keys() -> Iterable[str]:
    hosts = tuple(
        item.strip()
        for item in os.environ.get("CLIPROXY_MANAGEMENT_HOSTS", ",".join(DEFAULT_HOSTS)).split(",")
        if item.strip()
    )
    uas = user_agent_variants()
    seen: set[str] = set()
    for root in storage_roots():
        try:
            paths = sorted(root.glob("*.ldb")) + sorted(root.glob("*.log"))
        except OSError:
            continue
        for path in paths:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            offset = 0
            while True:
                offset = data.find(STORAGE_MARKER, offset)
                if offset < 0:
                    break
                end = offset + len(STORAGE_MARKER)
                while end < len(data) and data[end] in BASE64_BYTES:
                    end += 1
                try:
                    cipher = base64.b64decode(data[offset + len(STORAGE_MARKER) : end], validate=True)
                except (ValueError, base64.binascii.Error):
                    offset = end
                    continue
                for value in _decoded_objects(cipher, hosts, uas):
                    objects = [value]
                    if isinstance(value, dict) and isinstance(value.get("state"), dict):
                        objects.append(value["state"])
                    for obj in objects:
                        candidate = obj.get("managementKey") if isinstance(obj, dict) else None
                        if not isinstance(candidate, str):
                            continue
                        candidate = candidate.strip()
                        if not candidate or len(candidate) > 4096 or candidate in seen:
                            continue
                        if not all(32 <= ord(char) < 127 for char in candidate):
                            continue
                        seen.add(candidate)
                        yield candidate
                offset = end


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start usage meter using Chrome's existing localhost management session")
    parser.add_argument("meter_args", nargs=argparse.REMAINDER, help="Arguments passed to start_cliproxy_usage_meter.sh")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key = next(iter_management_keys(), None)
    if key is None:
        print("no Chrome management session key found", file=sys.stderr)
        return 2
    environment = os.environ.copy()
    environment.pop("CLIPROXY_MANAGEMENT_KEY_FILE", None)
    environment["CLIPROXY_MANAGEMENT_KEY"] = key
    os.chdir(ROOT)
    os.execvpe(str(START_SCRIPT), [str(START_SCRIPT), *args.meter_args], environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
