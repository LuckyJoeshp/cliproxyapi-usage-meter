from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import TestCase, mock

from scripts import cockpit_tools_api as api


SYNTHETIC_KEY = "agt_codex_synthetic_key_for_tests_only"


class _ModelsHandler(BaseHTTPRequestHandler):
    response_status = 200
    response_body: bytes = b'{"object":"list","data":[{"id":"synthetic-model"}]}'
    seen_authorization = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        type(self).seen_authorization = self.headers.get("Authorization", "")
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).response_body)))
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, *_args: Any) -> None:
        return


class CockpitToolsApiTest(TestCase):
    def _state(self, root: Path, value: dict[str, Any]) -> Path:
        path = root / "codex_local_access.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def _server(self) -> tuple[ThreadingHTTPServer, threading.Thread]:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ModelsHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        return server, thread

    def test_current_state_shape_is_capability_based_and_ignores_new_fields(self) -> None:
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "version": "future-version-does-not-matter",
                    "enabled": True,
                    "port": 54321,
                    "clientBaseUrlHost": "localhost",
                    "apiKey": SYNTHETIC_KEY,
                    "newUnknownField": {"nested": True},
                },
            )
            config = api.load_config(state_file=state)

        self.assertEqual(config.base_url, "http://localhost:54321/v1")
        self.assertEqual(config.port, 54321)
        self.assertTrue(config.enabled)
        self.assertEqual(config.key, SYNTHETIC_KEY)

    def test_nested_snake_case_state_and_key_list_are_supported(self) -> None:
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "collection": {
                        "enabled": True,
                        "api_port": 54322,
                        "client_base_url_host": "127.0.0.1",
                        "api_keys": [
                            {"key": "disabled-synthetic-key", "enabled": False},
                            {"key": SYNTHETIC_KEY, "enabled": True},
                        ],
                    }
                },
            )
            config = api.load_config(state_file=state)

        self.assertEqual(config.base_url, "http://127.0.0.1:54322/v1")
        self.assertEqual(config.key, SYNTHETIC_KEY)

    def test_direct_base_url_alias_is_supported_when_port_is_nested(self) -> None:
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "service": {
                        "base_url": "http://localhost:54324/v1/",
                        "api_key": SYNTHETIC_KEY,
                    },
                    "version": "future",
                },
            )
            config = api.load_config(state_file=state)

        self.assertEqual(config.base_url, "http://localhost:54324/v1")
        self.assertEqual(config.port, 54324)

    def test_check_bypasses_proxy_environment_and_never_prints_key(self) -> None:
        server, _ = self._server()
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "enabled": True,
                    "port": server.server_port,
                    "clientBaseUrlHost": "127.0.0.1",
                    "apiKey": SYNTHETIC_KEY,
                },
            )
            config = api.load_config(state_file=state)
            with mock.patch.dict(
                os.environ,
                {
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1",
                    "ALL_PROXY": "http://127.0.0.1:1",
                },
                clear=False,
            ), mock.patch("sys.stdout.write") as stdout_write:
                self.assertEqual(api.check_service(config, 2), 0)

        self.assertEqual(_ModelsHandler.seen_authorization, f"Bearer {SYNTHETIC_KEY}")
        printed = "".join(call.args[0] for call in stdout_write.call_args_list)
        self.assertNotIn(SYNTHETIC_KEY, printed)
        self.assertIn("1 models", printed)

    def test_live_endpoint_wins_over_a_stale_disabled_flag(self) -> None:
        server, _ = self._server()
        _ModelsHandler.response_status = 200
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "enabled": False,
                    "port": server.server_port,
                    "clientBaseUrlHost": "127.0.0.1",
                    "apiKey": SYNTHETIC_KEY,
                },
            )
            config = api.load_config(state_file=state)
            with mock.patch("builtins.print") as printer:
                self.assertEqual(api.check_service(config, 2), 0)

        message = " ".join(str(arg) for call in printer.call_args_list for arg in call.args)
        self.assertIn("state flag is currently disabled", message)
        self.assertNotIn(SYNTHETIC_KEY, message)

    def test_remote_host_is_rejected_without_echoing_state_contents(self) -> None:
        with TemporaryDirectory() as temp:
            state = self._state(
                Path(temp),
                {
                    "enabled": True,
                    "port": 54323,
                    "clientBaseUrlHost": "remote.example.invalid",
                    "apiKey": SYNTHETIC_KEY,
                },
            )
            with self.assertRaises(api.CockpitApiError) as raised:
                api.load_config(state_file=state)

        self.assertNotIn(SYNTHETIC_KEY, str(raised.exception))

    def test_missing_state_returns_a_safe_error(self) -> None:
        with TemporaryDirectory() as temp:
            with self.assertRaises(api.CockpitApiError) as raised:
                api.load_config(state_file=Path(temp) / "missing.json")
        self.assertIn("state file", str(raised.exception))
