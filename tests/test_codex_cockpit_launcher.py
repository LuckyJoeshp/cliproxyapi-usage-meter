from __future__ import annotations

import json
import os
import stat
import subprocess
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase


ROOT = Path(__file__).parents[1]
LAUNCHER = ROOT / "scripts" / "codex-cockpit"
HELPER = ROOT / "scripts" / "cockpit-tools-api"
SYNTHETIC_KEY = "agt_codex_launcher_synthetic_key"


class _LauncherModelsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_response(200)
        body = b'{"object":"list","data":[{"id":"synthetic-model"}]}'
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class CodexCockpitLauncherTest(TestCase):
    def test_launcher_is_dynamic_and_keeps_the_cli_proxy_profile_as_base(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('--profile "$COCKPIT_CODEX_PROFILE"', text)
        self.assertIn('COCKPIT_CODEX_PROFILE="${COCKPIT_CODEX_PROFILE:-cliproxy}"', text)
        self.assertIn("--strict-config", text)
        self.assertIn("--no-alt-screen", text)
        self.assertIn('auth.command=\\"cockpit-tools-api\\"', text)
        self.assertIn('auth.args=[\\"--token\\"]', text)
        self.assertIn("COCKPIT_CODEX_SKIP_HEALTHCHECK", text)
        self.assertNotIn("50083", text)
        self.assertNotIn("8317", text)
        self.assertNotIn("apiKey=", text)

    def test_wrapper_is_executable_and_loads_a_sibling_module(self) -> None:
        self.assertTrue(HELPER.stat().st_mode & stat.S_IXUSR)
        text = HELPER.read_text(encoding="utf-8")
        self.assertIn("cockpit_tools_api.py", text)
        self.assertNotIn("/Users/", text)

    def test_launcher_passes_runtime_endpoint_without_persisting_the_key(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LauncherModelsHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)

        with TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / "cockpit"
            data_dir.mkdir()
            (data_dir / "codex_local_access.json").write_text(
                json.dumps(
                    {
                        "version": "future",
                        "enabled": True,
                        "port": server.server_port,
                        "clientBaseUrlHost": "127.0.0.1",
                        "apiKey": SYNTHETIC_KEY,
                    }
                ),
                encoding="utf-8",
            )
            codex_home = root / "codex"
            codex_home.mkdir()
            (codex_home / "cliproxy.config.toml").write_text(
                textwrap.dedent(
                    '''\
                    model = "gpt-5.4"
                    model_provider = "cliproxyapi"
                    [model_providers.cliproxyapi]
                    name = "synthetic base"
                    base_url = "http://127.0.0.1:8317/v1"
                    wire_api = "responses"
                    [model_providers.cliproxyapi.auth]
                    command = "synthetic-token"
                    '''
                ),
                encoding="utf-8",
            )
            capture = root / "codex-args.txt"
            fake_codex = root / "fake-codex"
            fake_codex.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CODEX_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_BIN": str(fake_codex),
                    "CODEX_CAPTURE": str(capture),
                    "COCKPIT_TOOLS_DATA_DIR": str(data_dir),
                    "PATH": "/usr/bin:/bin",
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1",
                    "ALL_PROXY": "http://127.0.0.1:1",
                }
            )
            result = subprocess.run(
                ["/bin/zsh", str(LAUNCHER), "--synthetic-argument"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = capture.read_text(encoding="utf-8").splitlines()

        joined = "\n".join(args)
        self.assertIn("--profile", args)
        self.assertIn("cliproxy", args)
        self.assertIn("--strict-config", args)
        self.assertIn("--no-alt-screen", args)
        self.assertIn("--synthetic-argument", args)
        self.assertIn(f'base_url="http://127.0.0.1:{server.server_port}/v1"', joined)
        self.assertIn('auth.command="cockpit-tools-api"', joined)
        self.assertIn('auth.args=["--token"]', joined)
        self.assertNotIn(SYNTHETIC_KEY, joined)
        self.assertNotIn(SYNTHETIC_KEY, result.stdout)
        self.assertNotIn(SYNTHETIC_KEY, result.stderr)
