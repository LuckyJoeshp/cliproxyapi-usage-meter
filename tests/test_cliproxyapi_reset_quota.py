from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import cliproxyapi_reset_quota as reset
from scripts import cliproxyapi_quota_guard as guard
from scripts.cliproxy_usage_meter import AccountIdentity


class FakeResolver:
    def __init__(self, aliases: dict[str, str]):
        self.aliases = aliases

    def resolve_auth_file(self, name: str) -> AccountIdentity:
        return AccountIdentity(self.aliases.get(name), None, None)


def locked_item(name: str, index: str = "index-1") -> dict[str, object]:
    return {
        "name": name,
        "id": "auth-id-1",
        "auth_index": index,
        "provider": "codex",
        "unavailable": True,
        "next_retry_after": "2030-01-02T03:04:05Z",
        "status_message": '{"error":{"type":"usage_limit_reached"}}',
    }


class CLIProxyQuotaResetTest(unittest.TestCase):
    def test_parse_loopback_url_rejects_remote_and_credentials(self) -> None:
        for value in (
            "https://example.com",
            "http://user:pass@127.0.0.1:8317",
            "http://127.0.0.1:8317/v0/management",
        ):
            with self.subTest(value=value), self.assertRaises(reset.QuotaResetError):
                reset.parse_loopback_base_url(value)
        parsed = reset.parse_loopback_base_url("http://localhost:8317")
        self.assertEqual(parsed.hostname, "localhost")

    def test_owner_key_file_requires_mode_600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "management.key"
            path.write_text("fixture-secret\n", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(reset.QuotaResetError):
                reset.load_owner_key_file(path)
            path.chmod(0o600)
            self.assertEqual(reset.load_owner_key_file(path), "fixture-secret")

    def test_select_target_prefers_exact_and_supports_alias(self) -> None:
        first = locked_item("codex-user-one@example.test.json", "index-1")
        second = locked_item("codex-user-two@example.test.json", "index-2")
        second["id"] = "auth-id-2"
        resolver = FakeResolver(
            {
                "codex-user-one@example.test.json": "codex-1",
                "codex-user-two@example.test.json": "codex-2",
            }
        )
        self.assertIs(reset.select_target([first, second], "index-1", resolver), first)
        self.assertIs(reset.select_target([first, second], "codex-2", resolver), second)

    def test_alias_ambiguity_fails_closed(self) -> None:
        first = locked_item("first.json", "index-1")
        second = locked_item("second.json", "index-2")
        second["id"] = "auth-id-2"
        resolver = FakeResolver({"first.json": "codex-1", "second.json": "codex-1"})
        with self.assertRaises(reset.QuotaResetError):
            reset.select_target([first, second], "codex-1", resolver)

    def test_quota_lock_requires_unavailable_deadline_and_usage_marker(self) -> None:
        item = locked_item("fixture.json")
        self.assertEqual(reset.quota_lock_deadline(item), "2030-01-02T03:04:05Z")
        item["status_message"] = "transient upstream error"
        self.assertIsNone(reset.quota_lock_deadline(item))
        item["status_message"] = "quota exhausted"
        item["unavailable"] = False
        self.assertIsNone(reset.quota_lock_deadline(item))

    def test_dry_run_never_posts_reset(self) -> None:
        item = locked_item("fixture.json")
        inventory = {"files": [item]}
        calls: list[tuple[str, str]] = []

        def fake_request(parsed, key, method, path, payload=None, *, timeout=10.0):
            del parsed, key, payload, timeout
            calls.append((method, path))
            return 200, inventory

        fake_resolver = FakeResolver({"fixture.json": "codex-1"})
        with mock.patch.object(reset, "load_management_key", return_value="fixture-key"), mock.patch.object(
            reset, "management_request", side_effect=fake_request
        ), mock.patch.object(reset, "AccountResolver", return_value=fake_resolver), mock.patch(
            "builtins.print"
        ):
            code = reset.main(["codex-1", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("GET", "/v0/management/auth-files")])

    def test_reset_posts_only_opaque_auth_index(self) -> None:
        item = locked_item("fixture.json", "opaque-index")
        requests: list[tuple[str, str, object]] = []

        def fake_request(parsed, key, method, path, payload=None, *, timeout=10.0):
            del parsed, key, timeout
            requests.append((method, path, payload))
            if method == "GET":
                return 200, {"files": [item]}
            return 200, {"status": "ok"}

        fake_resolver = FakeResolver({"fixture.json": "codex-1"})
        with mock.patch.object(reset, "load_management_key", return_value="fixture-key"), mock.patch.object(
            reset, "management_request", side_effect=fake_request
        ), mock.patch.object(reset, "AccountResolver", return_value=fake_resolver), mock.patch(
            "builtins.print"
        ):
            code = reset.main(["codex-1"])
        self.assertEqual(code, 0)
        self.assertEqual(
            requests,
            [
                ("GET", "/v0/management/auth-files", None),
                ("POST", "/v0/management/reset-quota", {"auth_index": "opaque-index"}),
            ],
        )

    def test_key_environment_is_used_without_chrome_scan(self) -> None:
        with mock.patch.dict(os.environ, {"FIXTURE_MANAGEMENT_KEY": "fixture-key"}, clear=False):
            key = reset.load_management_key(
                key_file=None,
                key_env="FIXTURE_MANAGEMENT_KEY",
                from_chrome=False,
            )
        self.assertEqual(key, "fixture-key")

    def test_guard_only_lock_restores_weight_after_official_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "guard-locks.json"
            item = locked_item("fixture.json", "opaque-index")
            item["unavailable"] = False
            item.pop("next_retry_after")
            item["status_message"] = ""
            item["weight"] = 0
            lock = guard.GuardLock(
                auth_index="opaque-index",
                identity_key="subscription:" + "a" * 64,
                locked_until="2030-01-02T03:04:05Z",
                locked_at="2030-01-01T00:00:00Z",
                original_weight=None,
            )
            guard.save_guard_locks(state_path, {lock.auth_index: lock})
            requests: list[tuple[str, str, object]] = []

            def fake_request(parsed, key, method, path, payload=None, *, timeout=10.0):
                del parsed, key, timeout
                requests.append((method, path, payload))
                if method == "GET":
                    return 200, {"files": [item]}
                return 200, {"status": "ok"}

            fake_resolver = FakeResolver({"fixture.json": "codex-1"})
            with mock.patch.object(reset, "load_management_key", return_value="fixture-key"), mock.patch.object(
                reset, "management_request", side_effect=fake_request
            ), mock.patch.object(reset, "AccountResolver", return_value=fake_resolver), mock.patch(
                "builtins.print"
            ):
                code = reset.main(
                    [
                        "codex-1",
                        "--quota-guard-state-file",
                        str(state_path),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(
                requests,
                [
                    ("GET", "/v0/management/auth-files", None),
                    (
                        "POST",
                        "/v0/management/reset-quota",
                        {"auth_index": "opaque-index"},
                    ),
                    (
                        "PATCH",
                        "/v0/management/auth-files/fields",
                        {"name": "fixture.json", "weight": None},
                    ),
                ],
            )
            self.assertEqual(guard.load_guard_locks(state_path), {})


if __name__ == "__main__":
    unittest.main()
