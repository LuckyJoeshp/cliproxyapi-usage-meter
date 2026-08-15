from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest import mock

from scripts import cliproxyapi_quota_guard as guard


IDENTITY = "subscription:" + "a" * 64
AUTH_INDEX = "opaque-index"


class FakeRepo:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def latest_subscription_quotas(self):
        return list(self.rows)


class FakeManagement:
    def __init__(
        self, *, strategy: str = "weighted-round-robin", weight_marker="missing"
    ):
        self.strategy = strategy
        self.item = {
            "name": "fixture-codex.json",
            "provider": "codex",
            "auth_index": AUTH_INDEX,
        }
        if weight_marker != "missing":
            self.item["weight"] = weight_marker
        self.calls: list[tuple[str, str, object]] = []

    def __call__(self, key, method, path, payload):
        self.assert_key_is_fixture(key)
        self.calls.append((method, path, payload))
        if method == "GET" and path == "/v0/management/routing/strategy":
            return 200, {"strategy": self.strategy}
        if method == "GET" and path.startswith("/v0/management/auth-files?"):
            query = parse_qs(urlsplit(path).query)
            if query.get("auth_index") == [AUTH_INDEX]:
                return 200, {"files": [dict(self.item)]}
            return 200, {"files": []}
        if method == "PATCH" and path == "/v0/management/auth-files/fields":
            if payload.get("name") != self.item["name"]:
                return 404, {"error": "not found"}
            if payload.get("weight") is None:
                self.item.pop("weight", None)
            else:
                self.item["weight"] = payload["weight"]
            return 200, {"status": "ok"}
        if method == "POST" and path == "/v0/management/reset-quota":
            return 200, {"status": "ok"}
        return 404, {"error": "unexpected fixture request"}

    @staticmethod
    def assert_key_is_fixture(key):
        if key != "fixture-management-key":
            raise AssertionError("unexpected management key")


def full_window(now: datetime, *, reset_hours: int = 12) -> dict[str, object]:
    return {
        "identity_key": IDENTITY,
        "fetched_at": guard.utc_text(now - timedelta(minutes=5)),
        "window_kind": "weekly",
        "used_percent": 100,
        "remaining_percent": 0,
        "reset_at": guard.utc_text(now + timedelta(hours=reset_hours)),
    }


class QuotaRoutingGuardTest(unittest.TestCase):
    def test_exact_usage_limit_signal_does_not_treat_zero_percent_as_exhaustion(
        self,
    ) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        exact, deadline = guard.usage_limit_signal(
            {"rate_limit": {"remaining_percent": 0}}, now
        )
        self.assertFalse(exact)
        self.assertIsNone(deadline)
        exact, deadline = guard.usage_limit_signal(
            {"error": {"type": "rate_limit_error", "message": "try later"}}, now
        )
        self.assertFalse(exact)
        self.assertIsNone(deadline)

    def test_usage_limit_signal_prefers_provider_reset_timestamp(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        reset = now + timedelta(hours=3)
        body = json.dumps(
            {
                "error": {
                    "type": "usage_limit_reached",
                    "resets_at": int(reset.timestamp()),
                    "resets_in_seconds": 30,
                }
            }
        )
        exact, deadline = guard.usage_limit_signal(body, now)
        self.assertTrue(exact)
        self.assertEqual(deadline, reset)

    def test_state_file_is_owner_only_and_contains_no_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "locks.json"
            lock = guard.GuardLock(
                auth_index=AUTH_INDEX,
                identity_key=IDENTITY,
                locked_until="2030-01-02T00:00:00Z",
                locked_at="2030-01-01T00:00:00Z",
                original_weight=None,
            )
            guard.save_guard_locks(path, {AUTH_INDEX: lock})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(guard.load_guard_locks(path)[AUTH_INDEX], lock)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("fixture-codex.json", raw)
            self.assertNotIn("@", raw)

    def test_snapshot_deadline_requires_a_fresh_full_window(self) -> None:
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        rows = [
            full_window(now, reset_hours=5),
            {
                **full_window(now, reset_hours=8),
                "window_kind": "monthly",
            },
            {
                **full_window(now, reset_hours=10),
                "identity_key": "subscription:" + "b" * 64,
            },
        ]
        self.assertEqual(
            guard.snapshot_reset_deadline(FakeRepo(rows), IDENTITY, now),
            now + timedelta(hours=8),
        )
        rows[0]["remaining_percent"] = 50
        rows[0]["used_percent"] = 50
        rows[1]["remaining_percent"] = 50
        rows[1]["used_percent"] = 50
        self.assertIsNone(guard.snapshot_reset_deadline(FakeRepo(rows), IDENTITY, now))

    def test_confirmed_429_locks_and_reset_deadline_restores_weight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now_box = [datetime(2030, 1, 1, tzinfo=timezone.utc)]
            state_path = Path(temporary) / "locks.json"
            management = FakeManagement()
            quota_guard = guard.QuotaRoutingGuard(
                FakeRepo([full_window(now_box[0])]),
                "http://127.0.0.1:8317",
                enabled=True,
                state_file=state_path,
                requester=management,
                now_fn=lambda: now_box[0],
            )
            event = SimpleNamespace(identity_key=IDENTITY)
            record = {
                "failed": True,
                "auth_index": AUTH_INDEX,
                "fail": {
                    "status_code": 429,
                    "body": {"error": {"type": "usage_limit_reached"}},
                },
            }
            self.assertTrue(
                quota_guard.observe_record(record, event, "fixture-management-key")
            )
            self.assertEqual(management.item.get("weight"), 0)
            saved = guard.load_guard_locks(state_path)[AUTH_INDEX]
            self.assertTrue(saved.applied)
            self.assertIsNone(saved.original_weight)

            now_box[0] += timedelta(hours=11)
            self.assertEqual(quota_guard.reconcile("fixture-management-key"), 0)
            self.assertEqual(management.item.get("weight"), 0)
            now_box[0] += timedelta(hours=2)
            self.assertEqual(quota_guard.reconcile("fixture-management-key"), 1)
            self.assertNotIn("weight", management.item)
            self.assertEqual(guard.load_guard_locks(state_path), {})
            self.assertTrue(
                any(
                    method == "POST" and path == "/v0/management/reset-quota"
                    for method, path, _payload in management.calls
                )
            )

    def test_non_weighted_routing_fails_closed_without_editing_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime(2030, 1, 1, tzinfo=timezone.utc)
            management = FakeManagement(strategy="round-robin")
            quota_guard = guard.QuotaRoutingGuard(
                FakeRepo([full_window(now)]),
                "http://localhost:8317",
                enabled=True,
                state_file=Path(temporary) / "locks.json",
                requester=management,
                now_fn=lambda: now,
            )
            record = {
                "failed": True,
                "auth_index": AUTH_INDEX,
                "fail": {
                    "status_code": 429,
                    "body": '{"error":{"type":"usage_limit_reached"}}',
                },
            }
            self.assertFalse(
                quota_guard.observe_record(
                    record,
                    SimpleNamespace(identity_key=IDENTITY),
                    "fixture-management-key",
                )
            )
            self.assertNotIn("weight", management.item)
            self.assertFalse(
                any(method == "PATCH" for method, _path, _payload in management.calls)
            )

    def test_existing_zero_weight_is_never_claimed_by_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime(2030, 1, 1, tzinfo=timezone.utc)
            state_path = Path(temporary) / "locks.json"
            management = FakeManagement(weight_marker=0)
            quota_guard = guard.QuotaRoutingGuard(
                FakeRepo([full_window(now)]),
                "http://127.0.0.1:8317",
                enabled=True,
                state_file=state_path,
                requester=management,
                now_fn=lambda: now,
            )
            record = {
                "failed": True,
                "auth_index": AUTH_INDEX,
                "fail": {
                    "status_code": 429,
                    "body": '{"error":{"type":"usage_limit_reached"}}',
                },
            }
            self.assertFalse(
                quota_guard.observe_record(
                    record,
                    SimpleNamespace(identity_key=IDENTITY),
                    "fixture-management-key",
                )
            )
            self.assertEqual(management.item["weight"], 0)
            self.assertFalse(state_path.exists())

    def test_state_finalize_failure_keeps_pending_restoration_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            now = datetime(2030, 1, 1, tzinfo=timezone.utc)
            state_path = Path(temporary) / "locks.json"
            management = FakeManagement()
            quota_guard = guard.QuotaRoutingGuard(
                FakeRepo([full_window(now)]),
                "http://127.0.0.1:8317",
                enabled=True,
                state_file=state_path,
                requester=management,
                now_fn=lambda: now,
            )
            real_save = guard.save_guard_locks
            save_calls = 0

            def fail_second_save(path, locks):
                nonlocal save_calls
                save_calls += 1
                if save_calls == 2:
                    raise guard.QuotaGuardError("fixture state finalize failure")
                return real_save(path, locks)

            record = {
                "failed": True,
                "auth_index": AUTH_INDEX,
                "fail": {
                    "status_code": 429,
                    "body": '{"error":{"type":"usage_limit_reached"}}',
                },
            }
            with mock.patch.object(
                guard, "save_guard_locks", side_effect=fail_second_save
            ):
                self.assertFalse(
                    quota_guard.observe_record(
                        record,
                        SimpleNamespace(identity_key=IDENTITY),
                        "fixture-management-key",
                    )
                )

            self.assertEqual(management.item.get("weight"), 0)
            self.assertFalse(guard.load_guard_locks(state_path)[AUTH_INDEX].applied)
            self.assertEqual(
                quota_guard.reconcile("fixture-management-key"),
                0,
            )
            self.assertTrue(guard.load_guard_locks(state_path)[AUTH_INDEX].applied)


if __name__ == "__main__":
    unittest.main()
