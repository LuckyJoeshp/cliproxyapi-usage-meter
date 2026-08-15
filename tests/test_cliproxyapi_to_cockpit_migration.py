from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import migrate_cliproxyapi_to_cockpit as migration


class CliProxyApiToCockpitMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_dir = self.root / "cli-proxy-api"
        self.cockpit_dir = self.root / "antigravity-cockpit"
        self.source_dir.mkdir()
        self.cockpit_dir.mkdir()
        self.localstorage = self.root / "localstorage.sqlite3"
        self.history = self.root / "migration-history.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _account(
        email: str,
        account_id: str,
        suffix: str,
        *,
        refresh: str | None = None,
    ) -> dict[str, object]:
        return {
            "type": "codex",
            "email": email,
            "account_id": account_id,
            "id_token": f"id-token-{suffix}",
            "access_token": f"access-token-{suffix}",
            "refresh_token": refresh or f"refresh-token-{suffix}",
            "name": "synthetic fixture",
        }

    def _write_source(self, name: str, account: dict[str, object]) -> None:
        (self.source_dir / name).write_text(
            json.dumps(account), encoding="utf-8"
        )

    def _write_cockpit(self, *accounts: dict[str, object]) -> None:
        index_accounts = [
            {
                "id": account["account_id"],
                "email": account["email"],
                "plan_type": "pro",
            }
            for account in accounts
        ]
        (self.cockpit_dir / "codex_accounts.json").write_text(
            json.dumps({"version": "999", "accounts": index_accounts}),
            encoding="utf-8",
        )
        cache_accounts = []
        for account in accounts:
            cache_accounts.append(
                {
                    "id": account["account_id"],
                    "email": account["email"],
                    "account_id": account["account_id"],
                    "tokens": {
                        "id_token": account["id_token"],
                        "access_token": account["access_token"],
                        "refresh_token": account["refresh_token"],
                    },
                }
            )
        with sqlite3.connect(self.localstorage) as connection:
            connection.execute(
                "CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT INTO ItemTable(key, value) VALUES (?, ?)",
                (
                    migration.COCKPIT_CACHE_KEY,
                    json.dumps(cache_accounts).encode("utf-16le"),
                ),
            )

    def test_plan_selects_only_new_or_changed_credentials(self) -> None:
        identical = self._account("same@example.test", "same-id", "same")
        changed = self._account("changed@example.test", "changed-id", "new")
        old_changed = self._account("changed@example.test", "changed-id", "old")
        new = self._account("new@example.test", "new-id", "new")
        self._write_source("same.json", identical)
        self._write_source("changed.json", changed)
        self._write_source("new.json", new)
        self._write_cockpit(identical, old_changed)

        source = migration.read_source_accounts(self.source_dir)
        cockpit = migration.read_cockpit_snapshot(
            self.cockpit_dir, self.root, self.localstorage
        )
        plan = migration.build_plan(source, cockpit)

        self.assertEqual(plan.summary()["source_accounts"], 3)
        self.assertEqual(plan.summary()["identical_accounts"], 1)
        self.assertEqual(plan.summary()["updated_accounts"], 1)
        self.assertEqual(plan.summary()["new_accounts"], 1)
        self.assertEqual(len(plan.candidates), 2)
        self.assertEqual(
            {account.payload["email"] for account in plan.candidates},
            {"changed@example.test", "new@example.test"},
        )

    def test_shared_workspace_id_does_not_collapse_distinct_members(self) -> None:
        first = self._account("first@example.test", "shared-workspace", "first")
        second = self._account("second@example.test", "shared-workspace", "second")
        self._write_source("first.json", first)
        self._write_source("second.json", second)
        self._write_cockpit(first)

        source = migration.read_source_accounts(self.source_dir)
        cockpit = migration.read_cockpit_snapshot(
            self.cockpit_dir, self.root, self.localstorage
        )
        plan = migration.build_plan(source, cockpit)

        self.assertEqual(plan.source.conflict_count, 0)
        self.assertEqual(plan.reasons["identical"], 1)
        self.assertEqual(plan.reasons["new"], 1)
        self.assertEqual(len(plan.candidates), 1)

    def test_missing_cache_fails_closed_for_existing_accounts(self) -> None:
        existing = self._account("same@example.test", "same-id", "same")
        self._write_source("same.json", existing)
        self._write_cockpit(existing)

        source = migration.read_source_accounts(self.source_dir)
        cockpit = migration.read_cockpit_snapshot(
            self.cockpit_dir, self.root, self.root / "missing.sqlite3"
        )
        plan = migration.build_plan(source, cockpit)

        self.assertFalse(cockpit.cache_available)
        self.assertEqual(len(plan.candidates), 0)
        self.assertEqual(plan.unverified_count, 1)

    def test_history_contains_only_keyed_fingerprints_and_counts(self) -> None:
        account = self._account("private@example.test", "private-id", "secret")
        self._write_source("private.json", account)
        self._write_cockpit()
        source = migration.read_source_accounts(self.source_dir)
        cockpit = migration.read_cockpit_snapshot(
            self.cockpit_dir, self.root, self.localstorage
        )
        plan = migration.build_plan(source, cockpit)
        key = b"synthetic-local-key-which-is-long-enough"
        fingerprints = [migration.account_fingerprint(plan.candidates[0], key)]

        migration.append_history(
            self.history,
            status="dry_run",
            plan=plan,
            fingerprints=fingerprints,
        )

        serialized = self.history.read_bytes()
        self.assertNotIn(b"private@example.test", serialized)
        self.assertNotIn(b"private-id", serialized)
        self.assertNotIn(b"secret", serialized)
        self.assertRegex(serialized.decode("utf-8"), r"[0-9a-f]{64}")
        self.assertEqual(self.history.stat().st_mode & 0o777, 0o600)

    def test_dry_run_does_not_call_open_or_change_cockpit_cache(self) -> None:
        new = self._account("new@example.test", "new-id", "new")
        self._write_source("new.json", new)
        self._write_cockpit()
        before = self.localstorage.read_bytes()

        with patch.object(migration.subprocess, "run") as run_mock:
            result = migration.main(
                [
                    "--source-dir",
                    str(self.source_dir),
                    "--cockpit-data-dir",
                    str(self.cockpit_dir),
                    "--cockpit-localstorage-db",
                    str(self.localstorage),
                    "--history-file",
                    str(self.history),
                    "--json",
                ]
            )

        self.assertEqual(result, 0)
        run_mock.assert_not_called()
        self.assertEqual(before, self.localstorage.read_bytes())
        summary = json.loads(self.history.read_text(encoding="utf-8"))["runs"][-1]
        self.assertEqual(summary["status"], "dry_run")
        self.assertEqual(summary["requested"], 0)

    def test_readonly_wal_lock_uses_immutable_view_without_pending_journal(self) -> None:
        database = self.root / "wal-readonly.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE fixture (value TEXT)")
            connection.execute("INSERT INTO fixture VALUES ('safe-fixture')")
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for sidecar in (
            Path(f"{database}-wal"),
            Path(f"{database}-shm"),
        ):
            sidecar.unlink(missing_ok=True)

        real_connect = sqlite3.connect
        attempted: list[str] = []

        def locked_connect(database_uri: object, *args: object, **kwargs: object):
            if isinstance(database_uri, str):
                attempted.append(database_uri)
                if "immutable=1" not in database_uri:
                    raise sqlite3.OperationalError("simulated WAL sidecar lock")
            return real_connect(database_uri, *args, **kwargs)

        with patch.object(migration.sqlite3, "connect", side_effect=locked_connect):
            with migration._open_sqlite_readonly(database) as connection:
                self.assertEqual(
                    connection.execute("SELECT value FROM fixture").fetchone()[0],
                    "safe-fixture",
                )
        self.assertTrue(any("immutable=1" in uri for uri in attempted))


if __name__ == "__main__":
    unittest.main()
