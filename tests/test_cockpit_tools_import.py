from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import cliproxy_usage_meter as meter


REQUEST_LOG_SCHEMA = """
CREATE TABLE request_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_key TEXT NOT NULL UNIQUE,
  timestamp INTEGER NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  account_id TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  api_key_id TEXT NOT NULL DEFAULT '',
  api_key_label TEXT NOT NULL DEFAULT '',
  client_instance_id TEXT NOT NULL DEFAULT '',
  model_id TEXT NOT NULL DEFAULT '',
  gateway_mode TEXT NOT NULL DEFAULT '',
  request_kind TEXT NOT NULL DEFAULT 'other',
  service_tier TEXT NOT NULL DEFAULT '',
  reasoning_effort TEXT NOT NULL DEFAULT '',
  success INTEGER NOT NULL DEFAULT 0,
  http_status INTEGER,
  error_category TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  reasoning_tokens INTEGER NOT NULL DEFAULT 0,
  token_breakdown_json TEXT NOT NULL DEFAULT '',
  estimated_cost_usd REAL NOT NULL DEFAULT 0,
  model_pricing_version INTEGER NOT NULL DEFAULT 1,
  input_usd_per_million REAL NOT NULL DEFAULT 0,
  output_usd_per_million REAL NOT NULL DEFAULT 0,
  cached_input_usd_per_million REAL
)
"""


class CockpitToolsImporterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.data_dir = self.home / ".antigravity_cockpit"
        self.data_dir.mkdir(parents=True)
        self.localstorage = self.root / "localstorage.sqlite3"
        self.meter_db = self.root / "meter.sqlite"
        self.storage_id = "cockpit-selector-fixture"
        self.workspace_id = "workspace-fixture"
        self.email = "member@example.test"
        self.account_record = {
            "id": self.storage_id,
            "email": self.email,
            "user_id": "user-fixture",
            "account_id": self.workspace_id,
            "plan_type": "pro",
            "subscription_active_until": "2027-01-01T00:00:00Z",
            "usage_updated_at": 1_786_752_000,
            "tokens": {
                "access_token": "fixture-access-token-never-persist",
                "refresh_token": "fixture-refresh-token-never-persist",
            },
            "quota": {
                "hourly_percentage": 75,
                "hourly_reset_time": 1_786_670_000,
                "hourly_window_minutes": 300,
                "hourly_window_present": True,
                "weekly_percentage": 40,
                "weekly_reset_time": 1_787_200_000,
                "weekly_window_minutes": 10_080,
                "weekly_window_present": True,
            },
        }
        self._write_accounts(self.account_record)
        self._create_request_db()
        self.repo = meter.UsageRepository(self.meter_db)
        self.resolver = meter.AccountResolver(
            home=self.home,
            refresh_seconds=0,
            cockpit_tools_data_dir=self.data_dir,
            cockpit_tools_localstorage_db=self.localstorage,
        )
        self.importer = meter.CockpitToolsImporter(
            self.repo,
            self.resolver,
            data_dir=self.data_dir,
            localstorage_db=self.localstorage,
            poll_seconds=1,
        )

    def tearDown(self) -> None:
        self.importer.stop()
        self.temp.cleanup()

    def _write_accounts(
        self,
        *records: dict[str, object],
        index_version: str = "1",
        detail_schema_version: int = 1,
    ) -> None:
        (self.data_dir / meter.COCKPIT_TOOLS_ACCOUNTS_INDEX_NAME).write_text(
            json.dumps(
                {
                    "version": index_version,
                    "detail_schema_version": detail_schema_version,
                    "accounts": [
                        {
                            "id": record["id"],
                            "email": record.get("email"),
                            "plan_type": record.get("plan_type"),
                            "subscription_active_until": record.get(
                                "subscription_active_until"
                            ),
                        }
                        for record in records
                    ],
                }
            ),
            encoding="utf-8",
        )
        with sqlite3.connect(self.localstorage) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS ItemTable "
                "(key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT OR REPLACE INTO ItemTable (key, value) VALUES (?, ?)",
                (
                    meter.COCKPIT_TOOLS_ACCOUNT_CACHE_KEY,
                    json.dumps(list(records)).encode("utf-16le"),
                ),
            )

    def _create_request_db(self) -> None:
        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute(REQUEST_LOG_SCHEMA)

    def _insert_request(
        self,
        event_key: str,
        timestamp: int,
        *,
        pricing_version: int = 1,
        input_rate: float = 2.0,
        cached_rate: float | None = 0.2,
        output_rate: float = 10.0,
        estimated_cost: float = 0.00264,
    ) -> None:
        breakdown = json.dumps(
            {
                "schema_version": 1,
                "quality": "fixture-breakdown-never-persist",
                "input": {
                    "total_tokens": 1000,
                    "uncached_tokens": 700,
                    "cache_read_tokens": 200,
                    "cache_write_tokens": 100,
                },
                "output": {
                    "total_tokens": 100,
                    "non_reasoning_tokens": 50,
                    "reasoning_tokens": 50,
                },
                "unclassified_tokens": 0,
            }
        )
        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute(
                """INSERT INTO request_logs (
                     event_key, timestamp, request_id, account_id, email,
                     api_key_id, api_key_label, client_instance_id, model_id,
                     success, http_status, error_message, latency_ms,
                     input_tokens, output_tokens, total_tokens, cached_tokens,
                     reasoning_tokens, token_breakdown_json, estimated_cost_usd,
                     model_pricing_version, input_usd_per_million,
                     output_usd_per_million, cached_input_usd_per_million
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 200, ?, 123,
                             1000, 100, 1100, 200, 50, ?, ?, ?, ?, ?, ?)""",
                (
                    event_key,
                    timestamp,
                    "request-fixture-never-persist",
                    self.storage_id,
                    self.email,
                    "api-key-id-never-persist",
                    "api-key-label-never-persist",
                    "client-instance-never-persist",
                    "gpt-5.1-codex",
                    "error-body-never-persist",
                    breakdown,
                    estimated_cost,
                    pricing_version,
                    input_rate,
                    output_rate,
                    cached_rate,
                ),
            )

    def _insert_pre_account_rejection(self, event_key: str, timestamp: int) -> None:
        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute(
                """INSERT INTO request_logs (
                     event_key, timestamp, account_id, success, http_status,
                     error_category
                   ) VALUES (?, ?, '', 0, 401, 'auth_failed')""",
                (event_key, timestamp),
            )

    def _usage_rows(self) -> list[sqlite3.Row]:
        with sqlite3.connect(self.meter_db) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute("SELECT * FROM usage_events ORDER BY id").fetchall()

    def test_imports_tokens_frozen_cost_and_quota_without_sensitive_fields(self) -> None:
        raw_event_key = "cockpit-event-key-never-persist"
        self._insert_request(raw_event_key, 1_786_665_600)

        result = self.importer.import_once()
        self.assertEqual((result["imported"], result["scanned"]), (1, 1))
        row = self._usage_rows()[0]
        self.assertEqual(row["source"], meter.COCKPIT_TOOLS_REQUEST_SOURCE)
        self.assertEqual(row["ts"], "2026-08-14T00:00:00Z")
        self.assertEqual(
            (
                row["input_tokens"],
                row["cached_tokens"],
                row["cache_write_tokens"],
                row["output_tokens"],
                row["reasoning_tokens"],
            ),
            (1000, 200, 100, 100, 50),
        )
        self.assertAlmostEqual(row["non_cached_input_cost_usd"], 0.0016)
        self.assertAlmostEqual(row["cached_input_cost_usd"], 0.00004)
        self.assertAlmostEqual(row["output_cost_usd"], 0.001)
        self.assertAlmostEqual(row["estimated_api_cost_usd"], 0.00264)
        self.assertTrue(str(row["identity_key"]).startswith("subscription:"))

        with sqlite3.connect(self.meter_db) as connection:
            quotas = connection.execute(
                """SELECT window_kind, used_percent, remaining_percent,
                          window_seconds, source
                     FROM subscription_quota_snapshots ORDER BY window_kind"""
            ).fetchall()
            import_key = connection.execute(
                "SELECT import_key FROM local_import_records"
            ).fetchone()[0]
            path_key = connection.execute(
                "SELECT path FROM local_import_files"
            ).fetchone()[0]
        self.assertEqual(
            quotas,
            [
                ("five_hour", 25.0, 75.0, 18_000, "cockpit_tools_quota"),
                ("weekly", 60.0, 40.0, 604_800, "cockpit_tools_quota"),
            ],
        )
        self.assertRegex(import_key, r"^cockpit:[0-9a-f]{32}$")
        self.assertRegex(path_key, r"^file:[0-9a-f]{16}$")
        page = meter.dashboard_html(
            self.repo,
            account_resolver=self.resolver,
            cockpit_status=self.importer.status(),
        )
        self.assertIn("Cockpit Tools 只读导入", page)
        self.assertIn("已导入 1 条请求统计", page)

        serialized = b"".join(
            path.read_bytes()
            for path in self.root.glob("meter.sqlite*")
            if path.is_file()
        )
        for forbidden in (
            raw_event_key,
            self.storage_id,
            self.workspace_id,
            self.email,
            "user-fixture",
            "request-fixture-never-persist",
            "api-key-label-never-persist",
            "client-instance-never-persist",
            "error-body-never-persist",
            "fixture-access-token-never-persist",
            "fixture-refresh-token-never-persist",
            "fixture-breakdown-never-persist",
            str(self.data_dir),
        ):
            self.assertNotIn(forbidden.encode(), serialized)

    def test_pre_account_401_is_not_an_account_attempt_or_availability_signal(self) -> None:
        self._insert_request("selected-account-success", 1_786_665_600)
        self._insert_pre_account_rejection(
            "gateway-auth-rejection",
            1_786_665_601_000,
        )

        result = self.importer.import_once()

        self.assertEqual((result["imported"], result["scanned"]), (2, 2))
        rows = self._usage_rows()
        self.assertEqual(
            [(row["status_code"], row["account_attempt"]) for row in rows],
            [(200, 1), (401, 0)],
        )
        summary = self.repo.summary("all")
        self.assertEqual(summary["calls"], 2)
        self.assertEqual(summary["account_attempts"], 1)
        self.assertEqual(summary["successful_calls"], 1)
        self.assertEqual(summary["failed_calls"], 1)
        self.assertEqual(summary["successful_account_attempts"], 1)
        self.assertEqual(summary["failed_account_attempts"], 0)
        self.assertEqual(summary["logical_requests"], 1)
        self.assertEqual(
            [row["status_code"] for row in self.repo.recent(10)],
            [401, 200],
        )
        self.assertEqual(
            [row["status_code"] for row in self.repo.recent_account_attempts(10)],
            [200],
        )
        self.assertEqual(
            [row["model"] for row in self.repo.grouped("all", "model")],
            ["gpt-5.1-codex"],
        )
        now = datetime(2026, 8, 14, 0, 0, 59, tzinfo=timezone.utc)
        self.assertEqual(
            self.repo.response_timeline(1, now=now)["totals"],
            {"status_200": 1, "status_non_200": 1, "total": 2},
        )
        page = meter.dashboard_html(
            self.repo,
            account_resolver=self.resolver,
            cockpit_status=self.importer.status(),
        )
        self.assertIn("账号选择前的网关鉴权拒绝仅保留在 HTTP 时间轴", page)
        self.assertIn("成功 1 · 失败 0 · 请求关联不落库", page)
        self.assertNotIn('<span class="status-pill bad">401</span>', page)

    def test_initialize_repairs_legacy_pre_account_401_classification(self) -> None:
        self._insert_pre_account_rejection("legacy-gateway-rejection", 1_786_665_600)
        self.importer.import_once()
        with sqlite3.connect(self.meter_db) as connection:
            connection.execute(
                "UPDATE usage_events SET account_attempt=1 WHERE status_code=401"
            )

        self.repo.initialize()

        row = self._usage_rows()[0]
        self.assertEqual(row["account_attempt"], 0)
        self.assertEqual(self.repo.summary("all")["account_attempts"], 0)
        now = datetime(2026, 8, 14, 0, 0, 59, tzinfo=timezone.utc)
        self.assertEqual(
            self.repo.response_timeline(1, now=now)["totals"]["status_non_200"],
            1,
        )

    def test_newer_metadata_versions_and_additive_columns_are_accepted(self) -> None:
        self._write_accounts(
            self.account_record,
            index_version="999.0",
            detail_schema_version=999,
        )
        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute(
                "ALTER TABLE request_logs ADD COLUMN future_metric INTEGER DEFAULT 0"
            )
        self._insert_request("future-compatible-event", 1_786_665_600)

        result = self.importer.import_once()

        self.assertEqual((result["imported"], result["scanned"]), (1, 1))
        self.assertEqual(len(self._usage_rows()), 1)
        self.assertTrue(self.resolver.cockpit_inventory()["authoritative"])

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

        with patch.object(meter.sqlite3, "connect", side_effect=locked_connect):
            with meter.open_sqlite_readonly(database) as connection:
                self.assertEqual(
                    connection.execute("SELECT value FROM fixture").fetchone()[0],
                    "safe-fixture",
                )
        self.assertTrue(any("immutable=1" in uri for uri in attempted))

    def test_incremental_import_is_idempotent_and_reprices_in_place(self) -> None:
        self._insert_request("event-one", 1_786_665_600)
        self.assertEqual(self.importer.import_once()["imported"], 1)
        self.assertEqual(self.importer.import_once()["scanned"], 0)
        self._insert_request("event-two", 1_786_665_601_000)
        appended = self.importer.import_once()
        self.assertEqual((appended["imported"], appended["scanned"]), (1, 1))
        self.assertEqual(len(self._usage_rows()), 2)

        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute(
                """UPDATE request_logs
                      SET model_pricing_version=2,
                          input_usd_per_million=4,
                          cached_input_usd_per_million=0.4,
                          output_usd_per_million=20,
                          estimated_cost_usd=0.00528"""
            )
        repriced = self.importer.import_once()
        self.assertEqual((repriced["imported"], repriced["scanned"]), (0, 2))
        rows = self._usage_rows()
        self.assertEqual(len(rows), 2)
        self.assertTrue(
            all(abs(row["estimated_api_cost_usd"] - 0.00528) < 1e-12 for row in rows)
        )

    def test_response_timeline_survives_retirement_and_raw_log_backfill(self) -> None:
        self._insert_request("retired-response-fixture", 1_786_665_600)
        self.assertEqual(self.importer.import_once()["imported"], 1)
        now = datetime(2026, 8, 14, 0, 0, 59, tzinfo=timezone.utc)
        self.assertEqual(
            self.repo.response_timeline(1, now=now)["totals"]["status_200"],
            1,
        )

        identity_key = self._usage_rows()[0]["identity_key"]
        with self.repo.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            removed = self.repo._anonymize_subscription_conn(
                connection,
                identity_key,
            )
        self.assertEqual(removed["usage_events"], 1)
        self.assertEqual(len(self._usage_rows()), 0)
        self.assertEqual(
            self.repo.response_timeline(1, now=now)["totals"]["status_200"],
            1,
        )

        # Simulate upgrading an existing database after its account detail was
        # already retired.  The one-time raw Cockpit replay must restore only
        # the anonymous minute/status observation, never the retired detail.
        with self.repo.connect() as connection:
            connection.execute("DELETE FROM api_response_observations")
            connection.execute(
                "DELETE FROM api_response_backfills WHERE source=?",
                (meter.COCKPIT_TOOLS_REQUEST_SOURCE,),
            )
        replay = self.importer.import_once()
        self.assertEqual((replay["imported"], replay["scanned"]), (0, 1))
        self.assertEqual(len(self._usage_rows()), 0)
        timeline = self.repo.response_timeline(1, now=now)
        self.assertEqual(
            timeline["totals"],
            {
                "status_200": 1,
                "status_non_200": 0,
                "total": 1,
            },
        )

    def test_zero_rate_tokens_stay_unpriced_and_millisecond_time_is_normalized(self) -> None:
        self._insert_request(
            "zero-price",
            1_786_665_601_234,
            input_rate=0,
            cached_rate=None,
            output_rate=0,
            estimated_cost=0,
        )
        self.importer.import_once()
        row = self._usage_rows()[0]
        self.assertEqual(row["ts"], "2026-08-14T00:00:01Z")
        self.assertIsNone(row["estimated_api_cost_usd"])
        self.assertIsNone(row["non_cached_input_cost_usd"])
        self.assertIsNone(row["cached_input_cost_usd"])
        self.assertIsNone(row["output_cost_usd"])

    def test_structured_cockpit_identity_matches_existing_cliproxy_identity(self) -> None:
        proxy_dir = self.home / ".cli-proxy-api"
        proxy_dir.mkdir(parents=True)
        auth_path = proxy_dir / "fixture-member.json"
        auth_path.write_text(
            json.dumps(
                {
                    "type": "codex",
                    "account_id": self.workspace_id,
                    "email": self.email,
                    "access_token": "synthetic-cli-token",
                }
            ),
            encoding="utf-8",
        )
        resolver = meter.AccountResolver(
            home=self.home,
            refresh_seconds=0,
            cockpit_tools_data_dir=self.data_dir,
            cockpit_tools_localstorage_db=self.localstorage,
        )
        cli_identity = resolver.resolve_auth_file(auth_path.name)
        cockpit_identity = resolver.resolve_cockpit_account(self.storage_id)
        self.assertEqual(
            cli_identity.subscription_id_hash,
            cockpit_identity.subscription_id_hash,
        )
        self.assertEqual(len(resolver.active_subscription_keys()), 1)
        self.assertTrue(resolver.cockpit_inventory()["authoritative"])

    def test_inventory_reconciles_union_of_cliproxy_and_cockpit_accounts(self) -> None:
        proxy_dir = self.home / ".cli-proxy-api"
        proxy_dir.mkdir(parents=True)
        (proxy_dir / "other-member.json").write_text(
            json.dumps(
                {
                    "type": "codex",
                    "account_id": "other-workspace-fixture",
                    "email": "other-member@example.test",
                    "access_token": "synthetic-other-token",
                }
            ),
            encoding="utf-8",
        )
        resolver = meter.AccountResolver(
            home=self.home,
            refresh_seconds=0,
            cockpit_tools_data_dir=self.data_dir,
            cockpit_tools_localstorage_db=self.localstorage,
        )
        importer = meter.CockpitToolsImporter(
            self.repo,
            resolver,
            data_dir=self.data_dir,
            localstorage_db=self.localstorage,
        )
        importer.import_once()
        expected = resolver.active_subscription_keys()
        self.assertEqual(len(expected), 2)
        with sqlite3.connect(self.meter_db) as connection:
            active = {
                row[0]
                for row in connection.execute(
                    """SELECT identity_key FROM active_subscription_registry
                         WHERE state='active'"""
                )
            }
        self.assertEqual(active, expected)

    def test_fallback_identity_migrates_when_structured_cache_arrives(self) -> None:
        sparse = dict(self.account_record)
        sparse.pop("account_id")
        sparse.pop("user_id")
        self._write_accounts(sparse)
        self._insert_request("identity-migration-event", 1_786_665_600)
        self.importer.import_once()
        old_key = self._usage_rows()[0]["identity_key"]

        self._write_accounts(self.account_record)
        self.importer.import_once()
        new_identity = self.resolver.resolve_cockpit_account(self.storage_id)
        new_key = f"subscription:{new_identity.subscription_id_hash}"
        self.assertNotEqual(old_key, new_key)
        self.assertEqual(self._usage_rows()[0]["identity_key"], new_key)

    def test_bad_schema_is_isolated_in_background_health(self) -> None:
        with sqlite3.connect(
            self.data_dir / meter.COCKPIT_TOOLS_LOG_DB_NAME
        ) as connection:
            connection.execute("DROP TABLE request_logs")
            connection.execute("CREATE TABLE request_logs (id INTEGER PRIMARY KEY)")
        self.importer.start()
        deadline = time.monotonic() + 2
        status: dict[str, object] = {}
        while time.monotonic() < deadline:
            status = self.importer.status()
            if status.get("last_error_type"):
                break
            time.sleep(0.02)
        self.assertEqual(status.get("last_error_type"), "ValueError")
        self.assertNotIn(str(self.data_dir), json.dumps(status))

    def test_malformed_account_cache_fails_closed_without_blocking_usage(self) -> None:
        with sqlite3.connect(self.localstorage) as connection:
            connection.execute(
                "UPDATE ItemTable SET value=? WHERE key=?",
                (b"{\x00", meter.COCKPIT_TOOLS_ACCOUNT_CACHE_KEY),
            )
        inventory = self.resolver.cockpit_inventory(force_refresh=True)
        self.assertTrue(inventory["detected"])
        self.assertFalse(inventory["authoritative"])
        self._insert_request("malformed-cache-event", 1_786_665_600)
        result = self.importer.import_once()
        self.assertEqual(result["imported"], 1)
        self.assertEqual(len(self._usage_rows()), 1)


if __name__ == "__main__":
    unittest.main()
