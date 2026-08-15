from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import cliproxy_usage_meter as meter


def fixture_jwt(claims: dict[str, object]) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"fixture.{payload}.signature"


def subscription_key(label: str) -> str:
    return "subscription:" + hashlib.sha256(label.encode()).hexdigest()[:32]


class SubscriptionPrivacyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.auth_dir = self.home / ".cli-proxy-api"
        self.auth_dir.mkdir(parents=True)
        self.repo = meter.UsageRepository(self.root / "usage.sqlite")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_auth(
        self,
        filename: str,
        *,
        account_id: str,
        principal_id: str,
        email: str | None,
        access_token: str,
        extra: dict[str, object] | None = None,
    ) -> dict[str, object]:
        claims = {
            "sub": f"sub-{principal_id}",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": principal_id,
            },
        }
        data: dict[str, object] = {
            "type": "codex",
            "account_id": account_id,
            "id_token": fixture_jwt(claims),
            "access_token": access_token,
        }
        if email is not None:
            data["email"] = email
        if extra:
            data.update(extra)
        (self.auth_dir / filename).write_text(json.dumps(data), encoding="utf-8")
        return data

    def resolver(self) -> meter.AccountResolver:
        return meter.AccountResolver(home=self.home, refresh_seconds=0)

    def poller(self, resolver: meter.AccountResolver) -> meter.CodexQuotaPoller:
        return meter.CodexQuotaPoller(
            self.repo,
            resolver,
            meter.urlsplit("http://127.0.0.1:8317"),
            key_loader=lambda: "fixture-management",
        )

    def write_codex_alias_auth(
        self,
        alias: str,
        directory: str,
        data: dict[str, object],
    ) -> None:
        codex_home = self.home / directory
        codex_home.mkdir(parents=True, exist_ok=True)
        (codex_home / "auth.json").write_text(json.dumps(data), encoding="utf-8")
        zshrc = self.home / ".zshrc"
        existing = zshrc.read_text(encoding="utf-8") if zshrc.exists() else ""
        zshrc.write_text(
            existing
            + f'alias {alias}="CODEX_HOME=$HOME/{directory} codex"\n',
            encoding="utf-8",
        )

    @staticmethod
    def auth_item(
        filename: str,
        auth_index: str,
        account_id: str,
        email: str,
        *,
        disabled: bool = False,
    ) -> dict[str, object]:
        return {
            "provider": "codex",
            "name": filename,
            "id": filename,
            "auth_index": auth_index,
            "account": email,
            "email": email,
            "disabled": disabled,
            "id_token": {
                "chatgpt_account_id": account_id,
                "plan_type": "team",
            },
        }

    @staticmethod
    def quota_outer(used_percent: float, reset_at: str) -> tuple[int, object]:
        return 200, {
            "status_code": 200,
            "body": json.dumps(
                {
                    "plan_type": "team",
                    "rate_limit": {
                        "secondary_window": {
                            "used_percent": used_percent,
                            "limit_window_seconds": 604800,
                            "reset_at": reset_at,
                        }
                    },
                }
            ),
        }

    def registry_rows(self) -> list[sqlite3.Row]:
        with self.repo.connect() as conn:
            return conn.execute(
                "SELECT * FROM active_subscription_registry ORDER BY identity_key"
            ).fetchall()

    def test_structured_email_sources_are_supported_but_filename_is_never_email(self) -> None:
        account_prefix = "acct-email-source-"
        cases: list[tuple[str, str, dict[str, object]]] = [
            ("top", "top@example.test", {"email": "top@example.test"}),
            (
                "nested",
                "nested@example.test",
                {"tokens": {"email": "nested@example.test"}},
            ),
            (
                "id-root",
                "id-root@example.test",
                {"id_claims": {"email": "id-root@example.test"}},
            ),
            (
                "id-auth",
                "id-auth@example.test",
                {
                    "auth_claims": {
                        "email": "id-auth@example.test",
                    }
                },
            ),
            (
                "id-profile",
                "id-profile@example.test",
                {
                    "profile_claims": {
                        "email": "id-profile@example.test",
                    }
                },
            ),
            (
                "access",
                "access@example.test",
                {"access_claims": {"email": "access@example.test"}},
            ),
        ]
        expected: dict[str, str] = {}
        for index, (label, email, source) in enumerate(cases):
            account_id = f"{account_prefix}{index}"
            principal_id = f"principal-{index}"
            auth_claims = {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": principal_id,
                **source.get("auth_claims", {}),
            }
            id_claims = {
                "sub": f"sub-{principal_id}",
                "https://api.openai.com/auth": auth_claims,
                "https://api.openai.com/profile": source.get("profile_claims", {}),
                **source.get("id_claims", {}),
            }
            data: dict[str, object] = {
                "type": "codex",
                "account_id": account_id,
                "id_token": fixture_jwt(id_claims),
                "access_token": fixture_jwt(source.get("access_claims", {})),
            }
            if "email" in source:
                data["email"] = source["email"]
            if "tokens" in source:
                data["tokens"] = source["tokens"]
            filename = f"structured-{label}.json"
            (self.auth_dir / filename).write_text(json.dumps(data), encoding="utf-8")
            expected[filename] = email

        bait_name = "filename-only-person@example.cpa.2026-08-15_01-02-03.json"
        self.write_auth(
            bait_name,
            account_id="acct-filename-bait",
            principal_id="principal-filename-bait",
            email=None,
            access_token="fixture-bait-token",
        )
        resolver = self.resolver()
        for filename, email in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(resolver.resolve_auth_file(filename).account_email, email)
        bait = resolver.resolve_auth_file(bait_name)
        self.assertIsNone(bait.account_email)
        self.assertIsNotNone(bait.subscription_id_hash)

    def test_same_email_workspace_token_and_filename_rotation_is_one_identity(self) -> None:
        email = "rotating-member@example.test"
        account_id = "acct-rotating-workspace"
        principal_id = "principal-rotating-member"
        old_name = "member@example.cpa.2026-08-14_23-00-00.json"
        new_name = "member@example.cpa.2026-08-15_01-00-00.json"
        self.write_auth(
            old_name,
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token="fixture-old-token",
        )
        self.write_auth(
            new_name,
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token="fixture-new-token",
        )
        resolver = self.resolver()
        old_identity = resolver.resolve_auth_file(old_name)
        new_identity = resolver.resolve_auth_file(new_name)
        stable_key = meter.resolved_identity_key(old_identity)
        self.assertEqual(new_identity.subscription_id_hash, old_identity.subscription_id_hash)
        self.assertEqual(meter.resolved_identity_key(new_identity), stable_key)

        phase = {"files": [
            self.auth_item(old_name, "opaque-old", account_id, email),
            self.auth_item(new_name, "opaque-new", account_id, email),
        ]}
        api_calls: list[str] = []

        def management(
            _key: str,
            method: str,
            _path: str,
            payload: dict[str, object] | None = None,
        ) -> tuple[int, object]:
            if method == "GET":
                return 200, {"files": phase["files"]}
            assert payload is not None
            api_calls.append(str(payload["auth_index"]))
            return self.quota_outer(20, "2026-08-22T00:00:00Z")

        poller = self.poller(resolver)
        with mock.patch.object(poller, "_management_request", side_effect=management), mock.patch.object(
            meter, "utc_now", return_value="2026-08-15T00:00:00Z"
        ):
            self.assertEqual(poller.poll_once("fixture-management"), (1, 1))
        phase["files"] = [self.auth_item(new_name, "opaque-new", account_id, email)]
        with mock.patch.object(poller, "_management_request", side_effect=management), mock.patch.object(
            meter, "utc_now", return_value="2026-08-15T00:05:00Z"
        ):
            self.assertEqual(poller.poll_once("fixture-management"), (1, 1))

        self.assertEqual(api_calls, ["opaque-old", "opaque-new"])
        registry = self.registry_rows()
        self.assertEqual(len(registry), 1)
        self.assertEqual(registry[0]["identity_key"], stable_key)
        self.assertEqual(registry[0]["state"], "active")
        self.assertEqual(registry[0]["consecutive_misses"], 0)
        dump = "\n".join(self._sqlite_dump())
        for raw in (email, "fixture-old-token", "fixture-new-token", old_name, new_name):
            self.assertNotIn(raw, dump)

    def test_structured_email_is_stable_when_provider_subscription_id_rotates(self) -> None:
        account_id = "acct-provider-id-rotation"
        email = "stable-mailbox+team@example.test"
        first_name = "provider-id-first.json"
        second_name = "provider-id-second.json"
        self.write_auth(
            first_name,
            account_id=account_id,
            principal_id="principal-provider-first",
            email=email,
            access_token="fixture-provider-first-token",
            extra={"subscription_id": "provider-subscription-first"},
        )
        self.write_auth(
            second_name,
            account_id=account_id,
            principal_id="principal-provider-second",
            email=email,
            access_token="fixture-provider-second-token",
            extra={"subscription_id": "provider-subscription-second"},
        )
        resolver = self.resolver()
        first = resolver.resolve_auth_file(first_name)
        second = resolver.resolve_auth_file(second_name)
        self.assertEqual(first.account_email, email)
        self.assertEqual(second.account_email, email)
        self.assertEqual(
            meter.resolved_identity_key(first),
            meter.resolved_identity_key(second),
        )

    def test_principal_fallback_is_stable_when_provider_id_rotates_without_email(self) -> None:
        account_id = "acct-principal-fallback"
        principal_id = "principal-stable-fallback"
        names = ("principal-fallback-first.json", "principal-fallback-second.json")
        for index, name in enumerate(names):
            self.write_auth(
                name,
                account_id=account_id,
                principal_id=principal_id,
                email=None,
                access_token=f"fixture-principal-token-{index}",
                extra={"subscription_id": f"provider-rotated-{index}"},
            )
        resolver = self.resolver()
        first = resolver.resolve_auth_file(names[0])
        second = resolver.resolve_auth_file(names[1])
        self.assertEqual(meter.resolved_identity_key(first), meter.resolved_identity_key(second))

    def test_partial_management_claims_do_not_split_a_filename_match(self) -> None:
        filename = "partial-claims.json"
        account_id = "acct-partial-claims"
        principal_id = "principal-partial-claims"
        email = "partial-claims@example.test"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token="fixture-partial-claims-token",
        )
        resolver = self.resolver()
        local = resolver.resolve_auth_file(filename)
        partial = resolver.resolve_auth_file(
            filename,
            account_id=account_id,
            principal_id=principal_id,
        )
        self.assertEqual(meter.resolved_identity_key(partial), meter.resolved_identity_key(local))
        self.assertEqual(partial.account_email, email)

    def test_exact_filename_conflict_is_fail_closed_through_quota_poll(self) -> None:
        filename = "fixture-exact-conflict.json"
        account_id = "acct-exact-conflict"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id="principal-local",
            email="local-member@example.test",
            access_token="fixture-local-conflict-token",
        )
        resolver = self.resolver()
        conflict = resolver.resolve_auth_file(
            filename,
            account_id=account_id,
            account_email="different-member@example.test",
            principal_id="principal-management",
        )
        self.assertIsNone(conflict.subscription_id_hash)

        item = self.auth_item(
            filename,
            "opaque-conflict",
            account_id,
            "different-member@example.test",
        )
        poller = self.poller(resolver)
        with mock.patch.object(
            poller,
            "_management_request",
            return_value=(200, {"files": [item]}),
        ) as management:
            self.assertEqual(poller.poll_once("fixture-management"), (0, 0))
        self.assertEqual(management.call_count, 1)
        self.assertFalse(poller._inventory_result["authoritative"])
        self.assertEqual(self.registry_rows(), [])

    def test_matching_email_tolerates_principal_rotation(self) -> None:
        filename = "fixture-principal-rotation.json"
        account_id = "acct-principal-rotation"
        email = "stable-principal-rotation@example.test"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id="principal-before-rotation",
            email=email,
            access_token="fixture-principal-rotation-token",
        )
        resolver = self.resolver()
        local = resolver.resolve_auth_file(filename)
        rotated = resolver.resolve_auth_file(
            filename,
            account_id=account_id,
            account_email=email,
            principal_id="principal-after-rotation",
        )
        self.assertEqual(
            meter.resolved_identity_key(rotated),
            meter.resolved_identity_key(local),
        )

    def test_richer_proxy_email_upgrades_alias_principal_identity(self) -> None:
        alias = "codex-2"
        account_id = "acct-richer-alias"
        principal_id = "principal-richer-alias"
        email = "richer-alias@example.test"
        token = "fixture-richer-shared-token"
        claims = {
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": principal_id,
            }
        }
        self.write_codex_alias_auth(
            alias,
            ".codex-richer",
            {
                "account_id": account_id,
                "id_token": fixture_jwt(claims),
                "access_token": token,
            },
        )
        filename = "fixture-richer-proxy.json"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token=token,
        )
        resolver = self.resolver()
        alias_identity = resolver.resolve(alias, None)
        file_identity = resolver.resolve_auth_file(filename)
        queue_identity = resolver.resolve_queue(
            filename,
            meter.hashlib.sha256(token.encode()).hexdigest(),
        )
        canonical_key = meter.resolved_identity_key(file_identity)
        old_key = "subscription:" + resolver._private_hash(
            "codex-workspace-principal-v1", account_id, principal_id
        )
        self.assertEqual(meter.resolved_identity_key(alias_identity), canonical_key)
        self.assertEqual(meter.resolved_identity_key(queue_identity), canonical_key)
        self.assertEqual(alias_identity.usage_alias, alias)
        self.assertEqual(resolver.identity_migrations()[old_key], canonical_key)

    def test_proven_active_migration_moves_inventory_authorization_atomically(self) -> None:
        alias = "codex-6"
        account_id = "acct-active-lineage"
        principal_id = "principal-active-lineage"
        email = "active-lineage@example.test"
        token = "fixture-active-lineage-token"
        claims = {
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": principal_id,
            }
        }
        self.write_codex_alias_auth(
            alias,
            ".codex-active-lineage",
            {
                "account_id": account_id,
                "id_token": fixture_jwt(claims),
                "access_token": token,
            },
        )
        self.write_auth(
            "fixture-active-lineage.json",
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token=token,
        )
        resolver = self.resolver()
        canonical = meter.resolved_identity_key(resolver.resolve(alias, None))
        old_key = "subscription:" + resolver._private_hash(
            "codex-workspace-principal-v1", account_id, principal_id
        )
        self.assertEqual(resolver.identity_migrations()[old_key], canonical)

        def seed(repo: meter.UsageRepository) -> None:
            with repo.connect() as conn:
                conn.execute(
                    """INSERT INTO usage_events (
                           ts, identity_key, model, status_code, ok,
                           duration_ms, stream, input_tokens, output_tokens,
                           total_tokens, long_context_pricing_applied,
                           usage_missing, call_count, source
                         ) VALUES ('2026-08-14T00:00:00Z', ?,
                                   'fixture-model', 200, 1, 1, 0, 10, 2,
                                   12, 0, 0, 1, 'usage_queue')""",
                    (old_key,),
                )

        seed(self.repo)
        self.repo.reconcile_subscription_inventory(
            {old_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        self.repo.apply_privacy_minimization(resolver)
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?",
                    (canonical,),
                ).fetchone()[0],
                1,
            )
            registry = conn.execute(
                "SELECT identity_key, state FROM active_subscription_registry"
            ).fetchall()
            self.assertEqual([(row[0], row[1]) for row in registry], [(canonical, "active")])
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM anonymous_usage_daily").fetchone()[0],
                0,
            )

        suspect_repo = meter.UsageRepository(self.root / "suspect-lineage.sqlite")
        seed(suspect_repo)
        survivor = "subscription:" + "f" * 32
        suspect_repo.reconcile_subscription_inventory(
            {old_key, survivor}, "2026-08-15T00:00:00Z", authoritative=True
        )
        suspect_repo.reconcile_subscription_inventory(
            {survivor}, "2026-08-15T00:01:00Z", authoritative=True
        )
        suspect_repo.apply_privacy_minimization(resolver)
        with suspect_repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?",
                    (canonical,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT SUM(calls) FROM anonymous_usage_daily").fetchone()[0],
                1,
            )

    def test_conflicting_structured_identity_never_borrows_token_alias(self) -> None:
        token = "fixture-conflicting-shared-token"
        account_id = "acct-conflicting-shared-token"
        alias = "codex-3"
        alias_claims = {
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_user_id": "principal-alias-owner",
            }
        }
        self.write_codex_alias_auth(
            alias,
            ".codex-conflicting",
            {
                "account_id": account_id,
                "email": "alias-owner@example.test",
                "id_token": fixture_jwt(alias_claims),
                "access_token": token,
            },
        )
        filename = "fixture-conflicting-proxy.json"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id="principal-proxy-owner",
            email="proxy-owner@example.test",
            access_token=token,
        )
        resolver = self.resolver()
        alias_identity = resolver.resolve(alias, None)
        proxy_identity = resolver.resolve_auth_file(filename)
        token_identity = resolver.resolve(None, meter.short_hash(token))
        self.assertNotEqual(
            meter.resolved_identity_key(alias_identity),
            meter.resolved_identity_key(proxy_identity),
        )
        self.assertIsNone(proxy_identity.usage_alias)
        self.assertIsNone(token_identity.subscription_id_hash)

    def test_token_identity_wins_over_conflicting_known_alias(self) -> None:
        identities: dict[str, tuple[str, str, str]] = {
            "codex-4": (
                "acct-alias-token-a",
                "alias-token-a@example.test",
                "fixture-alias-token-a",
            ),
            "codex-5": (
                "acct-alias-token-b",
                "alias-token-b@example.test",
                "fixture-alias-token-b",
            ),
        }
        for alias, (account_id, email, token) in identities.items():
            claims = {
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": account_id,
                    "chatgpt_user_id": f"principal-{alias}",
                }
            }
            self.write_codex_alias_auth(
                alias,
                f".{alias}",
                {
                    "account_id": account_id,
                    "email": email,
                    "id_token": fixture_jwt(claims),
                    "access_token": token,
                },
            )
        resolver = self.resolver()
        expected = resolver.resolve("codex-5", None)
        resolved = resolver.resolve(
            "codex-4", meter.short_hash(identities["codex-5"][2])
        )
        self.assertEqual(
            meter.resolved_identity_key(resolved),
            meter.resolved_identity_key(expected),
        )
        self.assertEqual(resolved.usage_alias, "codex-5")

    def test_stale_valid_queue_digest_never_falls_back_to_reused_filename(self) -> None:
        filename = "fixture-reused-auth-name.json"
        old_token = "fixture-old-reused-token"
        self.write_auth(
            filename,
            account_id="acct-old-reused",
            principal_id="principal-old-reused",
            email="old-reused@example.test",
            access_token=old_token,
        )
        resolver = self.resolver()
        resolver.resolve_auth_file(filename)
        self.write_auth(
            filename,
            account_id="acct-new-reused",
            principal_id="principal-new-reused",
            email="new-reused@example.test",
            access_token="fixture-new-reused-token",
        )
        resolver.active_subscription_keys(force_refresh=True)
        stale = resolver.resolve_queue(
            filename,
            meter.hashlib.sha256(old_token.encode()).hexdigest(),
        )
        filename_only = resolver.resolve_queue(filename, None)
        self.assertIsNone(stale.subscription_id_hash)
        self.assertEqual(filename_only.account_email, "new-reused@example.test")

    def test_same_email_different_workspaces_keep_quota_and_registry_isolated(self) -> None:
        email = "shared-display@example.test"
        principal = "principal-shared-display"
        fixtures = {
            "a": {
                "name": "shared@example.cpa.2026-08-15_03-00-00.json",
                "index": "opaque-workspace-a",
                "account": "acct-workspace-alpha",
                "token": "fixture-workspace-alpha-token",
                "used": 16,
                "reset": "2026-08-22T14:32:00Z",
            },
            "b": {
                "name": "shared@example.cpa.2026-08-15_02-00-00.json",
                "index": "opaque-workspace-beta",
                "account": "acct-workspace-beta",
                "token": "fixture-workspace-beta-token",
                "used": 30,
                "reset": "2026-08-22T14:30:00Z",
            },
        }
        for item in fixtures.values():
            self.write_auth(
                str(item["name"]),
                account_id=str(item["account"]),
                principal_id=principal,
                email=email,
                access_token=str(item["token"]),
            )
        resolver = self.resolver()
        identities = {
            key: resolver.resolve_auth_file(str(item["name"]))
            for key, item in fixtures.items()
        }
        keys = {key: meter.resolved_identity_key(identity) for key, identity in identities.items()}
        self.assertNotEqual(keys["a"], keys["b"])
        files = [
            self.auth_item(str(item["name"]), str(item["index"]), str(item["account"]), email)
            for item in (fixtures["b"], fixtures["a"])
        ]
        calls: list[str] = []

        def management(
            _key: str,
            method: str,
            _path: str,
            payload: dict[str, object] | None = None,
        ) -> tuple[int, object]:
            if method == "GET":
                return 200, {"files": files}
            assert payload is not None
            auth_index = str(payload["auth_index"])
            calls.append(auth_index)
            item = next(value for value in fixtures.values() if value["index"] == auth_index)
            return self.quota_outer(float(item["used"]), str(item["reset"]))

        poller = self.poller(resolver)
        with mock.patch.object(poller, "_management_request", side_effect=management), mock.patch.object(
            meter, "utc_now", return_value="2026-08-15T04:00:00Z"
        ):
            self.assertEqual(poller.poll_once("fixture-management"), (2, 2))

        self.assertEqual(calls, ["opaque-workspace-beta", "opaque-workspace-a"])
        self.assertEqual({row["identity_key"] for row in self.registry_rows()}, set(keys.values()))
        cards = {row["identity_key"]: row for row in self.repo.subscription_dashboard_rows()}
        self.assertEqual(cards[keys["a"]]["windows"]["weekly"]["remaining_percent"], 84)
        self.assertEqual(cards[keys["b"]]["windows"]["weekly"]["remaining_percent"], 70)
        self.assertEqual(cards[keys["a"]]["windows"]["weekly"]["reset_at"], fixtures["a"]["reset"])
        self.assertEqual(cards[keys["b"]]["windows"]["weekly"]["reset_at"], fixtures["b"]["reset"])

    def test_duplicate_identity_tries_next_auth_file_after_stale_credential(self) -> None:
        email = "duplicate-fallback@example.test"
        account_id = "acct-duplicate-fallback"
        principal_id = "principal-duplicate-fallback"
        names = ("duplicate-stale.json", "duplicate-current.json")
        for index, name in enumerate(names):
            self.write_auth(
                name,
                account_id=account_id,
                principal_id=principal_id,
                email=email,
                access_token=f"fixture-duplicate-token-{index}",
            )
        files = [
            self.auth_item(names[0], "opaque-stale", account_id, email),
            self.auth_item(names[1], "opaque-current", account_id, email),
        ]
        calls: list[str] = []

        def management(
            _key: str,
            method: str,
            _path: str,
            payload: dict[str, object] | None = None,
        ) -> tuple[int, object]:
            if method == "GET":
                return 200, {"files": files}
            assert payload is not None
            auth_index = str(payload["auth_index"])
            calls.append(auth_index)
            if auth_index == "opaque-stale":
                return 200, {"status_code": 401, "body": "{}"}
            return self.quota_outer(30, "2026-08-22T00:00:00Z")

        poller = self.poller(self.resolver())
        with mock.patch.object(poller, "_management_request", side_effect=management), mock.patch.object(
            meter, "utc_now", return_value="2026-08-15T00:00:00Z"
        ):
            self.assertEqual(poller.poll_once("fixture-management"), (1, 1))
        self.assertEqual(calls, ["opaque-stale", "opaque-current"])
        self.assertEqual(len(self.repo.latest_subscription_quotas()), 1)

    def test_authoritative_inventory_retires_to_anonymous_aggregate_after_grace(self) -> None:
        active_key = subscription_key("fixture-active")
        retired_key = subscription_key("fixture-to-retire")
        baseline = self.repo.reconcile_subscription_inventory(
            {active_key, retired_key},
            "2026-08-15T00:00:00Z",
            authoritative=True,
        )
        self.assertEqual(
            {key: baseline[key] for key in ("initialized", "active", "suspect", "retired")},
            {"initialized": True, "active": 2, "suspect": 0, "retired": 0},
        )
        event_id = self._seed_identified_history(retired_key)
        before = self.repo.summary("all")
        self.assertEqual(before["streaming_calls"], 2)

        first = self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:01:00Z", authoritative=True
        )
        second = self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:05:00Z", authoritative=True
        )
        third = self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:12:00Z", authoritative=True
        )
        self.assertEqual((first["suspect"], first["retired"]), (1, 0))
        self.assertEqual((second["suspect"], second["retired"]), (1, 0))
        self.assertEqual(third["retired"], 1)

        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM active_subscription_registry WHERE identity_key=?",
                    (retired_key,),
                ).fetchone()[0],
                0,
            )
            for table in (
                "usage_events",
                "quota_events",
                "account_quota_cycles",
                "subscription_quota_snapshots",
            ):
                self.assertEqual(
                    conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE identity_key=?", (retired_key,)
                    ).fetchone()[0],
                    0,
                    table,
                )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM local_import_records WHERE usage_event_id=?", (event_id,)
                ).fetchone()[0],
                0,
            )
            anonymous = conn.execute("SELECT * FROM anonymous_usage_daily").fetchall()
            self.assertEqual(len(anonymous), 1)
            row = anonymous[0]
            self.assertEqual((row["calls"], row["input_tokens"], row["total_tokens"]), (2, 100, 130))
            self.assertAlmostEqual(row["estimated_api_cost_usd"], 1.25)
            anonymous_columns = {
                item[1] for item in conn.execute("PRAGMA table_info(anonymous_usage_daily)")
            }
            self.assertTrue(
                {
                    "identity_key",
                    "usage_alias",
                    "account_id_hash",
                    "auth_fingerprint",
                    "session_id",
                    "request_id",
                    "source",
                }.isdisjoint(anonymous_columns)
            )

        after = self.repo.summary("all")
        for key in (
            "calls",
            "successful_calls",
            "failed_calls",
            "streaming_calls",
            "input_tokens",
            "cached_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "estimated_api_cost_usd",
            "non_cached_input_cost_usd",
            "cached_input_cost_usd",
            "output_cost_usd",
        ):
            self.assertEqual(after[key], before[key], key)
        self.assertNotIn(retired_key, json.dumps(self.repo.recent(100)))
        self.assertNotIn(retired_key, json.dumps(self.repo.subscription_dashboard_rows()))
        self.assertNotIn(retired_key, json.dumps(self.repo.quota_summary("all")))
        dump = "\n".join(self._sqlite_dump())
        for secret in (
            "codex-retired",
            "fixture-auth-fingerprint",
            "fixture-session",
            "fixture-thread",
            "fixture-turn",
            "fixture-project",
            "fixture-request",
            "fixture-error-message",
        ):
            self.assertNotIn(secret, dump)
        again = self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:20:00Z", authoritative=True
        )
        self.assertEqual(again["retired"], 0)

    def test_anonymous_bucket_preserves_per_event_derived_token_totals(self) -> None:
        active_key = subscription_key("fixture-derived-active")
        retired_key = subscription_key("fixture-derived-retired")
        timestamp = meter.utc_now()
        with self.repo.connect() as conn:
            conn.executemany(
                """INSERT INTO usage_events (
                       ts, identity_key, model, status_code, ok, duration_ms,
                       stream, input_tokens, cached_tokens, output_tokens,
                       reasoning_tokens, total_tokens,
                       long_context_pricing_applied, usage_missing, call_count,
                       source
                     ) VALUES (?, ?, 'fixture-inverse-cache', 200, 1, 1,
                               0, ?, ?, ?, 0, ?, 0, 0, 1, 'fixture')""",
                (
                    (timestamp, retired_key, 0, 100, 3, 3),
                    (timestamp, retired_key, 100, 0, 7, 107),
                ),
            )
        self.repo.reconcile_subscription_inventory(
            {active_key, retired_key},
            "2026-08-15T00:00:00Z",
            authoritative=True,
        )

        summary_before = self.repo.summary("all")
        model_before = self.repo.grouped("all", "model")
        daily_before = self.repo.daily_usage(7)
        self.assertEqual(summary_before["non_cached_input_tokens"], 100)
        self.assertEqual(summary_before["codex_status_tokens"], 110)

        for observed in (
            "2026-08-15T00:01:00Z",
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                {active_key}, observed, authoritative=True
            )
        self.assertEqual(result["retired"], 1)

        summary_after = self.repo.summary("all")
        model_after = self.repo.grouped("all", "model")
        daily_after = self.repo.daily_usage(7)
        invariant_fields = (
            "calls",
            "input_tokens",
            "cached_tokens",
            "output_tokens",
            "total_tokens",
            "non_cached_input_tokens",
            "codex_status_tokens",
            "api_processed_tokens",
        )
        for field in invariant_fields:
            self.assertEqual(summary_after[field], summary_before[field], field)
        self.assertEqual(
            [{field: row[field] for field in invariant_fields} for row in model_after],
            [{field: row[field] for field in invariant_fields} for row in model_before],
        )
        self.assertEqual(
            [
                {field: row[field] for field in invariant_fields}
                for row in daily_after
            ],
            [
                {field: row[field] for field in invariant_fields}
                for row in daily_before
            ],
        )

    def test_large_inventory_drop_uses_extended_confirmation_window(self) -> None:
        keys = {subscription_key(f"fixture-bulk-{index}") for index in range(10)}
        survivors = {
            subscription_key("fixture-bulk-0"),
            subscription_key("fixture-bulk-1"),
        }
        self.repo.reconcile_subscription_inventory(
            keys, "2026-08-15T00:00:00Z", authoritative=True
        )
        for observed in (
            "2026-08-15T00:01:00Z",
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
            "2026-08-15T00:20:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                survivors, observed, authoritative=True
            )
            self.assertEqual(result["retired"], 0)
            self.assertEqual(result["suspect"], 8)
        result = self.repo.reconcile_subscription_inventory(
            survivors, "2026-08-15T00:31:00Z", authoritative=True
        )
        self.assertEqual(result["retired"], 8)
        self.assertEqual(result["active"], 2)

    def test_first_inventory_protects_large_historical_drop(self) -> None:
        keys = [f"subscription:{index + 100:032x}" for index in range(10)]
        active = set(keys[:2])
        with self.repo.connect() as conn:
            conn.executemany(
                """INSERT INTO usage_events (
                       ts, identity_key, model, status_code, ok, duration_ms,
                       stream, input_tokens, output_tokens, total_tokens,
                       long_context_pricing_applied, usage_missing, call_count,
                       source
                     ) VALUES ('2026-08-14T00:00:00Z', ?, 'fixture-model',
                               200, 1, 1, 0, 1, 1, 2, 0, 0, 1,
                               'usage_queue')""",
                ((key,) for key in keys),
            )
        initial = self.repo.reconcile_subscription_inventory(
            active, "2026-08-15T00:00:00Z", authoritative=True
        )
        self.assertEqual(initial["suspect"], 8)
        with self.repo.connect() as conn:
            flags = conn.execute(
                """SELECT high_risk_missing
                     FROM active_subscription_registry
                    WHERE state='suspect_missing'"""
            ).fetchall()
        self.assertEqual({row[0] for row in flags}, {1})
        for observed in (
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
            "2026-08-15T00:20:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                active, observed, authoritative=True
            )
            self.assertEqual(result["retired"], 0)
        result = self.repo.reconcile_subscription_inventory(
            active, "2026-08-15T00:31:00Z", authoritative=True
        )
        self.assertEqual(result["retired"], 8)

    def test_same_count_and_half_replacement_keep_missing_keys_high_risk(self) -> None:
        for replacement_count in (5, 10):
            with self.subTest(replacement_count=replacement_count):
                repo = meter.UsageRepository(
                    self.root / f"inventory-churn-{replacement_count}.sqlite"
                )
                old = [
                    f"subscription:{index + 200:032x}" for index in range(10)
                ]
                new = [
                    f"subscription:{index + 300:032x}" for index in range(10)
                ]
                repo.reconcile_subscription_inventory(
                    set(old), "2026-08-15T00:00:00Z", authoritative=True
                )
                active = set(old[replacement_count:]) | set(
                    new[:replacement_count]
                )
                for observed in (
                    "2026-08-15T00:01:00Z",
                    "2026-08-15T00:05:00Z",
                    "2026-08-15T00:12:00Z",
                    "2026-08-15T00:20:00Z",
                ):
                    result = repo.reconcile_subscription_inventory(
                        active, observed, authoritative=True
                    )
                    self.assertEqual(result["retired"], 0)
                    self.assertEqual(result["suspect"], replacement_count)
                result = repo.reconcile_subscription_inventory(
                    active, "2026-08-15T00:31:00Z", authoritative=True
                )
                self.assertEqual(result["retired"], replacement_count)

    def test_high_risk_missing_policy_survives_partial_inventory_recovery(self) -> None:
        keys = {subscription_key(f"fixture-partial-{index}") for index in range(10)}
        initial_survivors = {
            subscription_key("fixture-partial-0"),
            subscription_key("fixture-partial-1"),
        }
        partial_recovery = initial_survivors | {
            subscription_key(f"fixture-partial-{index}") for index in range(2, 6)
        }
        still_missing = keys - partial_recovery
        self.repo.reconcile_subscription_inventory(
            keys, "2026-08-15T00:00:00Z", authoritative=True
        )
        self.repo.reconcile_subscription_inventory(
            initial_survivors, "2026-08-15T00:01:00Z", authoritative=True
        )
        for observed in (
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
            "2026-08-15T00:20:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                partial_recovery, observed, authoritative=True
            )
            self.assertEqual(result["retired"], 0)
            self.assertEqual(result["suspect"], 4)
        with self.repo.connect() as conn:
            rows = conn.execute(
                """SELECT identity_key, state, high_risk_missing
                     FROM active_subscription_registry"""
            ).fetchall()
        registry = {row["identity_key"]: row for row in rows}
        for key in still_missing:
            self.assertEqual(registry[key]["state"], "suspect_missing")
            self.assertEqual(registry[key]["high_risk_missing"], 1)
        for key in partial_recovery:
            self.assertEqual(registry[key]["state"], "active")
            self.assertEqual(registry[key]["high_risk_missing"], 0)
        result = self.repo.reconcile_subscription_inventory(
            partial_recovery, "2026-08-15T00:31:00Z", authoritative=True
        )
        self.assertEqual(result["retired"], 4)

    def test_initialized_inventory_rejects_unknown_key_until_authoritative_appearance(self) -> None:
        active_key = subscription_key("fixture-allow-listed")
        unknown_key = subscription_key("fixture-not-in-inventory")
        self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        info = meter.RequestInfo(
            "/v1/responses", "POST", "fixture-model", 0,
            None, None, None, None, None, None, None, None, None, None,
            unknown_key,
        )
        self.repo.record_event(
            self._usage_event(unknown_key), info, source="usage_queue"
        )
        self.repo.insert_subscription_quota_snapshot(
            {
                "fetched_at": "2026-08-15T00:01:00Z",
                "identity_key": unknown_key,
                "window_kind": "weekly",
                "used_percent": 20,
                "remaining_percent": 80,
                "source": "cliproxy_wham_usage",
            }
        )
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT identity_key FROM usage_events ORDER BY id DESC LIMIT 1"
                ).fetchone()[0],
                "unknown",
            )
            self.assertEqual(
                conn.execute(
                    """SELECT COUNT(*) FROM subscription_quota_snapshots
                         WHERE identity_key=?""",
                    (unknown_key,),
                ).fetchone()[0],
                0,
            )

        self.repo.reconcile_subscription_inventory(
            {active_key, unknown_key},
            "2026-08-15T00:02:00Z",
            authoritative=True,
        )
        self.repo.record_event(
            self._usage_event(unknown_key), info, source="usage_queue"
        )
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    """SELECT COUNT(*) FROM usage_events
                         WHERE identity_key=?""",
                    (unknown_key,),
                ).fetchone()[0],
                1,
            )

    def test_suspect_missing_rejects_late_identity_detail_and_quota(self) -> None:
        active_key = subscription_key("fixture-still-active")
        missing_key = subscription_key("fixture-late-record")
        self.repo.reconcile_subscription_inventory(
            {active_key, missing_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:01:00Z", authoritative=True
        )
        info = meter.RequestInfo(
            "/v1/responses", "POST", "fixture-model", 0,
            "private-session", "private-thread", "private-turn", None, None,
            "codex-private", "private-project", "private-fingerprint",
            "private-account-hash", "TAIL1234", missing_key,
        )
        event = self._usage_event(missing_key)
        self.repo.record_event(event, info, source="usage_queue")
        self.repo.insert_subscription_quota_snapshot(
            {
                "fetched_at": "2026-08-15T00:01:30Z",
                "identity_key": missing_key,
                "window_kind": "weekly",
                "used_percent": 50,
                "remaining_percent": 50,
                "source": "cliproxy_wham_usage",
            }
        )
        with self.repo.connect() as conn:
            row = conn.execute(
                "SELECT * FROM usage_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertEqual(row["identity_key"], "unknown")
            for field in (
                "usage_alias", "auth_fingerprint", "account_id_hash",
                "account_id_tail", "session_id", "thread_id", "turn_id",
                "usage_project", "request_id",
            ):
                self.assertIsNone(row[field], field)
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM subscription_quota_snapshots WHERE identity_key=?",
                    (missing_key,),
                ).fetchone()[0],
                0,
            )

    def test_retired_tombstone_blocks_replay_until_complete_reappearance(self) -> None:
        active_key = subscription_key("fixture-tombstone-active")
        retired_key = subscription_key("fixture-tombstone-retired")
        self.repo.reconcile_subscription_inventory(
            {active_key, retired_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        for observed in (
            "2026-08-15T00:01:00Z",
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                {active_key}, observed, authoritative=True
            )
        self.assertEqual(result["retired"], 1)
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM retired_subscription_tombstones WHERE identity_key=?",
                    (retired_key,),
                ).fetchone()[0],
                1,
            )

        info = meter.RequestInfo(
            "/v1/responses", "POST", "fixture-model", 0,
            None, None, None, None, None, None, None, None, None, None,
            retired_key,
        )
        self.repo.record_event(self._usage_event(retired_key), info, source="usage_queue")
        self.repo.record_imported_event(
            self._usage_event(retired_key), "fixture-retired-replay", "fixture"
        )
        self.repo.insert_subscription_quota_snapshot(
            {
                "fetched_at": "2026-08-15T00:13:00Z",
                "identity_key": retired_key,
                "window_kind": "weekly",
                "used_percent": 10,
                "remaining_percent": 90,
                "source": "cliproxy_wham_usage",
            }
        )
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?", (retired_key,)
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key='unknown'"
                ).fetchone()[0],
                2,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM subscription_quota_snapshots WHERE identity_key=?",
                    (retired_key,),
                ).fetchone()[0],
                0,
            )

        self.repo.reconcile_subscription_inventory(
            {active_key, retired_key}, "2026-08-15T00:20:00Z", authoritative=True
        )
        self.repo.record_event(self._usage_event(retired_key), info, source="usage_queue")
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM retired_subscription_tombstones WHERE identity_key=?",
                    (retired_key,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?", (retired_key,)
                ).fetchone()[0],
                1,
            )

    def test_import_and_legacy_migration_keep_only_minimized_statistics(self) -> None:
        canonical_key = subscription_key("fixture-import")
        imported = self._usage_event(canonical_key)
        self.assertTrue(
            self.repo.record_imported_event(imported, "fixture-import-dedup", "fixture")
        )
        raw_path = self.root / "sessions" / "fixture.jsonl"
        self.repo.save_local_import_file_state(
            {"path": raw_path, "size": 10, "mtime_ns": 20, "offset": 10}
        )
        state = self.repo.local_import_file_state(raw_path)
        assert state is not None
        self.repo.save_local_import_file_state(state)
        with self.repo.connect() as conn:
            row = conn.execute("SELECT * FROM usage_events").fetchone()
            for field in (
                "endpoint", "method", "usage_alias", "usage_project",
                "auth_fingerprint", "account_id_hash", "account_id_tail",
                "session_id", "thread_id", "turn_id", "installation_id",
                "window_id", "error_message_redacted", "request_id",
            ):
                self.assertIsNone(row[field], field)
            self.assertEqual(row["request_bytes"], 0)
            self.assertEqual(row["response_bytes"], 0)
            paths = conn.execute("SELECT path FROM local_import_files").fetchall()
            self.assertEqual(len(paths), 1)
            self.assertRegex(paths[0]["path"], r"^file:[0-9a-f]{16}$")

        orphan_key = "account:fixture-unproven-orphan"
        self._seed_identified_history(orphan_key)
        before = self.repo.summary("all")
        self.repo.apply_privacy_minimization(self.resolver())
        after = self.repo.summary("all")
        self.assertEqual(after["calls"], before["calls"])
        self.assertEqual(after["total_tokens"], before["total_tokens"])
        self.assertEqual(after["estimated_api_cost_usd"], before["estimated_api_cost_usd"])
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?", (orphan_key,)
                ).fetchone()[0],
                0,
            )
        database_bytes = self.repo.path.read_bytes()
        wal_path = Path(str(self.repo.path) + "-wal")
        wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""
        for marker in (
            b"fixture-auth-fingerprint",
            b"fixture-session",
            b"fixture-project",
            b"fixture-error-message",
        ):
            self.assertNotIn(marker, database_bytes)
            self.assertNotIn(marker, wal_bytes)

    def test_workspace_only_legacy_history_is_never_assigned_to_visible_member(self) -> None:
        filename = "only-visible-member.json"
        account_id = "acct-one-visible-member"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id="principal-one-visible-member",
            email="one-visible-member@example.test",
            access_token="fixture-one-visible-token",
        )
        resolver = self.resolver()
        identity = resolver.resolve_auth_file(filename)
        legacy_key = f"account:{identity.account_id_hash}"
        canonical_key = meter.resolved_identity_key(identity)
        self._seed_identified_history(legacy_key)
        self.repo.apply_privacy_minimization(resolver)
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?", (canonical_key,)
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT SUM(calls) FROM anonymous_usage_daily").fetchone()[0],
                2,
            )

    def test_conflicting_email_upgrade_never_guesses_legacy_principal_owner(self) -> None:
        account_id = "acct-conflicting-email"
        principal_id = "principal-conflicting-email"
        for index, email in enumerate(
            ("first-conflict@example.test", "second-conflict@example.test")
        ):
            self.write_auth(
                f"conflict-{index}.json",
                account_id=account_id,
                principal_id=principal_id,
                email=email,
                access_token=f"fixture-conflict-token-{index}",
            )
        resolver = self.resolver()
        identity = resolver.resolve_auth_file("conflict-0.json")
        assert identity.legacy_subscription_id_hash is not None
        legacy_key = f"subscription:{identity.legacy_subscription_id_hash}"
        keyed_principal_fallback = "subscription:" + resolver._private_hash(
            "codex-workspace-principal-v1", account_id, principal_id
        )
        self.assertNotIn(legacy_key, resolver.identity_migrations())
        self.assertNotIn(keyed_principal_fallback, resolver.identity_migrations())
        self.assertIn(legacy_key, resolver.ambiguous_legacy_identity_keys())
        self.assertIn(
            keyed_principal_fallback,
            resolver.ambiguous_legacy_identity_keys(),
        )
        self._seed_identified_history(legacy_key)
        self.repo.apply_privacy_minimization(resolver)
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM usage_events WHERE identity_key=?", (legacy_key,)
                ).fetchone()[0],
                0,
            )

    def test_quota_metadata_carries_forward_when_new_claims_are_sparse(self) -> None:
        key = subscription_key("fixture-metadata-continuity")
        common = {
            "identity_key": key,
            "window_kind": "weekly",
            "used_percent": 10,
            "remaining_percent": 90,
            "source": "cliproxy_wham_usage",
        }
        # Model sparse rows written by older builds: the newest known plan and
        # newest known renewal can live on different snapshots.  Backfill must
        # search each field independently rather than copy one previous row.
        with self.repo.connect() as conn:
            conn.execute(
                """INSERT INTO subscription_quota_snapshots (
                       fetched_at, identity_key, plan_type, window_kind,
                       used_percent, remaining_percent, source)
                   VALUES ('2026-08-15T00:00:00Z', ?, 'team', 'weekly',
                           10, 90, 'cliproxy_wham_usage')""",
                (key,),
            )
            conn.execute(
                """INSERT INTO subscription_quota_snapshots (
                       fetched_at, identity_key, subscription_active_until,
                       window_kind, used_percent, remaining_percent, source)
                   VALUES ('2026-08-15T00:03:00Z', ?,
                           '2026-09-15T00:00:00Z', 'five_hour', 20, 80,
                           'cliproxy_wham_usage')""",
                (key,),
            )
        self.repo.insert_subscription_quota_snapshot(
            {**common, "fetched_at": "2026-08-15T00:05:00Z"}
        )
        latest = next(
            row
            for row in self.repo.latest_subscription_quotas()
            if row["window_kind"] == "weekly"
        )
        self.assertEqual(latest["plan_type"], "team")
        self.assertEqual(latest["subscription_active_until"], "2026-09-15T00:00:00Z")

    def test_dashboard_merges_latest_nonempty_metadata_across_windows(self) -> None:
        key = subscription_key("fixture-cross-window-metadata")
        with self.repo.connect() as conn:
            conn.executemany(
                """INSERT INTO subscription_quota_snapshots (
                       fetched_at, identity_key, plan_type,
                       subscription_active_until, window_kind, used_percent,
                       remaining_percent, source
                     ) VALUES (?, ?, ?, ?, ?, 25, 75,
                               'cliproxy_wham_usage')""",
                (
                    (
                        "2026-08-15T00:10:00Z",
                        key,
                        None,
                        "2026-09-15T00:00:00Z",
                        "five_hour",
                    ),
                    (
                        "2026-08-15T00:05:00Z",
                        key,
                        "team",
                        None,
                        "weekly",
                    ),
                ),
            )
        card = self.repo.subscription_dashboard_rows()[0]
        self.assertEqual(card["plan_type"], "team")
        self.assertEqual(
            card["subscription_active_until"],
            "2026-09-15T00:00:00Z",
        )

    def test_auto_reset_checks_each_latest_long_window_by_fetched_time(self) -> None:
        key = subscription_key("fixture-latest-long-window")
        common = {
            "identity_key": key,
            "remaining_percent": 0,
            "reset_at": "2026-08-16T00:00:00Z",
            "source": "cliproxy_wham_usage",
        }
        self.repo.insert_subscription_quota_snapshot(
            {
                **common,
                "fetched_at": "2026-08-15T00:10:00Z",
                "window_kind": "weekly",
                "used_percent": 20,
            }
        )
        self.repo.insert_subscription_quota_snapshot(
            {
                **common,
                "fetched_at": "2026-08-15T00:10:00Z",
                "window_kind": "monthly",
                "used_percent": 100,
            }
        )
        # Insert an older monthly sample last.  Row id order must not let it
        # hide the newer full window above.
        self.repo.insert_subscription_quota_snapshot(
            {
                **common,
                "fetched_at": "2026-08-15T00:05:00Z",
                "window_kind": "monthly",
                "used_percent": 0,
            }
        )
        with self.repo.connect() as conn:
            conn.execute(
                """INSERT INTO quota_events
                   (ts, identity_key, event_type, source)
                   VALUES ('2026-08-15T00:00:00Z', ?, 'usage_limit_hit',
                           'fixture')""",
                (key,),
            )
        info = meter.RequestInfo(
            "/v1/responses", "POST", "fixture-model", 0,
            None, None, None, None, None, None, None, None, None, None, key,
        )
        self.assertFalse(
            self.repo.maybe_auto_reset(info, "2026-08-15T00:30:00Z")
        )
        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute(
                    """SELECT COUNT(*) FROM quota_events
                         WHERE event_type='reset_detected'"""
                ).fetchone()[0],
                0,
            )

    def test_nonboolean_pagination_continuations_are_fail_closed(self) -> None:
        active_key = subscription_key("fixture-pagination-active")
        self.repo.reconcile_subscription_inventory(
            {active_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        poller = self.poller(self.resolver())
        for index, value in enumerate((1, "true", "unexpected-nonempty")):
            field = "has_more" if index != 1 else "hasMore"
            with self.subTest(value=value), mock.patch.object(
                poller,
                "_management_request",
                return_value=(200, {"files": [], field: value}),
            ):
                self.assertEqual(poller.poll_once("fixture-management"), (0, 0))
                self.assertFalse(poller._inventory_result["authoritative"])
                row = self.registry_rows()[0]
                self.assertEqual(row["identity_key"], active_key)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["consecutive_misses"], 0)

    def test_malformed_inventory_is_fail_closed_and_disabled_remains_present(self) -> None:
        filename = "disabled-member@example.cpa.2026-08-15_04-00-00.json"
        account_id = "acct-disabled-present"
        principal_id = "principal-disabled-present"
        email = "disabled-member@example.test"
        self.write_auth(
            filename,
            account_id=account_id,
            principal_id=principal_id,
            email=email,
            access_token="fixture-disabled-token",
        )
        resolver = self.resolver()
        identity_key = meter.resolved_identity_key(resolver.resolve_auth_file(filename))
        self.repo.reconcile_subscription_inventory(
            {identity_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        self.repo.insert_subscription_quota_snapshot(
            {
                "fetched_at": "2026-08-15T00:00:00Z",
                "identity_key": identity_key,
                "window_kind": "weekly",
                "used_percent": 10,
                "remaining_percent": 90,
                "source": "fixture",
            }
        )

        malformed_payloads = (
            {},
            {"files": {"not": "a-list"}},
            {"files": [{"provider": "codex", "name": filename}]},
            {"files": [], "next_cursor": "fixture-next-page"},
            {"files": [], "has_more": True},
        )
        for index, payload in enumerate(malformed_payloads, 1):
            with self.subTest(payload=payload):
                poller = self.poller(resolver)
                with mock.patch.object(
                    poller, "_management_request", return_value=(200, payload)
                ), mock.patch.object(
                    meter,
                    "utc_now",
                    return_value=f"2026-08-15T0{index}:00:00Z",
                ):
                    try:
                        poller.poll_once("fixture-management")
                    except (RuntimeError, ValueError):
                        pass
                row = self.registry_rows()[0]
                self.assertEqual(row["identity_key"], identity_key)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["consecutive_misses"], 0)
                self.assertEqual(len(self.repo.latest_subscription_quotas()), 1)

        disabled = self.auth_item(
            filename,
            "opaque-disabled",
            account_id,
            email,
            disabled=True,
        )
        poller = self.poller(resolver)
        with mock.patch.object(
            poller,
            "_management_request",
            return_value=(200, {"files": [disabled]}),
        ) as management, mock.patch.object(
            meter, "utc_now", return_value="2026-08-15T05:00:00Z"
        ):
            self.assertEqual(poller.poll_once("fixture-management"), (0, 0))
        self.assertEqual(management.call_count, 1)
        row = self.registry_rows()[0]
        self.assertEqual(row["identity_key"], identity_key)
        self.assertEqual(row["state"], "active")
        self.assertEqual(row["consecutive_misses"], 0)

    def test_strict_write_boundaries_never_persist_identifiable_identity_text(self) -> None:
        canonical = subscription_key("fixture-strict-boundary")
        identifiable = "subscription:member-boundary@example.test"
        self.assertIsNone(meter.canonical_subscription_key(f" {canonical}"))
        self.assertIsNone(meter.canonical_subscription_key(f"{canonical}\x00"))
        self.assertIsNone(meter.canonical_subscription_key(identifiable))
        info = meter.RequestInfo(
            "/v1/responses", "POST", "fixture-model", 0,
            None, None, None, None, None, None, None, None, None, None,
            identifiable,
        )

        self.repo.record_event(self._usage_event(identifiable), info, source="usage_queue")
        self.repo.record_quota_hit(
            info,
            "2026-08-15T00:00:00Z",
            "usage_limit_hit",
            "fixture",
            None,
        )
        with self.assertRaisesRegex(ValueError, "invalid subscription identity"):
            self.repo.insert_subscription_quota_snapshot(
                {
                    "fetched_at": "2026-08-15T00:00:00Z",
                    "identity_key": identifiable,
                    "window_kind": "weekly",
                    "used_percent": 10,
                    "source": "fixture",
                }
            )
        self.repo.insert_subscription_quota_snapshot(
            {
                "fetched_at": "2026-08-15T00:01:00Z",
                "identity_key": canonical,
                "window_kind": "weekly",
                "used_percent": 10,
                "plan_type": "plan-owner@example.test",
                "source": "fixture",
            }
        )

        with self.repo.connect() as conn:
            self.assertEqual(
                conn.execute("SELECT identity_key FROM usage_events").fetchone()[0],
                "unknown",
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM quota_events").fetchone()[0], 0)
            self.assertIsNone(
                conn.execute(
                    "SELECT plan_type FROM subscription_quota_snapshots"
                ).fetchone()[0]
            )
        dump = "\n".join(self._sqlite_dump())
        self.assertNotIn(identifiable, dump)
        self.assertNotIn("plan-owner@example.test", dump)

    def test_unsafe_anonymous_models_merge_without_losing_statistics(self) -> None:
        bucket = "2026-08-15T04:00:00.000Z"
        with self.repo.connect() as conn:
            conn.executemany(
                """INSERT INTO anonymous_usage_daily (
                     bucket_start, model, status_code, ok, usage_missing,
                     long_context_pricing_applied, split_priced, total_priced,
                     calls, streaming_calls, non_cached_input_tokens,
                     codex_status_tokens, duration_ms, input_tokens,
                     cached_tokens, cache_write_tokens, output_tokens,
                     reasoning_tokens, total_tokens, estimated_api_cost_usd,
                     non_cached_input_cost_usd, cached_input_cost_usd,
                     output_cost_usd
                   ) VALUES (?, ?, 200, 1, 0, 0, 1, 1, ?, ?, ?, ?, ?, ?, ?, 0,
                             ?, 0, ?, ?, ?, ?, ?)""",
                (
                    (
                        bucket,
                        "(unknown)",
                        2,
                        1,
                        8,
                        11,
                        20,
                        None,
                        None,
                        3,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                    (
                        bucket,
                        "bucket-owner@example.test",
                        3,
                        2,
                        12,
                        17,
                        30,
                        10,
                        2,
                        5,
                        15,
                        1.5,
                        0.8,
                        0.2,
                        0.5,
                    ),
                ),
            )
        before = self.repo.summary("all")

        self.repo.apply_privacy_minimization(self.resolver())

        after = self.repo.summary("all")
        for field in (
            "calls",
            "streaming_calls",
            "input_tokens",
            "cached_tokens",
            "output_tokens",
            "total_tokens",
            "non_cached_input_tokens",
            "codex_status_tokens",
            "estimated_api_cost_usd",
            "non_cached_input_cost_usd",
            "cached_input_cost_usd",
            "output_cost_usd",
        ):
            self.assertEqual(after[field], before[field], field)
        with self.repo.connect() as conn:
            rows = conn.execute("SELECT * FROM anonymous_usage_daily").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["model"], "(unknown)")
            self.assertEqual(rows[0]["calls"], 5)
            self.assertEqual(rows[0]["input_tokens"], 10)
        self.assertNotIn("bucket-owner@example.test", "\n".join(self._sqlite_dump()))

    def test_retired_import_key_prevents_recount_after_jsonl_rescan(self) -> None:
        active_key = subscription_key("fixture-import-active")
        retired_key = subscription_key("fixture-import-retired")
        import_key = "fixture-retired-import-dedup"
        self.repo.reconcile_subscription_inventory(
            {active_key, retired_key}, "2026-08-15T00:00:00Z", authoritative=True
        )
        event = self._usage_event(retired_key)
        self.assertTrue(self.repo.record_imported_event(event, import_key, "fixture"))
        with self.repo.connect() as conn:
            conn.execute(
                "UPDATE usage_events SET model='retired-owner@example.test' "
                "WHERE identity_key=?",
                (retired_key,),
            )
        for observed in (
            "2026-08-15T00:01:00Z",
            "2026-08-15T00:05:00Z",
            "2026-08-15T00:12:00Z",
        ):
            result = self.repo.reconcile_subscription_inventory(
                {active_key}, observed, authoritative=True
            )
        self.assertEqual(result["retired"], 1)
        after_retirement = self.repo.summary("all")

        self.assertFalse(self.repo.record_imported_event(event, import_key, "fixture"))

        self.assertEqual(self.repo.summary("all"), after_retirement)
        with self.repo.connect() as conn:
            import_row = conn.execute(
                "SELECT usage_event_id FROM local_import_records WHERE import_key=?",
                (import_key,),
            ).fetchone()
            self.assertIsNotNone(import_row)
            self.assertIsNone(import_row[0])
            anonymous_models = {
                row[0] for row in conn.execute("SELECT model FROM anonymous_usage_daily")
            }
            self.assertEqual(anonymous_models, {"(unknown)"})
        self.assertNotIn("retired-owner@example.test", "\n".join(self._sqlite_dump()))

    def test_invalid_historical_subscription_keys_are_fully_anonymized(self) -> None:
        legacy_key = "subscription:0123456789abcdef"
        self._seed_identified_history(legacy_key)
        with self.repo.connect() as conn:
            conn.execute(
                """INSERT INTO active_subscription_registry (
                     identity_key, state, first_seen_at, last_seen_at,
                     last_scan_generation
                   ) VALUES (?, 'active', '2026-08-15T00:00:00Z',
                             '2026-08-15T00:00:00Z', 1)""",
                (legacy_key,),
            )
            conn.execute(
                """INSERT INTO retired_subscription_tombstones (
                     identity_key, retired_at, last_scan_generation
                   ) VALUES (?, '2026-08-15T00:00:00Z', 1)""",
                (legacy_key,),
            )

        self.repo.apply_privacy_minimization(self.resolver())

        with self.repo.connect() as conn:
            for table in (
                "usage_events",
                "quota_events",
                "account_quota_cycles",
                "subscription_quota_snapshots",
                "active_subscription_registry",
                "retired_subscription_tombstones",
            ):
                self.assertEqual(
                    conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE identity_key=?",
                        (legacy_key,),
                    ).fetchone()[0],
                    0,
                    table,
                )
            import_row = conn.execute(
                "SELECT usage_event_id FROM local_import_records"
            ).fetchone()
            self.assertIsNotNone(import_row)
            self.assertIsNone(import_row[0])
        self.assertNotIn(legacy_key, "\n".join(self._sqlite_dump()))

    def test_proven_legacy_16_hex_identity_migrates_before_strict_cleanup(self) -> None:
        filename = "fixture-legacy-control.json"
        self.write_auth(
            filename,
            account_id="acct-legacy-control-fixture",
            principal_id="principal-legacy-control-fixture",
            email="legacy-control@example.test",
            access_token="fixture-legacy-control-token",
        )
        resolver = self.resolver()
        identity = resolver.resolve_auth_file(filename)
        self.assertIsNotNone(identity.legacy_subscription_id_hash)
        old_key = f"subscription:{identity.legacy_subscription_id_hash}"
        canonical_key = meter.resolved_identity_key(identity)
        self.assertEqual(resolver.identity_migrations()[old_key], canonical_key)
        self._seed_identified_history(old_key)
        before = self.repo.summary("all")

        self.repo.apply_privacy_minimization(resolver)

        after = self.repo.summary("all")
        for field in (
            "calls",
            "input_tokens",
            "cached_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
            "estimated_api_cost_usd",
        ):
            self.assertEqual(after[field], before[field], field)
        with self.repo.connect() as conn:
            for table in (
                "usage_events",
                "quota_events",
                "account_quota_cycles",
                "subscription_quota_snapshots",
            ):
                self.assertEqual(
                    conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE identity_key=?",
                        (old_key,),
                    ).fetchone()[0],
                    0,
                    table,
                )
                self.assertGreater(
                    conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE identity_key=?",
                        (canonical_key,),
                    ).fetchone()[0],
                    0,
                    table,
                )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM anonymous_usage_daily").fetchone()[0],
                0,
            )

    def test_historical_local_import_state_is_minimized_on_upgrade(self) -> None:
        unsafe_path = self.root / "private-account" / "rollout-sensitive.jsonl"
        safe_path = self.root / "safe-control" / "rollout.jsonl"
        with self.repo.connect() as conn:
            conn.executemany(
                """INSERT INTO local_import_files (
                     path, size, mtime_ns, offset, session_id, model_provider,
                     model, turn_id, updated_at
                   ) VALUES (?, 10, 20, 10, ?, ?, ?, ?,
                             '2026-08-15T00:00:00Z')""",
                (
                    (
                        str(unsafe_path),
                        "private-session-marker",
                        "provider-owner@example.test",
                        "model-owner@example.test",
                        "private-turn-marker",
                    ),
                    (
                        str(safe_path),
                        "safe-session-marker",
                        "openai",
                        "gpt-5-fixture",
                        "safe-turn-marker",
                    ),
                ),
            )

        self.repo.apply_privacy_minimization(self.resolver())

        with self.repo.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM local_import_files ORDER BY model IS NULL DESC"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertRegex(row["path"], r"^file:[0-9a-f]{16}$")
                self.assertIsNone(row["session_id"])
                self.assertIsNone(row["turn_id"])
            unsafe = next(row for row in rows if row["model"] is None)
            safe = next(row for row in rows if row["model"] == "gpt-5-fixture")
            self.assertIsNone(unsafe["model_provider"])
            self.assertEqual(safe["model_provider"], "openai")
        database_bytes = self.repo.path.read_bytes()
        wal_path = Path(str(self.repo.path) + "-wal")
        wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""
        for marker in (
            str(unsafe_path),
            "private-session-marker",
            "provider-owner@example.test",
            "model-owner@example.test",
            "private-turn-marker",
            "safe-session-marker",
            "safe-turn-marker",
        ):
            encoded = marker.encode()
            self.assertNotIn(encoded, database_bytes)
            self.assertNotIn(encoded, wal_bytes)

    def test_privacy_checkpoint_busy_state_is_retried(self) -> None:
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.execute.return_value.fetchone.return_value = (1, 4, 2)
        with mock.patch.object(self.repo, "connect", return_value=connection):
            self.assertFalse(self.repo._checkpoint_privacy_wal("fixture privacy"))
        self.assertTrue(self.repo._privacy_checkpoint_pending)

        connection.execute.return_value.fetchone.return_value = (0, 0, 0)
        with mock.patch.object(self.repo, "connect", return_value=connection):
            result = self.repo.reconcile_subscription_inventory(
                set(), authoritative=False
            )
        self.assertFalse(result["authoritative"])
        self.assertFalse(self.repo._privacy_checkpoint_pending)

    def _seed_identified_history(self, identity_key: str) -> int:
        with self.repo.connect() as conn:
            cursor = conn.execute(
                """INSERT INTO usage_events (
                       ts, identity_key, endpoint, method, model, status_code, ok,
                       duration_ms, stream, session_id, thread_id, turn_id,
                       installation_id, window_id, usage_alias, usage_project,
                       auth_fingerprint, account_id_hash, account_id_tail,
                       input_tokens, cached_tokens, cache_write_tokens, output_tokens,
                       reasoning_tokens, total_tokens, estimated_api_cost_usd,
                       non_cached_input_cost_usd, cached_input_cost_usd, output_cost_usd,
                       long_context_pricing_applied, usage_missing, error_type,
                       error_message_redacted, request_bytes, response_bytes,
                       call_count, source, request_id)
                   VALUES (
                       '2026-08-14T12:34:56.000000Z', ?, '/v1/private', 'POST',
                       'fixture-model', 429, 0, 321, 1, 'fixture-session',
                       'fixture-thread', 'fixture-turn', 'fixture-installation',
                       'fixture-window', 'codex-retired', 'fixture-project',
                       'fixture-auth-fingerprint', 'fixture-account-hash',
                       'TAIL1234', 100, 20, 5, 30, 7, 130, 1.25,
                       0.75, 0.10, 0.40, 1, 0, 'fixture-error-type',
                       'fixture-error-message', 111, 222, 2, 'usage_queue',
                       'fixture-request')""",
                (identity_key,),
            )
            event_id = int(cursor.lastrowid)
            conn.execute(
                """INSERT INTO quota_events
                   (ts, identity_key, account_id_hash, account_id_tail,
                    usage_alias, event_type, source, raw_message_redacted)
                   VALUES ('2026-08-14T12:35:00Z', ?, 'fixture-account-hash',
                           'TAIL1234', 'codex-retired', 'quota_hit', 'fixture',
                           'fixture-quota-message')""",
                (identity_key,),
            )
            conn.execute(
                """INSERT INTO account_quota_cycles
                   (identity_key, account_id_hash, account_id_tail, usage_alias,
                    cycle_start_ts, cycle_end_ts, total_calls, total_input_tokens,
                    total_output_tokens, total_tokens, estimated_api_cost_usd,
                    observed_floor_usd, is_complete_cycle)
                   VALUES (?, 'fixture-account-hash', 'TAIL1234', 'codex-retired',
                           '2026-08-14T00:00:00Z', '2026-08-14T12:35:00Z',
                           2, 100, 30, 130, 1.25, 1.25, 1)""",
                (identity_key,),
            )
            conn.execute(
                """INSERT INTO local_import_records
                   (import_key, source, usage_event_id, imported_at)
                   VALUES ('fixture-import-key', 'fixture', ?, '2026-08-14T12:36:00Z')""",
                (event_id,),
            )
        if meter.canonical_subscription_key(identity_key):
            self.repo.insert_subscription_quota_snapshot(
                {
                    "fetched_at": "2026-08-14T12:35:00Z",
                    "identity_key": identity_key,
                    "account_id_hash": "fixture-account-hash",
                    "account_id_tail": "TAIL1234",
                    "usage_alias": "codex-retired",
                    "plan_type": "team",
                    "window_kind": "weekly",
                    "used_percent": 75,
                    "remaining_percent": 25,
                    "source": "fixture",
                }
            )
        else:
            # Legacy/unproven identities can only exist in an upgraded DB;
            # current repository writes reject them at the boundary.
            with self.repo.connect() as conn:
                conn.execute(
                    """INSERT INTO subscription_quota_snapshots (
                           fetched_at, identity_key, account_id_hash,
                           account_id_tail, usage_alias, plan_type, window_kind,
                           used_percent, remaining_percent, source
                         ) VALUES ('2026-08-14T12:35:00Z', ?,
                                   'fixture-account-hash', 'TAIL1234',
                                   'codex-retired', 'team', 'weekly', 75, 25,
                                   'fixture')""",
                    (identity_key,),
                )
        return event_id

    @staticmethod
    def _usage_event(identity_key: str) -> meter.UsageEvent:
        return meter.UsageEvent(
            ts="2026-08-15T00:01:15Z",
            identity_key=identity_key,
            endpoint="/v1/private",
            method="POST",
            model="fixture-model",
            status_code=200,
            ok=1,
            duration_ms=12,
            stream=0,
            session_id="private-session",
            thread_id="private-thread",
            turn_id="private-turn",
            installation_id="private-installation",
            window_id="private-window",
            usage_alias="codex-private",
            usage_project="private-project",
            auth_fingerprint="private-fingerprint",
            account_id_hash="private-account-hash",
            account_id_tail="TAIL1234",
            input_tokens=40,
            output_tokens=10,
            cached_tokens=5,
            cache_write_tokens=0,
            reasoning_tokens=2,
            total_tokens=50,
            estimated_api_cost_usd=None,
            non_cached_input_cost_usd=None,
            cached_input_cost_usd=None,
            output_cost_usd=None,
            long_context_pricing_applied=0,
            subscription_amortized_cost_usd=None,
            api_equivalent_quota_usd=None,
            usage_missing=0,
            error_type=None,
            error_message_redacted="private-error",
            request_bytes=123,
            response_bytes=456,
            call_count=1,
            source="fixture",
            request_id="private-request",
        )

    def _sqlite_dump(self) -> list[str]:
        with self.repo.connect() as conn:
            return list(conn.iterdump())


if __name__ == "__main__":
    unittest.main()
