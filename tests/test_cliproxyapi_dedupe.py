from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.cliproxyapi_dedupe_codex_subscriptions import (
    SINGLE_FAILURE_RC,
    configured_backup_dir,
    dedupe,
    unpaired_failed_subscriptions,
)


def write_subscription(path: Path, email: str, marker: str) -> None:
    path.write_text(
        json.dumps(
            {
                "type": "codex",
                "email": email,
                "account_id": f"account-{marker}",
                "id_token": f"id-{marker}",
                "access_token": f"access-{marker}",
                "refresh_token": f"refresh-{marker}",
            }
        ),
        encoding="utf-8",
    )


def recursive_json(root: Path) -> list[Path]:
    return sorted(root.rglob("*.json"))


def test_legacy_archives_are_moved_outside_auth_dir(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    write_subscription(auth_dir / "codex-live@example.com-plus.json", "live@example.com", "live")
    legacy = auth_dir / "duplicate_subscription_backup_20260808"
    legacy.mkdir()
    write_subscription(legacy / "codex-old@example.com-plus.json", "old@example.com", "old")

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    assert not legacy.exists()
    assert (backup_dir / legacy.name / "codex-old@example.com-plus.json").exists()
    assert recursive_json(auth_dir) == [auth_dir / "codex-live@example.com-plus.json"]


def test_new_duplicate_archive_is_external(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    write_subscription(auth_dir / "codex-abc-user@example.com-plus.json", "user@example.com", "old")
    write_subscription(auth_dir / "codex-user@example.com-plus.json", "user@example.com", "new")

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    top_level = sorted(path.name for path in auth_dir.glob("*.json"))
    assert top_level == ["codex-user@example.com-plus.json"]
    archived = list(backup_dir.glob("duplicate_subscription_backup_*/*.json"))
    assert len(archived) == 1
    assert recursive_json(auth_dir) == [auth_dir / "codex-user@example.com-plus.json"]


def test_hashed_winner_is_copied_to_canonical_then_archived(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    canonical = auth_dir / "codex-user@example.com-plus.json"
    hashed = auth_dir / "codex-abc-user@example.com-plus.json"
    write_subscription(canonical, "user@example.com", "old")
    write_subscription(hashed, "user@example.com", "new")
    os.utime(canonical, (1, 1))
    os.utime(hashed, (2, 2))

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    assert canonical.exists()
    assert not hashed.exists()
    assert json.loads(canonical.read_text(encoding="utf-8"))["account_id"] == "account-new"
    archived = list(backup_dir.glob("duplicate_subscription_backup_*/codex-abc-user@example.com-plus.json"))
    assert len(archived) == 1
    assert recursive_json(auth_dir) == [canonical]


def test_single_failed_subscription_is_preserved(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    failed = auth_dir / "codex-failed@example.com-plus.json"
    failed.write_text(
        json.dumps(
            {
                "type": "codex",
                "email": "failed@example.com",
                "account_id": "account-failed",
                "id_token": "id-failed",
                "access_token": "",
                "refresh_token": "refresh-failed",
            }
        ),
        encoding="utf-8",
    )

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    assert failed.exists()
    assert not backup_dir.exists()
    assert recursive_json(auth_dir) == [failed]
    assert unpaired_failed_subscriptions(auth_dir) == [(failed, "missing access_token")]
    assert SINGLE_FAILURE_RC == 10


def test_single_disabled_subscription_is_quarantined_outside_auth_dir(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    disabled = auth_dir / "codex-disabled@example.com-plus.json"
    write_subscription(disabled, "disabled@example.com", "disabled")
    data = json.loads(disabled.read_text(encoding="utf-8"))
    data["disabled"] = True
    disabled.write_text(json.dumps(data), encoding="utf-8")

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    assert not disabled.exists()
    quarantined = list(
        backup_dir.glob("disabled_subscription_quarantine_*/codex-disabled@example.com-plus.json")
    )
    assert len(quarantined) == 1
    assert recursive_json(auth_dir) == []
    assert quarantined[0].stat().st_mode & 0o777 == 0o600


def test_disabled_subscription_dry_run_does_not_move_file(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    disabled = auth_dir / "codex-disabled@example.com-plus.json"
    write_subscription(disabled, "disabled@example.com", "disabled")
    data = json.loads(disabled.read_text(encoding="utf-8"))
    data["disabled"] = True
    disabled.write_text(json.dumps(data), encoding="utf-8")

    assert dedupe(auth_dir, True, False, False, backup_dir, True) == 0

    assert disabled.exists()
    assert not backup_dir.exists()


def test_failed_duplicate_is_removed_only_when_a_peer_exists(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    auth_dir.mkdir()
    valid = auth_dir / "codex-user@example.com-plus.json"
    failed = auth_dir / "codex-deadbeef-user@example.com-plus.json"
    write_subscription(valid, "user@example.com", "valid")
    failed.write_text(
        json.dumps(
            {
                "type": "codex",
                "email": "user@example.com",
                "account_id": "account-failed",
                "id_token": "id-failed",
                "access_token": "",
                "refresh_token": "refresh-failed",
            }
        ),
        encoding="utf-8",
    )

    assert dedupe(auth_dir, False, False, False, backup_dir, True) == 0

    assert valid.exists()
    assert not failed.exists()
    assert recursive_json(auth_dir) == [valid]


def test_backup_dir_inside_auth_dir_is_rejected(tmp_path: Path) -> None:
    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    with pytest.raises(ValueError, match="outside auth directory"):
        configured_backup_dir(auth_dir, auth_dir / "backups")
