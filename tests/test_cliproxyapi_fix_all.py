from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "cliproxyapi_fix_all.sh"


def make_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def write_subscription(path: Path, *, disabled: bool = False, missing_access: bool = False) -> None:
    path.write_text(
        json.dumps(
            {
                "type": "codex",
                "email": "user@example.com",
                "account_id": "account-test",
                "id_token": "id-test",
                "access_token": "" if missing_access else "access-test",
                "refresh_token": "refresh-test",
                "disabled": disabled,
            }
        ),
        encoding="utf-8",
    )


def prepare_environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path, Path, Path]:
    fake_bin = tmp_path / "bin"
    auth_dir = tmp_path / "auth"
    backup_dir = tmp_path / "auth-backups"
    home_dir = tmp_path / "home"
    fake_bin.mkdir()
    auth_dir.mkdir()
    home_dir.mkdir()

    python_log = tmp_path / "python.log"
    brew_log = tmp_path / "brew.log"
    auth_log = tmp_path / "auth.log"

    make_executable(
        fake_bin / "python3",
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$PYTHON_CALL_LOG\"\n"
        f"exec {shlex.quote(sys.executable)} \"$@\"\n",
    )
    make_executable(
        fake_bin / "brew",
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$BREW_CALL_LOG\"\n",
    )
    auth_helper = tmp_path / "fix-auth"
    make_executable(
        auth_helper,
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$AUTH_CALL_LOG\"\n",
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "HOME": str(home_dir),
            "CLIPROXYAPI_PYTHON_BIN": "python3",
            "CLIPROXYAPI_BREW_BIN": "brew",
            "CLIPROXYAPI_DIR": str(auth_dir),
            "CLIPROXYAPI_BACKUP_DIR": str(backup_dir),
            "CLIPROXYAPI_AUTH_FIX_SCRIPT": str(auth_helper),
            "PYTHON_CALL_LOG": str(python_log),
            "BREW_CALL_LOG": str(brew_log),
            "AUTH_CALL_LOG": str(auth_log),
        }
    )
    return env, auth_dir, backup_dir, python_log, brew_log


def run_fix_all(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", str(SCRIPT), *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_resolves_python_and_brew_from_path_and_runs_full_repair(tmp_path: Path) -> None:
    env, auth_dir, _backup_dir, python_log, brew_log = prepare_environment(tmp_path)
    write_subscription(auth_dir / "codex-user@example.com-plus.json")

    completed = run_fix_all(env)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "CLIProxyAPI repair completed successfully." in completed.stdout
    assert "cliproxyapi_dedupe_codex_subscriptions.py" in python_log.read_text(encoding="utf-8")
    assert brew_log.read_text(encoding="utf-8").strip() == "services restart cliproxyapi"
    assert (tmp_path / "auth.log").read_text(encoding="utf-8").strip() == "--reconcile --status"


def test_lone_failed_subscription_stops_before_auth_and_restart(tmp_path: Path) -> None:
    env, auth_dir, _backup_dir, _python_log, brew_log = prepare_environment(tmp_path)
    failed = auth_dir / "codex-user@example.com-plus.json"
    write_subscription(failed, missing_access=True)

    completed = run_fix_all(env)

    assert completed.returncode == 10
    assert "SAFETY STOP" in completed.stderr
    assert "restart were skipped" in completed.stderr
    assert failed.exists()
    assert not brew_log.exists()
    assert not (tmp_path / "auth.log").exists()


def test_disabled_subscription_is_quarantined_then_service_restarts(tmp_path: Path) -> None:
    env, auth_dir, backup_dir, _python_log, brew_log = prepare_environment(tmp_path)
    disabled = auth_dir / "codex-user@example.com-plus.json"
    write_subscription(disabled, disabled=True)

    completed = run_fix_all(env)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not disabled.exists()
    quarantined = list(backup_dir.glob("disabled_subscription_quarantine_*/*.json"))
    assert len(quarantined) == 1
    assert brew_log.read_text(encoding="utf-8").strip() == "services restart cliproxyapi"


def test_dry_run_previews_auth_changes_without_restarting(tmp_path: Path) -> None:
    env, auth_dir, _backup_dir, _python_log, brew_log = prepare_environment(tmp_path)
    subscription = auth_dir / "codex-user@example.com-plus.json"
    write_subscription(subscription)

    completed = run_fix_all(env, "--dry-run")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "DRY-RUN: would run: brew services restart cliproxyapi" in completed.stdout
    assert "Preview complete" in completed.stdout
    assert subscription.exists()
    assert not brew_log.exists()
    assert (tmp_path / "auth.log").read_text(encoding="utf-8").strip() == "--dry-run --reconcile"
