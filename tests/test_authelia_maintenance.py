from __future__ import annotations

import json
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_homelab.authelia_maintenance import MaintenanceError, Target, main, restore, run

HEALTH = "https://auth.example.invalid/api/health"
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def make_target(tmp_path: Path, **overrides: object) -> Target:
    stack = tmp_path / "edge"
    (stack / "authelia/data").mkdir(parents=True)
    compose = stack / "compose.yml"
    compose.write_text("services: {}\n")
    config = stack / "authelia/configuration.yml"
    config.write_text("old: true\n")
    config.chmod(0o640)
    candidate = tmp_path / "candidate.yml"
    candidate.write_text("new: true\n")
    database = stack / "authelia/data/db.sqlite3"
    database.write_bytes(b"sqlite-original")
    database.with_name("db.sqlite3-wal").write_bytes(b"wal-original")
    key = stack / "authelia/jwks.pem"
    key.write_text("synthetic-key-material\n")
    key.chmod(0o600)
    values: dict[str, object] = {
        "compose_file": compose,
        "service": "authelia",
        "config": config,
        "candidate": candidate,
        "container_config": "/config/configuration.yml",
        "database": database,
        "key_inputs": (key,),
        "backup_root": tmp_path / "backups",
        "verify": ((HEALTH, 200),),
        "verify_timeout": 0.0,
        "quiet_seconds": 0.0,
    }
    values.update(overrides)
    return Target(**values)  # type: ignore[arg-type]


class FakeDocker:
    """Records compose calls and simulates service state."""

    def __init__(self, *, validate_rc: int = 0, still_running: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.running = True
        self.validate_rc = validate_rc
        self.still_running = still_running

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        verb = command[6]
        if verb == "run":
            return subprocess.CompletedProcess(command, self.validate_rc, "", "secret-looking stderr")
        if verb == "stop":
            self.running = self.still_running
        elif verb == "up":
            self.running = True
        elif verb == "ps":
            return subprocess.CompletedProcess(command, 0, "authelia\n" if self.running else "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def verbs(self) -> list[str]:
        return [call[6] for call in self.calls]


def fetch_ok(url: str, timeout: float) -> int:
    return 200


def no_sleep(seconds: float) -> None:
    return None


def test_default_is_a_non_mutating_plan(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    docker = FakeDocker()
    report = run(target, runner=docker)
    assert report.status == "planned"
    assert docker.calls == []
    assert not target.backup_root.exists()
    assert target.config.read_text() == "old: true\n"


def test_successful_transaction_backs_up_then_applies(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    docker = FakeDocker()
    report = run(target, apply=True, runner=docker, fetch=fetch_ok, sleep=no_sleep, now=NOW)

    assert report.status == "complete", report.error
    assert docker.verbs() == ["run", "stop", "ps", "up"]
    validate = docker.calls[0]
    assert f"{target.candidate}:/config/configuration.yml:ro" in validate
    assert validate[-3:] == ["validate-config", "--config", "/config/configuration.yml"]

    assert target.config.read_text() == "new: true\n"
    assert stat.S_IMODE(target.config.stat().st_mode) == 0o640

    backup = Path(report.backup or "")
    assert backup.name == "authelia-20260102T030405Z"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o700
    manifest = json.loads((backup / "manifest.json").read_text())
    present = {Path(entry["path"]).name: entry for entry in manifest["files"]}
    assert present["configuration.yml"]["present"] and present["configuration.yml"]["mode"] == 0o640
    assert present["db.sqlite3"]["present"] and present["db.sqlite3-wal"]["present"]
    assert present["db.sqlite3-shm"]["present"] is False
    assert present["jwks.pem"]["present"]
    assert (backup / present["configuration.yml"]["copy"]).read_text() == "old: true\n"
    for entry in manifest["files"]:
        if entry["present"]:
            assert stat.S_IMODE((backup / entry["copy"]).stat().st_mode) == 0o600


def test_report_never_contains_file_contents(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    report = run(target, apply=True, runner=FakeDocker(), fetch=fetch_ok, sleep=no_sleep, now=NOW)
    text = json.dumps(report.as_dict())
    for secret in ("synthetic-key-material", "sqlite-original", "secret-looking stderr"):
        assert secret not in text


def test_invalid_candidate_stops_nothing(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    docker = FakeDocker(validate_rc=1)
    with pytest.raises(MaintenanceError, match="validate-config"):
        run(target, apply=True, runner=docker, fetch=fetch_ok, sleep=no_sleep, now=NOW)
    assert docker.verbs() == ["run"]
    assert target.config.read_text() == "old: true\n"
    assert not target.backup_root.exists()


def test_identical_candidate_is_refused(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    target.candidate.write_text("old: true\n")
    with pytest.raises(MaintenanceError, match="identical"):
        run(target, apply=True, runner=FakeDocker(), fetch=fetch_ok, sleep=no_sleep)


def test_symlinked_input_is_refused(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    link = tmp_path / "link.pem"
    link.symlink_to(target.key_inputs[0])
    with pytest.raises(MaintenanceError, match="regular file"):
        run(make_target(tmp_path / "b", key_inputs=(link,)), apply=True, runner=FakeDocker(), fetch=fetch_ok)


def test_failed_verification_rolls_back_every_file(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    shm = target.database.with_name("db.sqlite3-shm")
    seen: list[int] = []

    def fetch_first_fails(url: str, timeout: float) -> int:
        seen.append(1)
        if len(seen) == 1:
            # Simulate the new Authelia writing to its database before failing health.
            target.database.write_bytes(b"sqlite-migrated")
            shm.write_bytes(b"new-shm")
            return 502
        return 200

    docker = FakeDocker()
    report = run(target, apply=True, runner=docker, fetch=fetch_first_fails, sleep=no_sleep, now=NOW)

    assert report.status == "rolled-back"
    assert "verification failed" in (report.error or "")
    assert docker.verbs() == ["run", "stop", "ps", "up", "stop", "up"]
    assert target.config.read_text() == "old: true\n"
    assert stat.S_IMODE(target.config.stat().st_mode) == 0o640
    assert target.database.read_bytes() == b"sqlite-original"
    assert not shm.exists()
    assert report.steps[-3:] == ["rollback", "restored", "rollback-verified"]


def test_service_still_running_restarts_without_touching_files(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    docker = FakeDocker(still_running=True)
    report = run(target, apply=True, runner=docker, fetch=fetch_ok, sleep=no_sleep, now=NOW)
    assert report.status == "rolled-back"
    assert "still running" in (report.error or "")
    assert report.backup is None
    assert target.config.read_text() == "old: true\n"


def test_active_writer_after_stop_is_detected(tmp_path: Path) -> None:
    target = make_target(tmp_path)

    def writer_sleep(seconds: float) -> None:
        target.database.with_name("db.sqlite3-wal").write_bytes(b"wal-original-and-more")

    report = run(target, apply=True, runner=FakeDocker(), fetch=fetch_ok, sleep=writer_sleep, now=NOW)
    assert report.status == "rolled-back"
    assert "another writer" in (report.error or "")
    assert target.config.read_text() == "old: true\n"


def test_rollback_failure_is_reported_distinctly(tmp_path: Path) -> None:
    target = make_target(tmp_path)

    def always_down(url: str, timeout: float) -> int:
        return 0

    report = run(target, apply=True, runner=FakeDocker(), fetch=always_down, sleep=no_sleep, now=NOW)
    assert report.status == "rollback-failed"
    assert target.config.read_text() == "old: true\n"


def test_corrupt_backup_copy_is_not_restored(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    report = run(target, apply=True, runner=FakeDocker(), fetch=fetch_ok, sleep=no_sleep, now=NOW)
    backup = Path(report.backup or "")
    (backup / "00-configuration.yml").write_text("tampered\n")
    with pytest.raises(MaintenanceError, match="corrupt"):
        restore(backup)
    assert target.config.read_text() == "new: true\n"


def test_cli_dry_run_and_bad_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = make_target(tmp_path)
    base = [
        "--compose-file", str(target.compose_file),
        "--config", str(target.config),
        "--candidate", str(target.candidate),
        "--database", str(target.database),
        "--key-input", str(target.key_inputs[0]),
        "--backup-root", str(target.backup_root),
    ]  # fmt: skip
    assert main([*base, "--verify", f"{HEALTH}=200"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "planned"
    with pytest.raises(SystemExit):
        main([*base, "--verify", "not-a-url"])
