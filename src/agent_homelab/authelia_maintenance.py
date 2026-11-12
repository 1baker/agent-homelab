"""Standard stopped-writer maintenance transaction for an Authelia service.

One announced window: validate the candidate configuration, stop Authelia,
confirm its SQLite writer is quiet, cold-copy the configuration, database
(with -wal/-shm) and referenced durable key inputs into a dated 0700 backup,
install the candidate, start, and verify. Any failure after the stop restores
the protected copies (contents, mode, owner), starts and verifies again.

Dry-run is the default. File contents are never printed; only paths, sizes,
modes and SHA-256 digests are written, and the manifest lives inside the
0700 backup directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

Runner = Callable[..., subprocess.CompletedProcess[str]]
Fetcher = Callable[[str, float], int]
Sleeper = Callable[[float], None]


class MaintenanceError(RuntimeError):
    """A precondition or step failed; the message never contains file contents."""


@dataclass(frozen=True)
class Target:
    compose_file: Path
    service: str
    config: Path
    candidate: Path
    container_config: str
    database: Path
    key_inputs: tuple[Path, ...]
    backup_root: Path
    verify: tuple[tuple[str, int], ...]
    verify_timeout: float = 60.0
    quiet_seconds: float = 2.0

    def protected(self) -> list[Path]:
        """Every file the transaction backs up and may restore, in a fixed order."""
        db = self.database
        return [
            self.config,
            db,
            db.with_name(db.name + "-wal"),
            db.with_name(db.name + "-shm"),
            *self.key_inputs,
        ]


@dataclass
class Report:
    status: str = "planned"
    steps: list[str] = field(default_factory=list)
    backup: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "steps": self.steps, "backup": self.backup, "error": self.error}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compose(target: Target) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-directory",
        str(target.compose_file.parent),
        "-f",
        str(target.compose_file),
    ]


def _default_fetch(url: str, timeout: float) -> int:
    if not url.startswith(("http://", "https://")):
        return 0
    request = urllib.request.Request(url, method="GET")  # noqa: S310 - scheme checked above
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked above
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0


def plan(target: Target) -> Report:
    report = Report()
    report.steps = [
        f"preflight: config, candidate, database and {len(target.key_inputs)} key input(s) exist; candidate differs",
        f"validate candidate with `authelia validate-config` in a one-off `{target.service}` container",
        f"stop service `{target.service}` and confirm it is not running",
        f"confirm database files are quiet for {target.quiet_seconds:g}s",
        f"cold-copy {len(target.protected())} protected path(s) into a dated 0700 directory under {target.backup_root}",
        "verify every copy against its SHA-256 and write manifest.json (0600)",
        "install candidate atomically with the original mode and owner",
        f"start service `{target.service}` (same container; no recreate)",
        f"verify {len(target.verify)} URL(s) within {target.verify_timeout:g}s",
        "on any failure after stop: restore copies, start, verify (rollback); if a restore fails, stay stopped",
    ]
    return report


def preflight(target: Target) -> None:
    for path in (target.compose_file, target.config, target.candidate, target.database, *target.key_inputs):
        if not path.is_file() or path.is_symlink():
            raise MaintenanceError(f"not a regular file: {path}")
    if _sha256(target.config) == _sha256(target.candidate):
        raise MaintenanceError("candidate is identical to the current configuration")
    if not target.verify:
        raise MaintenanceError("at least one --verify URL=STATUS is required")
    if target.backup_root.exists() and not target.backup_root.is_dir():
        raise MaintenanceError(f"backup root is not a directory: {target.backup_root}")
    euid = os.geteuid()
    for path in target.protected():
        if not os.access(path.parent, os.W_OK | os.X_OK):
            raise MaintenanceError(f"cannot write the directory needed to restore: {path.parent}")
        if not path.exists():
            continue
        if not os.access(path, os.R_OK):
            raise MaintenanceError(f"cannot read protected file: {path}")
        if euid != 0 and path.stat().st_uid != euid:
            raise MaintenanceError(f"protected file is owned by another user and could not be restored: {path}")


def validate_candidate(target: Target, runner: Runner) -> None:
    command = [
        *_compose(target),
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "authelia",
        "-v",
        f"{target.candidate}:{target.container_config}:ro",
        target.service,
        "validate-config",
        "--config",
        target.container_config,
    ]
    result = runner(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise MaintenanceError(f"candidate failed validate-config (exit {result.returncode})")


def _running(target: Target, runner: Runner) -> bool:
    result = runner(
        [*_compose(target), "ps", "--status", "running", "--services"],
        check=True,
        capture_output=True,
        text=True,
    )
    return target.service in result.stdout.split()


def _fingerprint(paths: list[Path]) -> list[tuple[str, int, int] | None]:
    out: list[tuple[str, int, int] | None] = []
    for path in paths:
        try:
            st = path.stat()
        except FileNotFoundError:
            out.append(None)
            continue
        out.append((str(path), st.st_size, st.st_mtime_ns))
    return out


def stop_and_confirm(target: Target, runner: Runner, sleep: Sleeper) -> None:
    runner([*_compose(target), "stop", target.service], check=True, text=True)
    if _running(target, runner):
        raise MaintenanceError(f"service `{target.service}` is still running after stop")
    db_files = target.protected()[1:4]
    before = _fingerprint(db_files)
    sleep(target.quiet_seconds)
    if _fingerprint(db_files) != before:
        raise MaintenanceError("database files changed after stop; another writer may be active")


def backup(target: Target, now: datetime) -> Path:
    target.backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = target.backup_root / f"authelia-{now.strftime('%Y%m%dT%H%M%SZ')}"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    entries = []
    for index, source in enumerate(target.protected()):
        if not source.exists():
            entries.append({"index": index, "path": str(source), "present": False})
            continue
        st = source.stat()
        copy = directory / f"{index:02d}-{source.name}"
        shutil.copy2(source, copy)
        os.chmod(copy, 0o600)
        with copy.open("rb") as handle:
            os.fsync(handle.fileno())
        digest = _sha256(source)
        if _sha256(copy) != digest:
            raise MaintenanceError(f"backup copy does not match source: {source}")
        entries.append(
            {
                "index": index,
                "path": str(source),
                "present": True,
                "copy": copy.name,
                "sha256": digest,
                "size": st.st_size,
                "mode": st.st_mode & 0o7777,
                "uid": st.st_uid,
                "gid": st.st_gid,
            }
        )
    manifest = directory / "manifest.json"
    manifest.write_text(json.dumps({"created": now.isoformat(), "files": entries}, indent=2) + "\n")
    os.chmod(manifest, 0o600)
    return directory


def _install(source: Path, destination: Path, mode: int, uid: int, gid: int) -> None:
    temp = destination.with_name(f".{destination.name}.agent-homelab-tmp")
    temp.unlink(missing_ok=True)
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as out, source.open("rb") as src:
        shutil.copyfileobj(src, out)
    os.chmod(temp, mode)
    if (uid, gid) != (os.getuid(), os.getgid()):
        os.chown(temp, uid, gid)
    with temp.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(temp, destination)


def apply_candidate(target: Target) -> None:
    st = target.config.stat()
    _install(target.candidate, target.config, st.st_mode & 0o7777, st.st_uid, st.st_gid)


def restore(directory: Path) -> None:
    """Restore every manifest entry; attempt all of them, then fail if any could not be restored."""
    manifest = json.loads((directory / "manifest.json").read_text())
    failures: list[str] = []
    for entry in manifest["files"]:
        path = Path(entry["path"])
        try:
            if not entry["present"]:
                path.unlink(missing_ok=True)
                continue
            copy = directory / entry["copy"]
            if _sha256(copy) != entry["sha256"]:
                failures.append(f"backup copy is corrupt: {copy.name}")
                continue
            _install(copy, path, entry["mode"], entry["uid"], entry["gid"])
            if _sha256(path) != entry["sha256"]:
                failures.append(f"restored file does not match backup: {path}")
        except OSError as exc:
            failures.append(f"could not restore {path}: {exc.strerror or type(exc).__name__}")
    if failures:
        raise MaintenanceError("; ".join(failures))


def start_and_verify(target: Target, runner: Runner, fetch: Fetcher, sleep: Sleeper) -> None:
    runner([*_compose(target), "start", target.service], check=True, text=True)
    deadline = time.monotonic() + target.verify_timeout
    pending = list(target.verify)
    while pending:
        pending = [(url, want) for url, want in pending if fetch(url, 5.0) != want]
        if not pending:
            return
        if time.monotonic() >= deadline:
            failed = ", ".join(f"{url} (want {want})" for url, want in pending)
            raise MaintenanceError(f"verification failed: {failed}")
        sleep(1.0)


def run(
    target: Target,
    *,
    apply: bool = False,
    runner: Runner | None = None,
    fetch: Fetcher | None = None,
    sleep: Sleeper | None = None,
    now: datetime | None = None,
) -> Report:
    report = plan(target)
    if not apply:
        return report
    invoke = runner or subprocess.run
    get = fetch or _default_fetch
    pause = sleep or time.sleep
    report.steps = []
    preflight(target)
    report.steps.append("preflight")
    validate_candidate(target, invoke)
    report.steps.append("validated")
    stopped = False
    directory: Path | None = None
    try:
        stopped = True
        stop_and_confirm(target, invoke, pause)
        report.steps.append("stopped")
        directory = backup(target, now or datetime.now(UTC))
        report.backup = str(directory)
        report.steps.append("backed-up")
        apply_candidate(target)
        report.steps.append("applied")
        start_and_verify(target, invoke, get, pause)
        report.steps.append("verified")
        report.status = "complete"
        return report
    except (MaintenanceError, subprocess.CalledProcessError, OSError) as exc:
        report.error = _describe(exc)
        if not stopped:
            report.status = "failed"
            return report
        report.steps.append("rollback")
        try:
            invoke([*_compose(target), "stop", target.service], check=True, text=True)
            if directory is not None:
                restore(directory)
                report.steps.append("restored")
            start_and_verify(target, invoke, get, pause)
            report.steps.append("rollback-verified")
            report.status = "rolled-back"
        except (MaintenanceError, subprocess.CalledProcessError, OSError) as rollback_exc:
            report.status = "rollback-failed"
            report.error = f"{report.error}; rollback: {_describe(rollback_exc)}"
            if directory is not None and "restored" not in report.steps:
                report.error += "; service left stopped, restore by hand from the backup directory"
        return report


def _describe(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        command = exc.cmd if isinstance(exc.cmd, list) else [str(exc.cmd)]
        return f"command failed (exit {exc.returncode}): {' '.join(str(part) for part in command[:6])} ..."
    return str(exc)


def _verify_arg(value: str) -> tuple[str, int]:
    url, sep, status = value.rpartition("=")
    if not sep or not url.startswith(("http://", "https://")) or not status.isdigit():
        raise argparse.ArgumentTypeError("expected URL=STATUS, for example https://auth.example.invalid/api/health=200")
    return url, int(status)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="agent-homelab-authelia-maintenance",
        description="Stopped-writer Authelia maintenance: validate, stop, back up, apply, start, verify, roll back.",
    )
    root.add_argument("--compose-file", type=Path, required=True)
    root.add_argument("--service", default="authelia")
    root.add_argument("--config", type=Path, required=True, help="live configuration file on the host")
    root.add_argument("--candidate", type=Path, required=True, help="reviewed candidate configuration")
    root.add_argument("--container-config", default="/config/configuration.yml")
    root.add_argument("--database", type=Path, required=True, help="SQLite database file on the host")
    root.add_argument(
        "--key-input", type=Path, action="append", default=[], help="durable referenced input; repeatable"
    )
    root.add_argument("--backup-root", type=Path, required=True)
    root.add_argument("--verify", type=_verify_arg, action="append", default=[], metavar="URL=STATUS")
    root.add_argument("--verify-timeout", type=float, default=60.0)
    root.add_argument("--quiet-seconds", type=float, default=2.0)
    root.add_argument("--apply", action="store_true", help="perform the transaction; default is a dry-run plan")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    target = Target(
        compose_file=args.compose_file.expanduser().absolute(),
        service=args.service,
        config=args.config.expanduser().absolute(),
        candidate=args.candidate.expanduser().absolute(),
        container_config=args.container_config,
        database=args.database.expanduser().absolute(),
        key_inputs=tuple(path.expanduser().absolute() for path in args.key_input),
        backup_root=args.backup_root.expanduser().absolute(),
        verify=tuple(args.verify),
        verify_timeout=args.verify_timeout,
        quiet_seconds=args.quiet_seconds,
    )
    try:
        report = run(target, apply=args.apply)
    except MaintenanceError as exc:
        report = Report(status="failed", error=str(exc))
    print(json.dumps(report.as_dict(), indent=2))
    return {"planned": 0, "complete": 0, "failed": 1, "rolled-back": 2, "rollback-failed": 3}[report.status]


if __name__ == "__main__":
    sys.exit(main())
