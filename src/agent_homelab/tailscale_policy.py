"""Private, conditional Tailscale policy transactions; no mesh administration.

Policy bodies and credentials stay outside Git. Only fixed vendor endpoints are
used, and a write is never retried automatically, including after a timeout.
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .model import InventoryError, load_inventory

TOKEN_URL = "https://api.tailscale.com/api/v2/oauth/token"  # noqa: S105
POLICY_URL = "https://api.tailscale.com/api/v2/tailnet/-/acl"
READER_SCOPES = ("policy_file:read", "devices:posture_attributes:read", "devices:core:read")
WRITER_SCOPES = ("policy_file", "devices:posture_attributes", "devices:core:read")
MAX_BODY = 8 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ENV_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")


class PolicyError(ValueError):
    """An intentionally non-sensitive public error code."""


class TransportError(PolicyError):
    """A request may have reached the server; callers must not retry writes."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes = field(repr=False)


class Transport(Protocol):
    def request(self, method: str, url: str, headers: dict[str, str], body: bytes | None = None) -> Response: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class HTTPSOnlyTransport:
    def request(self, method: str, url: str, headers: dict[str, str], body: bytes | None = None) -> Response:
        if url not in {TOKEN_URL, POLICY_URL, POLICY_URL + "/validate"}:
            raise PolicyError("ENDPOINT_FORBIDDEN")
        # The exact HTTPS-only allowlist above excludes file: and other schemes.
        request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            result = opener.open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            result = exc
        except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException):
            raise TransportError("TRANSPORT_UNAVAILABLE") from None
        try:
            with result:
                payload = result.read(MAX_BODY + 1)
                if len(payload) > MAX_BODY:
                    raise TransportError("RESPONSE_TOO_LARGE")
                return Response(result.code, dict(result.headers.items()), payload)
        except (OSError, ValueError, http.client.HTTPException):
            raise TransportError("TRANSPORT_UNAVAILABLE") from None


@dataclass(frozen=True)
class Settings:
    authority: str
    credential_ref: dict[str, str] = field(repr=False)
    writer_credential_ref: dict[str, str] | None = field(default=None, repr=False)

    @classmethod
    def from_inventory(cls, path: str | Path) -> Settings:
        try:
            config = load_inventory(path).data.get("tailscale")
            if not isinstance(config, dict):
                raise PolicyError("TAILSCALE_NOT_CONFIGURED")
            return cls.from_mapping(config)
        except InventoryError:
            # jsonschema errors may include submitted values, including secrets.
            raise PolicyError("INVENTORY_INVALID") from None

    @classmethod
    def from_mapping(cls, config: dict[str, Any]) -> Settings:
        if set(config) - {"authority", "credential_ref", "writer_credential_ref"}:
            raise PolicyError("TAILSCALE_CONFIG_INVALID")
        if config.get("authority") not in {"console", "gitops"}:
            raise PolicyError("POLICY_AUTHORITY_REQUIRED")
        reader = _reference(config.get("credential_ref"))
        writer = config.get("writer_credential_ref")
        if writer is not None:
            writer = _reference(writer)
            if writer == reader:
                raise PolicyError("SEPARATE_WRITER_REQUIRED")
        return cls(config["authority"], reader, writer)


def _reference(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) != 1:
        raise PolicyError("CREDENTIAL_REFERENCE_INVALID")
    if "file" in value and isinstance(value["file"], str) and Path(value["file"]).is_absolute():
        return dict(value)
    if "env" in value and isinstance(value["env"], str) and ENV_RE.fullmatch(value["env"]):
        return dict(value)
    raise PolicyError("CREDENTIAL_REFERENCE_INVALID")


def _path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise PolicyError("PRIVATE_PATH_MUST_BE_ABSOLUTE")
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise PolicyError("PRIVATE_PATH_SYMLINK")
        if (part / ".git").exists():
            raise PolicyError("PRIVATE_PATH_INSIDE_GIT")
    return path


def _directory(value: str | Path, *, create: bool = False) -> Path:
    path = _path(value)
    if create:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise PolicyError("PRIVATE_DIRECTORY_UNAVAILABLE") from None
    try:
        info = path.lstat()
    except OSError:
        raise PolicyError("PRIVATE_DIRECTORY_UNAVAILABLE") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PolicyError("PRIVATE_DIRECTORY_UNSAFE")
    return path


def _private_read(value: str | Path) -> bytes:
    path = _path(value)
    _directory(path.parent)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise PolicyError("PRIVATE_FILE_UNSAFE")
            payload = stream.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                raise PolicyError("PRIVATE_FILE_TOO_LARGE")
            return payload
    except OSError:
        raise PolicyError("PRIVATE_FILE_UNAVAILABLE") from None


def _private_write(value: str | Path, payload: bytes) -> None:
    path = _path(value)
    _directory(path.parent)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _sync_directory(path.parent)
    except OSError:
        raise PolicyError("PRIVATE_FILE_CREATE_REFUSED") from None


def _replace_receipt(path: Path, data: dict[str, Any]) -> None:
    _private_read(path)
    directory = _directory(path.parent)
    temp_name: str | None = None
    try:
        descriptor, temp_name = tempfile.mkstemp(prefix=".receipt-", dir=directory)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json(data))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        _sync_directory(directory)
    except OSError:
        raise PolicyError("RECEIPT_UPDATE_FAILED") from None
    finally:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _json(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


def _decode_json(payload: bytes, error: str) -> dict[str, Any]:
    try:
        result = json.loads(payload)
    except (ValueError, UnicodeError):
        raise PolicyError(error) from None
    if not isinstance(result, dict):
        raise PolicyError(error)
    return result


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def enroll(path: str | Path) -> dict[str, Any]:
    """Human-only, no-echo intake. Both values are deliberately absent from argv."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise PolicyError("ENROLL_REQUIRES_HUMAN_TTY")
    destination = _path(path)
    _directory(destination.parent, create=True)
    if destination.exists():
        raise PolicyError("PRIVATE_FILE_CREATE_REFUSED")
    try:
        with warnings.catch_warnings():
            # getpass otherwise falls back to echoed stdin when no safe TTY exists.
            warnings.simplefilter("error", getpass.GetPassWarning)
            client_id = getpass.getpass("OAuth client ID (hidden): ")
            client_secret = getpass.getpass("OAuth client secret (hidden): ")
    except getpass.GetPassWarning:
        raise PolicyError("ENROLL_REQUIRES_HUMAN_TTY") from None
    if not client_id.strip() or not client_secret.strip():
        raise PolicyError("CREDENTIAL_INPUT_EMPTY")
    _private_write(destination, _json({"client_id": client_id, "client_secret": client_secret}))
    return {"status": "ENROLLED"}


def _credentials(reference: dict[str, str]) -> dict[str, str]:
    if "file" in reference:
        raw = _private_read(reference["file"])
    else:
        # Read exactly one operator-named variable; never enumerate environment.
        raw_value = os.environ.get(reference["env"])
        if not raw_value:
            raise PolicyError("CREDENTIAL_UNAVAILABLE")
        raw = raw_value.encode()
    data = _decode_json(raw, "CREDENTIAL_INVALID")
    if set(data) != {"client_id", "client_secret"} or any(
        not isinstance(data.get(key), str) or not data[key].strip() for key in ("client_id", "client_secret")
    ):
        raise PolicyError("CREDENTIAL_INVALID")
    return data


class PolicyClient:
    def __init__(self, settings: Settings, *, writer: bool = False, transport: Transport | None = None):
        self.transport = transport or HTTPSOnlyTransport()
        reference = settings.writer_credential_ref if writer else settings.credential_ref
        if reference is None:
            raise PolicyError("WRITER_NOT_CONFIGURED")
        credentials = _credentials(reference)
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                **credentials,
                "scope": " ".join(WRITER_SCOPES if writer else READER_SCOPES),
            }
        ).encode()
        result = self.transport.request("POST", TOKEN_URL, {"Content-Type": "application/x-www-form-urlencoded"}, form)
        if result.status != 200:
            raise PolicyError("OAUTH_UNAVAILABLE")
        token = _decode_json(result.body, "OAUTH_INVALID")
        access = token.get("access_token")
        if not isinstance(access, str) or not access or "\r" in access or "\n" in access:
            raise PolicyError("OAUTH_INVALID")
        self._access = access

    def __repr__(self) -> str:
        return "PolicyClient(<private credential>)"

    def request(self, method: str, *, suffix: str = "", body: bytes | None = None, etag: str | None = None) -> Response:
        headers = {"Authorization": "Bearer " + self._access, "Accept": "application/hujson"}
        if body is not None:
            headers["Content-Type"] = "application/hujson"
        if etag is not None:
            headers["If-Match"] = _if_match(etag)
        return self.transport.request(method, POLICY_URL + suffix, headers, body)

    def read(self) -> tuple[bytes, str]:
        result = self.request("GET")
        if result.status != 200:
            raise PolicyError("POLICY_READ_UNAVAILABLE")
        return result.body, _response_etag(result)

    def validate(self, body: bytes) -> str:
        result = self.request("POST", suffix="/validate", body=body)
        if result.status in {401, 403}:
            return "VALIDATION_UNAVAILABLE"
        if result.status == 200 and not result.body:
            return "VALID"
        return "VALIDATION_FAILED"


def _if_match(etag: Any) -> str:
    if not isinstance(etag, str) or not etag or etag.startswith("W/"):
        raise PolicyError("ETAG_REQUIRED")
    value = etag[1:-1] if etag.startswith('"') and etag.endswith('"') else etag
    if not value or len(value) > 512 or any(ord(char) < 33 or ord(char) > 126 or char == '"' for char in value):
        raise PolicyError("ETAG_INVALID")
    return '"' + value + '"'


def _response_etag(result: Response) -> str:
    etag = next((value for key, value in result.headers.items() if key.lower() == "etag"), None)
    if not isinstance(etag, str):
        raise PolicyError("ETAG_REQUIRED")
    _if_match(etag)
    return etag


def _snapshot(path: str | Path) -> tuple[bytes, dict[str, Any]]:
    directory = _directory(path)
    manifest = _decode_json(_private_read(directory / "manifest.json"), "SNAPSHOT_INVALID")
    body = _private_read(directory / "policy.hujson")
    if manifest.get("version") != 1 or manifest.get("sha256") != _sha(body):
        raise PolicyError("SNAPSHOT_HASH_MISMATCH")
    _if_match(manifest.get("etag"))
    if manifest.get("authority") not in {"console", "gitops"}:
        raise PolicyError("SNAPSHOT_INVALID")
    return body, manifest


def read_policy(settings: Settings, snapshot_dir: str | Path, *, transport: Transport | None = None) -> dict[str, Any]:
    directory = _directory(snapshot_dir, create=True)
    if any(directory.iterdir()):
        raise PolicyError("SNAPSHOT_DIRECTORY_NOT_EMPTY")
    body, etag = PolicyClient(settings, transport=transport).read()
    manifest = {"version": 1, "authority": settings.authority, "etag": etag, "sha256": _sha(body)}
    _private_write(directory / "policy.hujson", body)
    _private_write(directory / "manifest.json", _json(manifest))
    return {"status": "SNAPSHOT_SAVED", "etag": etag, "sha256": manifest["sha256"]}


def plan_policy(
    settings: Settings,
    snapshot: str | Path,
    candidate: str | Path,
    plan_dir: str | Path,
    *,
    transport: Transport | None = None,
) -> dict[str, Any]:
    baseline, manifest = _snapshot(snapshot)
    if manifest["authority"] != settings.authority:
        raise PolicyError("POLICY_AUTHORITY_MISMATCH")
    body = _private_read(candidate)
    directory = _directory(plan_dir, create=True)
    if any(directory.iterdir()):
        raise PolicyError("PLAN_DIRECTORY_NOT_EMPTY")
    try:
        lines = difflib.unified_diff(
            baseline.decode("utf-8").splitlines(keepends=True),
            body.decode("utf-8").splitlines(keepends=True),
            fromfile="snapshot.hujson",
            tofile="candidate.hujson",
        )
        diff = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines)
    except UnicodeError:
        raise PolicyError("POLICY_ENCODING_INVALID") from None
    validation = PolicyClient(settings, transport=transport).validate(body)
    record = {
        "status": "PLANNED",
        "authority": settings.authority,
        "baseline_sha256": manifest["sha256"],
        "candidate_sha256": _sha(body),
        "etag": manifest["etag"],
        "validation": validation,
    }
    _private_write(directory / "policy.diff", diff.encode("utf-8"))
    _private_write(directory / "validation.json", _json(record))
    return record


def _writer_guard(settings: Settings, apply: bool) -> None:
    if not apply:
        raise PolicyError("APPLY_REQUIRED")
    if settings.authority != "console":
        raise PolicyError("GITOPS_DIRECT_WRITE_FORBIDDEN")
    if settings.writer_credential_ref is None or settings.writer_credential_ref == settings.credential_ref:
        raise PolicyError("SEPARATE_WRITER_REQUIRED")


def apply_policy(
    settings: Settings,
    snapshot: str | Path,
    candidate: str | Path,
    expect_etag: str,
    candidate_sha256: str,
    receipt_dir: str | Path,
    *,
    apply: bool = False,
    transport: Transport | None = None,
) -> dict[str, Any]:
    _writer_guard(settings, apply)
    baseline, manifest = _snapshot(snapshot)
    body = _private_read(candidate)
    if not SHA_RE.fullmatch(candidate_sha256) or _sha(body) != candidate_sha256:
        raise PolicyError("CANDIDATE_HASH_MISMATCH")
    if manifest["etag"] != expect_etag or manifest["authority"] != settings.authority:
        raise PolicyError("SNAPSHOT_BINDING_MISMATCH")
    client = PolicyClient(settings, writer=True, transport=transport)
    current, current_etag = client.read()
    if current_etag != expect_etag or current != baseline:
        raise PolicyError("STALE_SNAPSHOT")
    if client.validate(body) != "VALID":
        raise PolicyError("WRITER_VALIDATION_REQUIRED")
    return _write_once(client, baseline, body, expect_etag, receipt_dir, operation="apply")


def _write_once(
    client: PolicyClient,
    baseline: bytes,
    candidate: bytes,
    etag: str,
    receipt_dir: str | Path,
    *,
    operation: str,
) -> dict[str, Any]:
    directory = _directory(receipt_dir, create=True)
    if any(directory.iterdir()):
        raise PolicyError("RECEIPT_DIRECTORY_NOT_EMPTY")
    receipt: dict[str, Any] = {
        "version": 1,
        "operation": operation,
        "status": "WRITE_ATTEMPTED",
        "authority": "console",
        "baseline_sha256": _sha(baseline),
        "candidate_sha256": _sha(candidate),
        "baseline_etag": etag,
        "produced_etag": None,
    }
    _private_write(directory / "original.hujson", baseline)
    _private_write(directory / "candidate.hujson", candidate)
    receipt_path = directory / "receipt.json"
    _private_write(receipt_path, _json(receipt))
    try:
        result = client.request("POST", body=candidate, etag=etag)
    except TransportError:
        result = None
    if result is not None and result.status == 412:
        receipt["status"] = "CONFLICT"
    elif result is not None and 400 <= result.status < 500:
        receipt["status"] = "WRITE_REJECTED"
    else:
        # Only the POST response can identify the version created by this write.
        # A later GET may belong to a concurrent writer, even with identical bytes.
        post_etag = None
        if result is not None and result.status == 200:
            try:
                post_etag = _response_etag(result)
                receipt["post_etag"] = post_etag
            except PolicyError:
                pass
        # One observation after success or uncertain transport; never another POST.
        try:
            observed, observed_etag = client.read()
            receipt["observed_sha256"] = _sha(observed)
            receipt["observed_etag"] = observed_etag
            if post_etag is not None and observed_etag == post_etag and observed == candidate:
                receipt["status"] = "APPLIED" if operation == "apply" else "ROLLED_BACK"
                receipt["produced_etag"] = post_etag
            else:
                receipt["status"] = "WRITE_UNCERTAIN"
        except PolicyError:
            receipt["status"] = "WRITE_UNCERTAIN"
    _replace_receipt(receipt_path, receipt)
    return receipt


def rollback_policy(
    settings: Settings,
    receipt: str | Path,
    receipt_dir: str | Path,
    *,
    apply: bool = False,
    transport: Transport | None = None,
) -> dict[str, Any]:
    _writer_guard(settings, apply)
    path = _path(receipt)
    record = _decode_json(_private_read(path), "RECEIPT_INVALID")
    if (
        record.get("version") != 1
        or record.get("operation") != "apply"
        or record.get("status") != "APPLIED"
        or record.get("authority") != "console"
    ):
        raise PolicyError("ROLLBACK_NOT_ELIGIBLE")
    original = _private_read(path.parent / "original.hujson")
    candidate = _private_read(path.parent / "candidate.hujson")
    if _sha(original) != record.get("baseline_sha256") or _sha(candidate) != record.get("candidate_sha256"):
        raise PolicyError("ROLLBACK_HASH_MISMATCH")
    produced = record.get("produced_etag")
    _if_match(produced)
    client = PolicyClient(settings, writer=True, transport=transport)
    current, etag = client.read()
    if etag != produced or current != candidate:
        raise PolicyError("ROLLBACK_VERSION_CHANGED")
    if client.validate(original) != "VALID":
        raise PolicyError("WRITER_VALIDATION_REQUIRED")
    return _write_once(client, candidate, original, etag, receipt_dir, operation="rollback")


def add_parser(subparsers: Any) -> argparse.ArgumentParser:
    group = subparsers.add_parser("tailscale-policy", help="private snapshots and conditional Tailscale policy changes")
    sub = group.add_subparsers(dest="tailscale_command", required=True)
    intake = sub.add_parser("enroll", help="human-only hidden OAuth credential intake")
    intake.add_argument("--credential-file", required=True)
    read = sub.add_parser("read", help="save canonical raw policy and ETag privately")
    read.add_argument("--inventory", default="homelab.yaml")
    read.add_argument("--snapshot-dir", required=True)
    plan = sub.add_parser("plan", help="save a private diff and vendor validation result")
    plan.add_argument("--inventory", default="homelab.yaml")
    plan.add_argument("--snapshot", required=True)
    plan.add_argument("--candidate", required=True)
    plan.add_argument("--plan-dir", required=True)
    apply = sub.add_parser("apply", help="write once with explicit candidate and version checks")
    apply.add_argument("--inventory", default="homelab.yaml")
    apply.add_argument("--snapshot", required=True)
    apply.add_argument("--candidate", required=True)
    apply.add_argument("--expect-etag", required=True)
    apply.add_argument("--candidate-sha256", required=True)
    apply.add_argument("--receipt-dir", required=True)
    apply.add_argument("--apply", action="store_true")
    rollback = sub.add_parser("rollback", help="conditionally restore the original policy from a confirmed receipt")
    rollback.add_argument("--inventory", default="homelab.yaml")
    rollback.add_argument("--receipt", required=True)
    rollback.add_argument("--receipt-dir", required=True)
    rollback.add_argument("--apply", action="store_true")
    return group


def run(args: argparse.Namespace) -> int:
    try:
        if args.tailscale_command == "enroll":
            result = enroll(args.credential_file)
        else:
            settings = Settings.from_inventory(args.inventory)
            if args.tailscale_command == "read":
                result = read_policy(settings, args.snapshot_dir)
            elif args.tailscale_command == "plan":
                result = plan_policy(settings, args.snapshot, args.candidate, args.plan_dir)
            elif args.tailscale_command == "apply":
                result = apply_policy(
                    settings,
                    args.snapshot,
                    args.candidate,
                    args.expect_etag,
                    args.candidate_sha256,
                    args.receipt_dir,
                    apply=args.apply,
                )
            elif args.tailscale_command == "rollback":
                result = rollback_policy(settings, args.receipt, args.receipt_dir, apply=args.apply)
            else:
                raise PolicyError("COMMAND_INVALID")
        print(json.dumps(result, indent=2, sort_keys=True))
        bad = result.get("status") in {"CONFLICT", "WRITE_REJECTED", "WRITE_UNCERTAIN"}
        bad = bad or result.get("validation") in {"VALIDATION_FAILED", "VALIDATION_UNAVAILABLE"}
        return 2 if bad else 0
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, EOFError, KeyboardInterrupt):
        print("error: TAILSCALE_OPERATION_UNAVAILABLE", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    root = argparse.ArgumentParser(prog="agent-homelab")
    add_parser(root.add_subparsers(dest="command", required=True))
    return run(root.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
