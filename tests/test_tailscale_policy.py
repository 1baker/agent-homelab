from __future__ import annotations

import http.client
import json
import os
import stat
import urllib.parse
from dataclasses import replace
from pathlib import Path

import pytest

from agent_homelab import tailscale_policy as tp

BASELINE = b'{\n // retain this comment\n "grants": [], "unknown": {"keep": true},\n}\n'
CANDIDATE = b'{\n // retain this comment\n "grants": [], "unknown": {"keep": false},\n}\n'
FAKE_SECRET = "test-only-client-secret"
FAKE_TOKEN = "test-only-access-token"


class FakeTransport:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def request(self, method, url, headers, body=None):
        self.calls.append((method, url, headers, body))
        if not self.results:
            raise AssertionError("unexpected transport call")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def oauth():
    return tp.Response(200, {}, json.dumps({"access_token": FAKE_TOKEN}).encode())


def policy(body=BASELINE, etag='"version-1"'):
    return tp.Response(200, {"ETag": etag}, body)


def private(directory: Path, name: str, body: bytes) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / name
    path.write_bytes(body)
    path.chmod(0o600)
    return path


@pytest.fixture
def settings(tmp_path):
    reader = private(
        tmp_path / "creds",
        "reader.json",
        json.dumps(
            {
                "client_id": "test-reader",
                "client_secret": FAKE_SECRET,
            }
        ).encode(),
    )
    writer = private(
        tmp_path / "creds",
        "writer.json",
        json.dumps(
            {
                "client_id": "test-writer",
                "client_secret": FAKE_SECRET,
            }
        ).encode(),
    )
    return tp.Settings("console", {"file": str(reader)}, {"file": str(writer)})


@pytest.fixture
def snapshot(settings, tmp_path):
    path = tmp_path / "snapshot"
    tp.read_policy(settings, path, transport=FakeTransport(oauth(), policy()))
    return path


@pytest.fixture
def candidate(tmp_path):
    return private(tmp_path / "candidate", "candidate.hujson", CANDIDATE)


def apply_call(settings, snapshot, candidate, tmp_path, transport, **overrides):
    options = {
        "expect_etag": '"version-1"',
        "candidate_sha256": tp._sha(CANDIDATE),
        "receipt_dir": tmp_path / "receipt",
        "apply": True,
        "transport": transport,
    }
    options.update(overrides)
    return tp.apply_policy(settings, snapshot, candidate, **options)


def write_calls(transport):
    return [call for call in transport.calls if call[0] == "POST" and call[1] == tp.POLICY_URL]


def test_raw_hujson_snapshot_and_token_scope(settings, tmp_path):
    transport = FakeTransport(oauth(), policy())
    result = tp.read_policy(settings, tmp_path / "snapshot", transport=transport)
    assert (tmp_path / "snapshot/policy.hujson").read_bytes() == BASELINE
    manifest = json.loads((tmp_path / "snapshot/manifest.json").read_text())
    assert manifest["etag"] == '"version-1"'
    assert result["sha256"] == tp._sha(BASELINE)
    assert transport.calls[0][1] == tp.TOKEN_URL
    form = urllib.parse.parse_qs(transport.calls[0][3].decode())
    assert set(form["scope"][0].split()) == set(tp.READER_SCOPES)
    assert transport.calls[1][2]["Accept"] == "application/hujson"
    for path in (tmp_path / "snapshot").iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert FAKE_SECRET.encode() not in path.read_bytes()
        assert FAKE_TOKEN.encode() not in path.read_bytes()
    assert FAKE_SECRET not in repr(result)
    assert FAKE_TOKEN not in repr(result)


@pytest.mark.parametrize("etag", ['"version-1"', "version-1"])
def test_if_match_quoted_and_unquoted(etag):
    assert tp._if_match(etag) == '"version-1"'


@pytest.mark.parametrize("etag", [None, "", 'W/"weak"', '"bad\r\nheader"', 'bad"quote'])
def test_invalid_etags(etag):
    with pytest.raises(tp.PolicyError):
        tp._if_match(etag)


def test_missing_etag_rejected(settings, tmp_path):
    transport = FakeTransport(oauth(), tp.Response(200, {}, BASELINE))
    with pytest.raises(tp.PolicyError, match="ETAG_REQUIRED"):
        tp.read_policy(settings, tmp_path / "snapshot", transport=transport)


def test_snapshot_directory_cannot_overwrite(settings, snapshot):
    transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match="NOT_EMPTY"):
        tp.read_policy(settings, snapshot, transport=transport)
    assert not transport.calls


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400])
def test_credential_modes_rejected(settings, mode):
    Path(settings.credential_ref["file"]).chmod(mode)
    transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match="PRIVATE_FILE_UNSAFE"):
        tp.PolicyClient(settings, transport=transport)
    assert not transport.calls


def test_credential_owner_rejected(settings, monkeypatch):
    current = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: current + 1)
    with pytest.raises(tp.PolicyError, match="UNSAFE"):
        tp.PolicyClient(settings, transport=FakeTransport())


def test_credential_symlink_rejected(settings, tmp_path):
    link = tmp_path / "creds/link.json"
    link.symlink_to(settings.credential_ref["file"])
    with pytest.raises(tp.PolicyError, match="SYMLINK"):
        tp.PolicyClient(replace(settings, credential_ref={"file": str(link)}), transport=FakeTransport())


def test_credential_symlink_parent_rejected(settings, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path / "creds", target_is_directory=True)
    with pytest.raises(tp.PolicyError, match="SYMLINK"):
        tp.PolicyClient(
            replace(settings, credential_ref={"file": str(alias / "reader.json")}),
            transport=FakeTransport(),
        )


def test_private_files_reject_git_worktree(tmp_path):
    (tmp_path / ".git").write_text("gitdir: elsewhere")
    path = private(tmp_path / "state", "credentials.json", b"{}")
    with pytest.raises(tp.PolicyError, match="INSIDE_GIT"):
        tp._private_read(path)


def test_private_directory_mode_rejected(settings):
    Path(settings.credential_ref["file"]).parent.chmod(0o755)
    with pytest.raises(tp.PolicyError, match="DIRECTORY_UNSAFE"):
        tp.PolicyClient(settings, transport=FakeTransport())


def test_only_explicit_environment_reference_is_read(monkeypatch):
    class Environment:
        def get(self, name):
            assert name == "TEST_TAILSCALE_READER"
            return json.dumps({"client_id": "test-reader", "client_secret": FAKE_SECRET})

        def __iter__(self):
            raise AssertionError("environment enumeration forbidden")

    settings = tp.Settings("console", {"env": "TEST_TAILSCALE_READER"})
    with monkeypatch.context() as patch:
        patch.setattr(os, "environ", Environment())
        client = tp.PolicyClient(settings, transport=FakeTransport(oauth()))
    assert FAKE_TOKEN not in repr(client)


@pytest.mark.parametrize("extra", [{"client_secret": FAKE_SECRET}, {"client_id": "test-inline"}])
def test_inline_credential_fields_rejected(extra):
    with pytest.raises(tp.PolicyError, match="CONFIG_INVALID"):
        tp.Settings.from_mapping({"authority": "console", "credential_ref": {"env": "TEST_READER"}, **extra})


def test_enroll_requires_tty(tmp_path, monkeypatch):
    monkeypatch.setattr(tp.sys.stdin, "isatty", lambda: False)
    with pytest.raises(tp.PolicyError, match="HUMAN_TTY"):
        tp.enroll(tmp_path / "private/reader.json")


def test_enroll_hidden_exclusive(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(tp.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(tp.sys.stderr, "isatty", lambda: True)
    values = iter(["test-client-id", FAKE_SECRET])
    monkeypatch.setattr(tp.getpass, "getpass", lambda prompt: next(values))
    path = tmp_path / "private/reader.json"
    assert tp.enroll(path) == {"status": "ENROLLED"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(tp.PolicyError, match="CREATE_REFUSED"):
        tp.enroll(path)
    captured = capsys.readouterr()
    assert FAKE_SECRET not in captured.out + captured.err


@pytest.mark.parametrize(
    "response,expected",
    [
        (tp.Response(200, {}, b""), "VALID"),
        (tp.Response(200, {}, b'{"errors":["private details"]}'), "VALIDATION_FAILED"),
        (tp.Response(200, {}, b"\n"), "VALIDATION_FAILED"),
        (tp.Response(401, {}, b"private denied detail"), "VALIDATION_UNAVAILABLE"),
        (tp.Response(403, {}, b"private denied detail"), "VALIDATION_UNAVAILABLE"),
        (tp.Response(400, {}, b"private failed test detail"), "VALIDATION_FAILED"),
    ],
)
def test_vendor_validation_empty_success_only(settings, snapshot, candidate, tmp_path, response, expected):
    transport = FakeTransport(oauth(), response)
    result = tp.plan_policy(settings, snapshot, candidate, tmp_path / "plan", transport=transport)
    assert result["validation"] == expected
    assert transport.calls[-1][3] == CANDIDATE
    assert (tmp_path / "plan/policy.diff").read_text().startswith("--- snapshot.hujson")
    assert "private denied detail" not in (tmp_path / "plan/validation.json").read_text()


def test_candidate_hash_mismatch_before_auth(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match="CANDIDATE_HASH_MISMATCH"):
        apply_call(settings, snapshot, candidate, tmp_path, transport, candidate_sha256="0" * 64)
    assert not transport.calls


@pytest.mark.parametrize("current", [policy(etag='"changed"'), policy(body=CANDIDATE)])
def test_stale_snapshot_refuses_before_post(settings, snapshot, candidate, tmp_path, current):
    transport = FakeTransport(oauth(), current)
    with pytest.raises(tp.PolicyError, match="STALE_SNAPSHOT"):
        apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert not write_calls(transport)


def test_apply_requires_successful_writer_validation(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport(oauth(), policy(), tp.Response(403, {}, b"private"))
    with pytest.raises(tp.PolicyError, match="WRITER_VALIDATION_REQUIRED"):
        apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert not write_calls(transport)
    form = urllib.parse.parse_qs(transport.calls[0][3].decode())
    assert set(form["scope"][0].split()) == set(tp.WRITER_SCOPES)


@pytest.mark.parametrize(
    "setting,apply,code",
    [
        ("reader", True, "SEPARATE_WRITER_REQUIRED"),
        ("gitops", True, "GITOPS_DIRECT_WRITE_FORBIDDEN"),
        ("writer", False, "APPLY_REQUIRED"),
    ],
)
def test_write_guards_before_network(settings, snapshot, candidate, tmp_path, setting, apply, code):
    if setting == "reader":
        settings = replace(settings, writer_credential_ref=None)
    elif setting == "gitops":
        settings = replace(settings, authority="gitops")
    transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match=code):
        apply_call(settings, snapshot, candidate, tmp_path, transport, apply=apply)
    assert not transport.calls


def test_conflict_is_one_post_without_retry(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport(oauth(), policy(), tp.Response(200, {}, b""), tp.Response(412, {}, b"private"))
    result = apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert result["status"] == "CONFLICT"
    assert result["produced_etag"] is None
    assert len(write_calls(transport)) == 1
    assert write_calls(transport)[0][2]["If-Match"] == '"version-1"'
    assert not transport.results


def test_uncertain_write_observed_without_retry(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport(
        oauth(),
        policy(),
        tp.Response(200, {}, b""),
        tp.TransportError("TRANSPORT_UNAVAILABLE"),
        policy(CANDIDATE, '"version-2"'),
    )
    result = apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert result["status"] == "WRITE_UNCERTAIN"
    assert result["observed_sha256"] == tp._sha(CANDIDATE)
    assert result["produced_etag"] is None
    assert len(write_calls(transport)) == 1
    assert transport.calls[-1][0] == "GET"


def test_success_requires_exact_readback(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport(
        oauth(),
        policy(),
        tp.Response(200, {}, b""),
        tp.Response(200, {"ETag": '"version-2"'}, b"ignored"),
        policy(CANDIDATE, '"version-2"'),
    )
    result = apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert result["status"] == "APPLIED"
    assert result["produced_etag"] == '"version-2"'
    for path in (tmp_path / "receipt").iterdir():
        assert FAKE_SECRET.encode() not in path.read_bytes()
        assert FAKE_TOKEN.encode() not in path.read_bytes()


def applied_receipt(settings, snapshot, candidate, tmp_path):
    transport = FakeTransport(
        oauth(),
        policy(),
        tp.Response(200, {}, b""),
        tp.Response(200, {"ETag": '"version-2"'}, b""),
        policy(CANDIDATE, '"version-2"'),
    )
    apply_call(settings, snapshot, candidate, tmp_path, transport)
    return tmp_path / "receipt/receipt.json"


def test_rollback_compare_and_swap(settings, snapshot, candidate, tmp_path):
    receipt = applied_receipt(settings, snapshot, candidate, tmp_path)
    transport = FakeTransport(
        oauth(),
        policy(CANDIDATE, '"version-2"'),
        tp.Response(200, {}, b""),
        tp.Response(200, {"ETag": '"version-3"'}, b""),
        policy(BASELINE, '"version-3"'),
    )
    result = tp.rollback_policy(settings, receipt, tmp_path / "rollback", apply=True, transport=transport)
    assert result["status"] == "ROLLED_BACK"
    assert write_calls(transport)[0][2]["If-Match"] == '"version-2"'
    assert write_calls(transport)[0][3] == BASELINE
    assert len(write_calls(transport)) == 1


def test_rollback_refuses_changed_version(settings, snapshot, candidate, tmp_path):
    receipt = applied_receipt(settings, snapshot, candidate, tmp_path)
    transport = FakeTransport(oauth(), policy(CANDIDATE, '"somebody-else"'))
    with pytest.raises(tp.PolicyError, match="ROLLBACK_VERSION_CHANGED"):
        tp.rollback_policy(settings, receipt, tmp_path / "rollback", apply=True, transport=transport)
    assert not write_calls(transport)


def test_tampered_snapshot_refuses_before_auth(settings, snapshot, candidate, tmp_path):
    (snapshot / "policy.hujson").write_bytes(b"tampered")
    transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match="SNAPSHOT_HASH_MISMATCH"):
        apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert not transport.calls


def test_oauth_error_does_not_echo_private_body(settings):
    transport = FakeTransport(tp.Response(401, {}, FAKE_SECRET.encode()))
    with pytest.raises(tp.PolicyError, match="OAUTH_UNAVAILABLE") as error:
        tp.PolicyClient(settings, transport=transport)
    assert FAKE_SECRET not in str(error.value)


def test_fixed_endpoint_transport_refuses_other_urls():
    with pytest.raises(tp.PolicyError, match="ENDPOINT_FORBIDDEN"):
        tp.HTTPSOnlyTransport().request("POST", "https://elsewhere.invalid/token", {}, b"private")


def test_redirect_handler_does_not_follow():
    assert tp._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid/") is None


@pytest.mark.parametrize(
    "post_headers,observed_etag",
    [
        ({"ETag": '"version-2"'}, '"later-identical-version"'),
        ({}, '"version-2"'),
        ({"ETag": 'W/"weak-version"'}, '"version-2"'),
        ({"ETag": '"invalid\r\nheader"'}, '"version-2"'),
    ],
)
def test_apply_etag_belongs_to_post_not_later_get(
    settings,
    snapshot,
    candidate,
    tmp_path,
    post_headers,
    observed_etag,
):
    transport = FakeTransport(
        oauth(),
        policy(),
        tp.Response(200, {}, b""),
        tp.Response(200, post_headers, b""),
        policy(CANDIDATE, observed_etag),
    )
    result = apply_call(settings, snapshot, candidate, tmp_path, transport)
    assert result["status"] == "WRITE_UNCERTAIN"
    assert result["produced_etag"] is None
    assert result["observed_etag"] == observed_etag
    assert result["observed_sha256"] == tp._sha(CANDIDATE)
    assert len(write_calls(transport)) == 1
    rollback_transport = FakeTransport()
    with pytest.raises(tp.PolicyError, match="ROLLBACK_NOT_ELIGIBLE"):
        tp.rollback_policy(
            settings,
            tmp_path / "receipt/receipt.json",
            tmp_path / "rollback",
            apply=True,
            transport=rollback_transport,
        )
    assert not rollback_transport.calls


def test_truncated_http_response_is_sanitized_transport_error(monkeypatch):
    class TruncatedResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            raise http.client.IncompleteRead(FAKE_SECRET.encode(), 100)

    class Opener:
        def open(self, request, timeout):
            return TruncatedResponse()

    monkeypatch.setattr(tp.urllib.request, "build_opener", lambda handler: Opener())
    with pytest.raises(tp.TransportError, match="TRANSPORT_UNAVAILABLE") as error:
        tp.HTTPSOnlyTransport().request("POST", tp.POLICY_URL, {}, CANDIDATE)
    assert FAKE_SECRET not in str(error.value)
