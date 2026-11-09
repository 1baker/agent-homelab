from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_homelab import verify


@dataclass
class FakeResponse:
    status: int
    location: str | None = None

    def getheader(self, name: str) -> str | None:
        return self.location if name == "Location" else None

    def read(self, _limit: int) -> bytes:
        return b""


class FakeConnection:
    response = FakeResponse(200)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def request(self, *_args: object, **_kwargs: object) -> None:
        pass

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    "status,expected",
    [(200, True), (302, True), (400, False), (403, False), (404, False), (500, False)],
)
def test_unprotected_route_requires_success_or_redirect(
    monkeypatch: pytest.MonkeyPatch, status: int, expected: bool
) -> None:
    FakeConnection.response = FakeResponse(status)
    monkeypatch.setattr(verify.http.client, "HTTPConnection", FakeConnection)
    assert verify.probe("app", "local", "http://app.localhost").ok is expected


def test_protected_route_requires_auth_host_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeConnection.response = FakeResponse(302, "https://auth.example.net/")
    monkeypatch.setattr(verify.http.client, "HTTPSConnection", FakeConnection)
    result = verify.probe("app", "public", "https://app.example.net", expected_auth_redirect=True)
    assert result.ok is True

    FakeConnection.response = FakeResponse(302, "https://unrelated.example.net/")
    result = verify.probe("app", "public", "https://app.example.net", expected_auth_redirect=True)
    assert result.ok is False


def test_probe_spec_sends_forged_header_and_checks_expected_status(monkeypatch) -> None:
    sent: dict = {}

    class Connection:
        def __init__(self, host, port, **kwargs):
            sent["host"] = host

        def request(self, method, path, body=None, headers=None):
            sent.update(method=method, path=path, headers=headers)

        def getresponse(self):
            return FakeResponse(200 if sent["headers"].get("X-Forwarded-Host") else 302, "https://auth.example.net/")

        def close(self):
            pass

    monkeypatch.setattr(verify.http.client, "HTTPSConnection", Connection)
    spec = {
        "name": "app-forged-forwarded-host",
        "url": "https://app.example.net/",
        "method": "GET",
        "headers": {"X-Forwarded-Host": "auth.example.net"},
        "expect": [302, 401],
    }
    result = verify.probe_spec(spec)
    assert sent["headers"]["X-Forwarded-Host"] == "auth.example.net"
    assert result.ok is False and result.status == 200 and "got 200" in result.detail
    spec["headers"] = {}
    assert verify.probe_spec(spec).ok is True
