from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "skills/homelab-mcp-connector/scripts/check_mcp_route.py"
spec = importlib.util.spec_from_file_location("check_mcp_route", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

RESOURCE = "https://mcp.example.com/mcp"
META_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
GOOD_META = {"resource": RESOURCE, "authorization_servers": ["https://auth.example.com"]}
GOOD_CHALLENGE = 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'


def meta(**fields):
    return json.dumps({**GOOD_META, **fields}).encode()


def test_valid_metadata_and_challenge_pass():
    assert probe.check_metadata(200, json.dumps(GOOD_META).encode(), RESOURCE, META_URL) == []
    assert probe.check_challenge(401, {"WWW-Authenticate": GOOD_CHALLENGE}) == []


def test_challenge_scheme_is_case_insensitive_and_allows_other_params():
    header = 'bearer error="invalid_token", resource_metadata="https://mcp.example.com/m"'
    assert probe.check_challenge(401, {"www-authenticate": header}) == []


@pytest.mark.parametrize(
    "header",
    [
        'BearerX resource_metadata="https://mcp.example.com/m"',
        'Basic resource_metadata="https://mcp.example.com/m"',
        'Bearer resource_metadata=""',
        "Bearer resource_metadata=",
        'Bearer resource_metadata="not-a-url"',
        'Bearer resource_metadata="http://mcp.example.com/m"',
        'Bearer realm="x"',
        "Bearer",
        "",
    ],
)
def test_malformed_challenge_fails(header):
    assert probe.check_challenge(401, {"WWW-Authenticate": header})


def test_challenge_requires_401():
    assert probe.check_challenge(200, {"WWW-Authenticate": GOOD_CHALLENGE})


@pytest.mark.parametrize(
    "body",
    [
        meta(authorization_servers="https://auth.example.com"),
        meta(authorization_servers=[]),
        meta(authorization_servers=[""]),
        meta(authorization_servers=["not-a-url"]),
        meta(authorization_servers=[42]),
        meta(resource="https://other.example.com/mcp"),
        b"[]",
        b"not json",
    ],
)
def test_malformed_metadata_fails(body):
    assert probe.check_metadata(200, body, RESOURCE, META_URL)


def test_metadata_requires_200():
    assert probe.check_metadata(302, b"", RESOURCE, META_URL)
