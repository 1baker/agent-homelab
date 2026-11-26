"""Classify supplied listener observations; no runtime discovery, I/O or effects."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

MAX_POLICY_BYTES = 65536
MAX_HOLDS = 64
MAX_HOLD_AGE = timedelta(days=14)
_FIELDS = {"route_port", "backend", "owner", "reason", "ticket", "starts_at", "expires_at"}


class _InvalidPolicy(ValueError):
    pass


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidPolicy("duplicate key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> object:
    raise _InvalidPolicy("non-JSON number")


def _port(value: object) -> bool:
    return type(value) is int and 1 <= value <= 65535


def _backend(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", value):
        return False
    return int(value.rsplit(":", 1)[1]) <= 65535


def _text(value: object, limit: int) -> bool:
    return (
        isinstance(value, str) and 0 < len(value) <= limit and bool(value.strip())
        and all(32 <= ord(char) <= 126 for char in value)
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise _InvalidPolicy("invalid timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _holds(raw: bytes | None) -> list[dict[str, object]]:
    if raw is None:
        return []
    if not isinstance(raw, bytes) or len(raw) > MAX_POLICY_BYTES:
        raise _InvalidPolicy("invalid size or type")
    policy = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    if (
        not isinstance(policy, dict) or set(policy) != {"schema_version", "expected_down"}
        or type(policy["schema_version"]) is not int or policy["schema_version"] != 1
        or not isinstance(policy["expected_down"], list) or len(policy["expected_down"]) > MAX_HOLDS
    ):
        raise _InvalidPolicy("invalid schema")
    seen = set()
    for entry in policy["expected_down"]:
        if (
            not isinstance(entry, dict) or set(entry) != _FIELDS
            or not _port(entry["route_port"]) or not _backend(entry["backend"])
            or not _text(entry["owner"], 64) or not _text(entry["reason"], 256)
            or not _text(entry["ticket"], 256)
        ):
            raise _InvalidPolicy("invalid entry")
        pair = (entry["route_port"], entry["backend"])
        if pair in seen:
            raise _InvalidPolicy("duplicate route/backend")
        seen.add(pair)
        start, end = _time(entry["starts_at"]), _time(entry["expires_at"])
        if not timedelta(0) < end - start <= MAX_HOLD_AGE:
            raise _InvalidPolicy("invalid lifetime")
    return policy["expected_down"]


def _result(status: str, reason: str) -> dict[str, object]:
    # No owner-supplied strings or exception text escape into health logs/alerts.
    return {"status": status, "reason": reason, "alert_required": status == "FAIL"}


def classify_backend(
    policy_bytes: bytes | None, *, route_port: int, backend: str, listener_up: bool, now: datetime
) -> dict[str, object]:
    """Return PASS/HELD/FAIL using an explicitly supplied policy and UTC clock.

    Missing policy never suppresses failure. Invalid policy/observations fail
    closed. HELD is advisory expected-down intent, not proof of runtime custody.
    The caller must keep HELD visible and route FAIL to its qualified alert sink.
    """
    if (
        not _port(route_port) or not _backend(backend) or type(listener_up) is not bool
        or not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0)
    ):
        return _result("FAIL", "invalid_observation")
    try:
        holds = _holds(policy_bytes)
    except (ValueError, TypeError, RecursionError):
        return _result("FAIL", "invalid_policy")
    if listener_up:
        return _result("PASS", "listener_up")
    for entry in holds:
        if (
            entry["route_port"] == route_port and entry["backend"] == backend
            and _time(entry["starts_at"]) <= now < _time(entry["expires_at"])
        ):
            return _result("HELD", "expected_down")
    return _result("FAIL", "listener_missing")
