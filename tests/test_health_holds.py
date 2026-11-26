from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from agent_homelab.health_holds import classify_backend

NOW = datetime(2026, 1, 8, tzinfo=UTC)


def policy(**changes):
    entry = {
        "route_port": 9443,
        "backend": "127.0.0.1:19094",
        "owner": "example-owner",
        "reason": "Planned maintenance",
        "ticket": "https://tracker.example.invalid/issues/1",
        "starts_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-15T00:00:00Z",
    }
    entry.update(changes)
    return json.dumps({"schema_version": 1, "expected_down": [entry]}).encode()


class HealthHoldsTests(unittest.TestCase):
    def test_explicit_active_hold_is_visible_without_failure(self):
        result = classify_backend(
            policy(), route_port=9443, backend="127.0.0.1:19094", listener_up=False, now=NOW
        )
        self.assertEqual(result, {"status": "HELD", "reason": "expected_down", "alert_required": False})

    def test_hold_stops_suppressing_failure_at_exact_expiry(self):
        result = classify_backend(
            policy(expires_at="2026-01-08T00:00:00Z"), route_port=9443,
            backend="127.0.0.1:19094", listener_up=False, now=NOW
        )
        self.assertEqual(result, {"status": "FAIL", "reason": "listener_missing", "alert_required": True})

    def test_overlong_hold_is_invalid_policy_even_before_expiry(self):
        result = classify_backend(
            policy(expires_at="2026-01-16T00:00:00Z"), route_port=9443,
            backend="127.0.0.1:19094", listener_up=False, now=NOW
        )
        self.assertEqual(result, {"status": "FAIL", "reason": "invalid_policy", "alert_required": True})


    def classify(self, raw=None, **changes):
        args = {"route_port": 9443, "backend": "127.0.0.1:19094", "listener_up": False, "now": NOW}
        args.update(changes)
        return classify_backend(raw, **args)

    def assert_failure(self, raw=None, **changes):
        result = self.classify(raw, **changes)
        self.assertEqual(result["status"], "FAIL")
        self.assertIs(result["alert_required"], True)
        return result

    def test_missing_policy_does_not_hide_outage(self):
        self.assert_failure()

    def test_empty_policy_does_not_hide_outage(self):
        self.assert_failure(b'{"schema_version":1,"expected_down":[]}')

    def test_present_listener_is_healthy(self):
        self.assertEqual(self.classify(listener_up=True),
                         {"status": "PASS", "reason": "listener_up", "alert_required": False})

    def test_present_listener_is_not_labelled_held(self):
        self.assertEqual(self.classify(policy(), listener_up=True)["status"], "PASS")

    def test_mismatched_route_does_not_hide_other_outage(self):
        self.assert_failure(policy(), route_port=8443)

    def test_mismatched_backend_does_not_hide_other_outage(self):
        self.assert_failure(policy(), backend="127.0.0.1:19095")

    def test_future_hold_does_not_hide_current_outage(self):
        self.assert_failure(policy(starts_at="2026-01-09T00:00:00Z", expires_at="2026-01-10T00:00:00Z"))

    def test_expired_hold_does_not_hide_outage(self):
        self.assert_failure(policy(expires_at="2026-01-07T00:00:00Z"))

    def test_hold_is_effective_at_exact_start(self):
        self.assertEqual(self.classify(policy(), now=datetime(2026, 1, 1, tzinfo=UTC))["status"], "HELD")

    def test_hold_is_effective_just_before_expiry(self):
        self.assertEqual(self.classify(policy(), now=datetime(2026, 1, 15, tzinfo=UTC)
                                      - timedelta(microseconds=1))["status"], "HELD")

    def test_inverted_or_zero_lifetime_fails_closed(self):
        for expiry in ("2025-12-31T00:00:00Z", "2026-01-01T00:00:00Z"):
            with self.subTest(expiry=expiry):
                self.assert_failure(policy(expires_at=expiry))

    def test_required_metadata_cannot_be_missing_empty_or_control_text(self):
        for key in ("owner", "reason", "ticket", "starts_at", "expires_at"):
            for bad in (None, "", " ", "line\nbreak", 1):
                with self.subTest(key=key, bad=bad):
                    self.assert_failure(policy(**{key: bad}))
            value = json.loads(policy())
            del value["expected_down"][0][key]
            self.assert_failure(json.dumps(value).encode())

    def test_noncanonical_or_impossible_times_fail_closed(self):
        for bad in ("2026-1-1T00:00:00Z", "2026-01-01", "2026-01-01T00:00:00+00:00",
                    "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z"):
            with self.subTest(bad=bad):
                self.assert_failure(policy(starts_at=bad))

    def test_route_ports_must_be_unambiguous_valid_integers(self):
        for bad in (True, "9443", 0, -1, 65536, 9443.0):
            with self.subTest(bad=bad):
                self.assert_failure(policy(route_port=bad))
                self.assert_failure(policy(), route_port=bad)

    def test_noncanonical_or_nonloopback_backend_cannot_be_suppressed(self):
        for bad in ("localhost:19094", "192.0.2.1:19094", "127.0.0.1:019094", "127.0.0.1:65536",
                    "http://127.0.0.1:19094", "127.0.0.1:0", "[::1]:19094", None):
            with self.subTest(bad=bad):
                self.assert_failure(policy(backend=bad))
                self.assert_failure(policy(), backend=bad)

    def test_invalid_observations_fail_even_with_active_hold(self):
        for changes in ({"listener_up": 1}, {"now": NOW.replace(tzinfo=None)}, {"now": "2026-01-08"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.assert_failure(policy(), **changes)["reason"], "invalid_observation")

    def test_duplicate_record_cannot_ambiguously_extend_hold(self):
        value = json.loads(policy())
        value["expected_down"].append(value["expected_down"][0].copy())
        self.assert_failure(json.dumps(value).encode())

    def test_unknown_or_mistyped_schema_fields_fail_closed(self):
        for value in ({}, [], {"schema_version": True, "expected_down": []},
                      {"schema_version": 2, "expected_down": []},
                      {"schema_version": 1, "expected_down": {}},
                      {"schema_version": 1, "expected_down": [], "override": True}):
            with self.subTest(value=value):
                self.assert_failure(json.dumps(value).encode())
        self.assert_failure(policy(ignore_forever=True))

    def test_duplicate_json_keys_fail_closed(self):
        self.assert_failure(b'{"schema_version":1,"schema_version":1,"expected_down":[]}')
        self.assert_failure(policy().replace(b'"owner":', b'"owner":"first","owner":'))

    def test_malformed_nonfinite_and_oversize_inputs_fail_without_echo(self):
        for raw in (b'', b'{', b'\xff', b'{"schema_version":NaN,"expected_down":[]}',
                    b'[' * 2000 + b']' * 2000, b' ' * 65537, 'not bytes'):
            with self.subTest(size=len(raw)):
                self.assertEqual(self.assert_failure(raw)["reason"], "invalid_policy")

    def test_excessive_entry_count_fails_closed(self):
        entry = json.loads(policy())["expected_down"][0]
        value = {"schema_version": 1, "expected_down": [dict(entry, route_port=1000+i) for i in range(65)]}
        self.assert_failure(json.dumps(value).encode())

    def test_invalid_policy_is_visible_even_if_listener_up(self):
        self.assertEqual(self.assert_failure(b'not json', listener_up=True)["reason"], "invalid_policy")

    def test_metadata_is_not_copied_into_status_or_alert(self):
        raw = policy(owner="DO_NOT_ECHO", reason="DO_NOT_ECHO", ticket="DO_NOT_ECHO")
        self.assertNotIn("DO_NOT_ECHO", json.dumps(self.classify(raw)))
        self.assertNotIn("DO_NOT_ECHO", json.dumps(self.classify(raw, backend="127.0.0.1:19095")))

    def test_real_module_fake_checker_keeps_held_visible_and_alerts_actual_failure(self):
        statuses, alerts = [], []
        for port, backend in ((9443, "127.0.0.1:19094"), (8443, "127.0.0.1:19095")):
            result = self.classify(policy(), route_port=port, backend=backend)
            statuses.append(result["status"])
            if result["alert_required"]:
                alerts.append({"route_port": port, "reason": result["reason"]})
        self.assertEqual(statuses, ["HELD", "FAIL"])
        self.assertEqual(alerts, [{"route_port": 8443, "reason": "listener_missing"}])

    def test_pure_classifier_has_no_file_network_or_process_effects(self):
        raw = policy()
        with (mock.patch("builtins.open", side_effect=AssertionError("file effect")),
              mock.patch("socket.socket", side_effect=AssertionError("network effect")),
              mock.patch("subprocess.Popen", side_effect=AssertionError("process effect"))):
            self.assertEqual(self.classify(raw)["status"], "HELD")
            self.assert_failure(None)


if __name__ == "__main__":
    unittest.main()
