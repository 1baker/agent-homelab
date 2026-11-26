# Expected-down health policy

The health-hold classifier consumes supplied observations; it does not discover
services, read a host's configuration, probe a listener, change routes or send
alerts. It is not yet wired into an installed Bastion health checker.

`agent_homelab.health_holds.classify_backend(policy_bytes, route_port=...,
backend=..., listener_up=..., now=...)` accepts a JSON byte string (or `None` for
no policy), an exact TCP port and canonical `127.0.0.1:PORT` backend, a boolean
listener observation and an aware UTC `datetime` from the caller.

A reviewed policy uses this format, with only synthetic values shown:

```json
{
  "schema_version": 1,
  "expected_down": [{
    "route_port": 9443,
    "backend": "127.0.0.1:19094",
    "owner": "example-owner",
    "reason": "Planned maintenance",
    "ticket": "https://tracker.example.invalid/issues/1",
    "starts_at": "2026-01-01T00:00:00Z",
    "expires_at": "2026-01-15T00:00:00Z"
  }]
}
```

In plain English: an operator records which exact route is deliberately down,
who owns it, why, its tracking ticket and when that exception ends. This example
is expired and does not authorize a real host change or hide a current outage.

Every field is required; extra fields, duplicate keys/route-backend pairs,
non-integer ports, noncanonical backends and malformed timestamps are rejected.
Owner/reason/ticket are bounded, nonempty printable ASCII strings, not executed
commands or automatically verified ownership evidence. Timestamps use whole
seconds and a literal `Z`. Lifetime must be positive and at most 14 days. Policy
size is at most 65,536 bytes and at most 64 entries. Keep production policy in
its owner's protected, reviewed configuration; never derive intent from another
machine's STOP file or include private configuration in this repository.

Results contain only `status`, a fixed `reason` code and `alert_required`:

| Observation | Result | Alert required |
| --- | --- | --- |
| Valid input, listener up | PASS / listener_up | false |
| Listener down, exact active record | HELD / expected_down | false |
| Listener down, no exact active record | FAIL / listener_missing | true |
| Invalid policy, including when listener is up | FAIL / invalid_policy | true |
| Invalid observation or clock | FAIL / invalid_observation | true |

The start is inclusive and expiry exclusive. Future or expired records cannot
suppress a failure. An invalid policy fails closed as a whole instead of partly
applying an ambiguous exception. No metadata or parse-error text is reflected in
health logs. Missing policy is equivalent to no exceptions, never permission to
ignore an outage.

## Adapter and operational acceptance still required

The actual health checker must keep its existing observation method and pass the
correct route/backend pair, a fresh boolean listener result and its trusted UTC
clock. It must keep HELD visible, preserve all other checks and route every FAIL
to the separately qualified alert destination. `alert_required` is an obligation
for that adapter, not evidence that a person received a notification. Tests use
a fake alert receiver only.

The installed checker is not tracked in this repository's current baseline.
Its exact canonical Source and integration call site must be bound before
claiming this change repairs it. No real expected-down entry is supplied here:
its actual producer owner must confirm held intent first, and any deployment or
alert Send keeps its separate human authorization. A record is an operator
attestation, not a proof that a listener is safe to restore or a service retired.

## Validation and rollback

The tests call the real module with public fake policy, listener observations,
clock and alert receiver. They cover missing/expired/mismatched records, expiry
boundaries, maximum lifetime, malformed input and no file/network/process
calls. There is no live health check, transport or producer acceptance test.

A future authorized adapter deployment must preserve its exact preimage and
policy separately. Reverting Source or removing an expected-down record makes
the corresponding missing listener FAIL again; it does not stop, restore,
retire or expose any service. No installation or rollback executor is included.
