"""Offline decisions for #364. All times and ages are integer seconds."""

from dataclasses import dataclass


@dataclass(frozen=True)
class BusyState:
    at: int
    reasons: tuple[str, ...]


def _nonnegative(value):
    return type(value) is int and value >= 0


def busy_state(now, turn_age, live_handoff_age, pro_pending, helpers_active, waiter_armed):
    """Summarize qualified PC observations. None means the inputs are incomplete."""
    if not all(map(_nonnegative, (now, turn_age, live_handoff_age, pro_pending, helpers_active))):
        return None
    if type(waiter_armed) is not bool:
        return None
    signals = (
        ("turn", turn_age < 600),
        ("handoff", live_handoff_age < 3600),
        ("pro", pro_pending > 0),
        ("helper", helpers_active > 0),
        ("waiter", waiter_armed),
    )
    return BusyState(now, tuple(reason for reason, active in signals if active))


def dry_run(now, last_good, polls, disabled, attempts):
    """Evaluate the latest three consecutive poll results and complete attempt history.

    Callers must establish observation provenance, clock continuity and completeness.
    This pure decision neither reserves an attempt nor sends a wake.
    """
    if disabled is not False:
        return "disabled_or_unknown"
    if not _nonnegative(now) or type(last_good) is not BusyState:
        return "unknown_state"
    if not _nonnegative(last_good.at) or not 0 <= now - last_good.at < 600:
        return "stale_state"
    reasons = last_good.reasons
    known = ("turn", "handoff", "pro", "helper", "waiter")
    if type(reasons) is not tuple or reasons != tuple(r for r in known if r in reasons):
        return "unknown_state"
    if not reasons:
        return "idle"
    if type(polls) is not tuple or len(polls) != 3:
        return "unqualified_polls"
    times = []
    for poll in polls:
        if type(poll) is not tuple or len(poll) != 2:
            return "unqualified_polls"
        at, outcome = poll
        if not _nonnegative(at) or outcome != "unreachable":
            return "unqualified_polls"
        times.append(at)
    if times[0] <= last_good.at or times[-1] != now:
        return "unqualified_polls"
    if any(not 120 <= later - earlier <= 180 for earlier, later in zip(times, times[1:], strict=False)):
        return "unqualified_polls"
    if type(attempts) is not tuple or any(not _nonnegative(t) or t > now for t in attempts):
        return "unknown_attempts"
    if any(later <= earlier for earlier, later in zip(attempts, attempts[1:], strict=False)):
        return "unknown_attempts"
    if attempts and now - attempts[-1] < 1200:
        return "cooldown"
    if sum(now - t < 86400 for t in attempts) >= 6:
        return "attempt_limit"
    return "would_wake"
