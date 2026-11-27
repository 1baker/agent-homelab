"""Content-free #364 busy, ordinary-wake and Windows system-awake policies.

Times are integer seconds on a qualified continuous clock. Readers supply a
complete observation or unknown. No timer, network transport or wake sender.
"""

REASONS = ("turn", "handoff", "pro", "helper", "waiter")
FRESH_SECONDS = 300
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 1


def _nonnegative(value):
    return type(value) is int and value >= 0


def busy_state(*, now, seq, turns, live_handoff_age, pro_pending, helpers_active, claude_unclaimed, claude_running):
    """Input turns are (age, disposition); an empty collection means no turns.

    The observer counts only unclaimed handoffs for live recipients. A known
    empty handoff set can be represented by an age of 3600 or greater. The
    Claude inputs cover both sessions and waiters; being armed is irrelevant.
    """
    if (
        not all(map(_nonnegative, (now, seq, live_handoff_age, pro_pending, helpers_active, claude_unclaimed)))
        or type(claude_running) is not bool
    ):
        return None
    if not isinstance(turns, (tuple, list)):
        return None
    recent_work = False
    for turn in turns:
        if (
            not isinstance(turn, (tuple, list))
            or len(turn) != 2
            or not _nonnegative(turn[0])
            or turn[1] not in ("work", "nudge_no_work", "nudge_blocked")
        ):
            return None
        if turn[1] == "work" and turn[0] < 600:
            recent_work = True
    active = (
        recent_work,
        live_handoff_age < 3600,
        pro_pending > 0,
        helpers_active > 0,
        claude_unclaimed > 0 or claude_running,
    )
    reasons = [reason for reason, present in zip(REASONS, active, strict=True) if present]
    return dict(at=now, seq=seq, reasons=reasons, busy=bool(reasons))


def _valid(state):
    if type(state) is not dict or set(state) != {"at", "seq", "busy", "reasons"}:
        return False
    reasons = state["reasons"]
    return (
        _nonnegative(state["at"])
        and _nonnegative(state["seq"])
        and type(reasons) is list
        and all(reason in REASONS for reason in reasons)
        and len(set(reasons)) == len(reasons)
        and state["busy"] is bool(reasons)
    )


def keep_awake(observations, set_thread_execution_state):
    """Consume (now, signal, marker_present) on a single dedicated Windows thread.

    The observation source must deliver fresh reads at least through signal
    expiry, yielding unknown on a read failure. The injected setter has the
    Win32 SetThreadExecutionState ABI. Windows drops the request on thread exit.
    """
    held = False
    try:
        for now, state, marker in observations:
            want = (
                _nonnegative(now)
                and marker is False
                and _valid(state)
                and 0 <= now - state["at"] <= FRESH_SECONDS
                and state["busy"]
            )
            if held != want:
                flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED if want else ES_CONTINUOUS
                if not set_thread_execution_state(flags):
                    raise OSError("execution state change failed")
                held = want
    finally:
        if held and not set_thread_execution_state(ES_CONTINUOUS):
            raise OSError("execution state release failed")


def windows_keep_awake(observations):
    """Run on a dedicated Windows thread with an independently qualified signal reader."""
    import ctypes
    from ctypes import wintypes

    setter = ctypes.WinDLL("kernel32", use_last_error=True).SetThreadExecutionState
    setter.argtypes = (wintypes.DWORD,)
    setter.restype = wintypes.DWORD
    keep_awake(observations, setter)


def dry_run(*, now, last_good, pulled_at, polls, attempts, read_veto):
    """Ordinary wake only. Polls start at the first miss following the last pull.

    The complete attempt history uses the existing conservative rolling day cap.
    A fresh bastion reader returns (disabled, marker_present, lock_present).
    This policy neither reserves nor sends. A future sender must qualify the
    read at the effect boundary; a dry-run result never authorizes a packet.
    """
    if not _nonnegative(now) or not _nonnegative(pulled_at) or not _valid(last_good):
        return "unknown_state"
    if not 0 <= pulled_at - last_good["at"] <= FRESH_SECONDS or not 0 <= now - last_good["at"] <= 7200:
        return "stale_state"
    if not last_good["busy"]:
        return "idle"
    if type(polls) is not tuple or len(polls) < 3:
        return "unqualified_polls"
    times = []
    for poll in polls:
        if type(poll) is not tuple or len(poll) != 2:
            return "unqualified_polls"
        at, outcome = poll
        if not _nonnegative(at) or outcome != "unreachable":
            return "unqualified_polls"
        times.append(at)
    if not 0 < times[0] - pulled_at <= 480 or times[-1] != now:
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
    try:
        veto = read_veto()
    except OSError:
        return "veto_or_unknown"
    if type(veto) is not tuple or len(veto) != 3 or any(flag is not False for flag in veto):
        return "veto_or_unknown"
    return "would_wake"
