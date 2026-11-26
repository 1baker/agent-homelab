#!/usr/bin/env python3
"""Evaluate a public synthetic maintenance trace. No executor or live adapters."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

CT = ZoneInfo("America/Chicago")
VERSION = re.compile(r"(?:codex-cli\s+)?(\d+\.\d+\.\d+)(?:\s+\(Claude Code\))?")
SHA256 = re.compile(r"[a-f0-9]{64}")
REAL_PORTS = (
    "P-0",
    "R1",
    "R2",
    "R3",
    "349/369 notice",
    "C2/ETF observations",
    "tool version observations",
    "BSS role bindings",
    "non-consuming caller audits",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def integer(value):
    return type(value) is int and value >= 0


def version(raw):
    """Accept release versions only; reject channels, prereleases and shell text."""
    if not isinstance(raw, str):
        raise ValueError("version unavailable")
    match = VERSION.fullmatch(raw.strip())
    if not match:
        raise ValueError("not a release version")
    return match.group(1)


def validate_inventory(cfg):
    if not isinstance(cfg, dict) or cfg.get("schema") != "update-agent.inventory.v1":
        raise ValueError("unknown inventory schema")
    for key in ("home", "windows", "distro"):
        if not isinstance(cfg.get(key), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", cfg[key]):
            raise ValueError("invalid SSH alias or distro")
    for key in ("restore_wrapper", "startup_wrapper", "restore_snapshot"):
        if not isinstance(cfg.get(key), str) or not cfg[key].startswith("/") or "\n" in cfg[key]:
            raise ValueError("reviewed absolute wrapper/snapshot paths required")
    for key in ("restore_wrapper_sha256", "startup_wrapper_sha256"):
        if not SHA256.fullmatch(cfg.get(key, "")):
            raise ValueError("reviewed wrapper digests required")
    if not isinstance(cfg.get("hold_paths"), list) or not cfg["hold_paths"]:
        raise ValueError("complete startup-hold inventory required")
    for path in cfg["hold_paths"]:
        if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("hold paths must be relative to the remote home")
    if not isinstance(cfg.get("services"), list) or not cfg["services"]:
        raise ValueError("service inventory required")
    if any(
        not isinstance(u, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@_.-]*\.service", u) for u in cfg["services"]
    ):
        raise ValueError("invalid service unit")
    for name in ("codex", "claude"):
        if not isinstance(cfg.get("tools"), dict) or not isinstance(cfg["tools"].get(name), dict):
            raise ValueError("tool methods and channels required")
        tool = cfg["tools"][name]
        allowed = ("npm",) if name == "codex" else ("npm", "native")
        if tool.get("method") not in allowed or tool.get("channel") not in ("latest", "stable"):
            raise ValueError("unsupported tool method/channel; no implicit migration")
    if not isinstance(cfg.get("tabs"), list) or not cfg["tabs"]:
        raise ValueError("static pane matrix required")
    return cfg


def parse_snapshot(raw):
    if not isinstance(raw, dict) or raw.get("schema") != "update-agent.snapshot.v1":
        raise ValueError("unknown snapshot schema")
    cfg = validate_inventory(raw["inventory"])
    if not integer(raw.get("at")) or not isinstance(raw.get("tmux"), str) or not raw["tmux"]:
        raise ValueError("snapshot time or tmux listing unavailable")
    panes = {}
    for line in raw["tmux"].splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise ValueError("invalid tmux listing")
        session, window, pane, cwd, codex_id, claude_id = fields
        key = (session, window, pane)
        if key in panes or not re.fullmatch(r"@\d+", window) or not re.fullmatch(r"%\d+", pane):
            raise ValueError("duplicate or invalid pane address")
        panes[key] = (cwd, codex_id, claude_id)
    tabs, seen_ids, seen_panes = [], set(), set()
    for tab in cfg["tabs"]:
        key = (tab["session"], tab["window"], tab["pane"])
        if key not in panes or key in seen_panes:
            raise ValueError("static matrix differs from live panes")
        seen_panes.add(key)
        cwd, codex_id, claude_id = panes[key]
        kind = tab["kind"]
        if kind not in ("codex", "claude", "shell") or not cwd.startswith("/"):
            raise ValueError("unknown tab kind or working directory")
        if kind != "shell":
            actual = codex_id if kind == "codex" else claude_id
            if not isinstance(tab.get("id"), str) or str(UUID(tab["id"])) != tab["id"]:
                raise ValueError("invalid thread/session UUID")
            if actual != tab["id"] or actual in seen_ids:
                raise ValueError("missing, changed or duplicate thread/session UUID")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", tab.get("profile", "")):
                raise ValueError("role profile required")
            seen_ids.add(actual)
        elif codex_id or claude_id:
            raise ValueError("agent session incorrectly declared as shell")
        tabs.append({**tab, "cwd": cwd})
    if seen_panes != set(panes):
        raise ValueError("unmapped panes; refuse partial restore")
    return cfg, tabs


def idle_gate(state, now):
    if not isinstance(state, dict) or set(state) != {"at", "seq", "reasons", "busy"}:
        return "unknown_busy_state"
    if not integer(now) or not integer(state["at"]) or not 0 <= now - state["at"] <= 300:
        return "stale_or_future_busy_state"
    reasons = state["reasons"]
    if (
        not integer(state["seq"])
        or type(state["busy"]) is not bool
        or not isinstance(reasons, list)
        or any(reason not in ("turn", "handoff", "pro", "helper", "waiter") for reason in reasons)
        or len(set(reasons)) != len(reasons)
        or bool(reasons) != state["busy"]
    ):
        return "unknown_busy_state"
    return "busy" if state["busy"] else "idle"


class Hold(ValueError):
    """A named evidence requirement failed in a synthetic trace."""


def require(condition, reason):
    if not condition:
        raise Hold(reason)


def identifier(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", value))


def names(values):
    return isinstance(values, list) and all(identifier(value) for value in values) and len(set(values)) == len(values)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def versions(raw, cfg):
    require(set(raw) == {"codex", "claude"}, "observed_versions")
    changes = {}
    for tool in ("codex", "claude"):
        observed = raw[tool]
        before, target = version(observed["installed"]), version(observed["available"])
        require(
            observed["method"] == cfg["tools"][tool]["method"]
            and observed["channel"] == cfg["tools"][tool]["channel"]
            and observed["side_effect_free_observation"] is True,
            "version_provenance",
        )
        if tuple(map(int, target.split("."))) > tuple(map(int, before.split("."))):
            changes[tool] = (before, target)
    return changes


def receipt(value, kind, binding, now):
    require(
        isinstance(value, dict)
        and value.get("schema") == "fixture." + kind + ".v1"
        and value.get("binding") == binding,
        kind + "_binding",
    )
    require(
        integer(value.get("at")) and integer(value.get("expires")) and value["at"] <= now <= value["expires"],
        kind + "_freshness",
    )
    return value


def preconditions(gate, now, binding, notice):
    require(gate["disabled"] is False and gate["sleep_intended"] is False, "disable_or_C2")
    require(idle_gate(gate["busy"], now) == "idle", "C1")
    etf = gate["etf"]
    require(
        etf["complete"] is True
        and etf["hold_present"] is True
        and set(etf["families"]) == {"etf-agent-*", "codex-wake-etf-trading-agent*"}
        and all(state == "inactive" for state in etf["families"].values()),
        "ETF",
    )
    p = receipt(gate.get("presence"), "P0", binding, now)
    require(
        integer(gate["opened"])
        and p["boundary"] == gate["boundary"]
        and gate["opened"] <= p["at"]
        and now - p["at"] <= 5
        and integer(p["last_input_time"])
        and p["last_input_time"] <= p["at"]
        and integer(p["u"]),
        "presence_incomparable",
    )
    require(now - p["last_input_time"] >= 1200 and p["last_input_time"] < notice["at"] - p["u"], "presence_input")


def history_gate(history, notice, now):
    require(history["complete"] is True and history["suspended"] is False, "history_or_suspension")
    seen = set()
    cancellations = []
    for event in history["prior_attempts"]:
        require(
            identifier(event["attempt"])
            and event["attempt"] != notice["binding"]["attempt"]
            and event["attempt"] not in seen
            and integer(event["posted_at"])
            and event["posted_at"] <= notice["at"],
            "attempt_history",
        )
        seen.add(event["attempt"])
        require(notice["at"] - event["posted_at"] >= 4 * 3600, "notice_cooldown")
        if event["update_id"] == notice["update_id"]:
            require(
                event["outcome"] in ("presence_cancelled", "completed", "cleared_fault"), "unresolved_prior_attempt"
            )
            if event["outcome"] == "presence_cancelled":
                end = event["ended_at"]
                require(integer(end) and event["posted_at"] <= end <= notice["at"], "attempt_history")
                cancellations.append(end)
    for end in cancellations:
        if (
            datetime.fromtimestamp(end, CT).date() == datetime.fromtimestamp(now, CT).date()
            and sum(end - 86400 < other <= end for other in cancellations) >= 3
        ):
            raise Hold("presence_daily_limit")


def admission(value, binding, now):
    r = receipt(value, "admission", binding, now)
    require(
        r["survivor_available"] is True
        and r["windows_route"] is True
        and r["exclusive_journal"] is True
        and identifier(r["operator_generation"]),
        "R1_admission",
    )
    require(
        r["complete_ingress"] is True
        and names(r["participants"])
        and r["participants"]
        and {"native-queue", "dispatch", "helpers", "claude-waiter", "browser", "provider"} <= set(r["participants"])
        and names(r["available"])
        and set(r["participants"]) == set(r["available"]) == set(r["owners"]),
        "R2_admission",
    )
    require(
        isinstance(r["role_map"], dict) and r["installed_manifest_schema"] is True and r["role_map_valid"] is True,
        "R3_admission",
    )
    return r


def verify_manifest(raw, binding, epoch, now, tabs):
    r = receipt(raw, "R3", binding, now)
    rows = r["rows"]
    require(
        r["epoch"] == epoch
        and r["complete"] is True
        and isinstance(rows, list)
        and digest(rows) == r["manifest_digest"]
        and len(rows) == len(tabs),
        "R3_manifest",
    )
    by_pane = {t["pane"]: t for t in tabs}
    owners = set()
    callers = set()
    for row in rows:
        pane = row["pane"]
        require(pane in by_pane, "R3_duplicate_pane")
        tab = by_pane.pop(pane)
        require(
            all(row.get(k) == tab.get(k) for k in ("kind", "session", "window", "cwd", "id", "profile")), "R3_placement"
        )
        require(
            identifier(row["owner"])
            and row["owner"] not in owners
            and all(identifier(row[k]) for k in ("settings_generation", "owner_generation"))
            and all(SHA256.fullmatch(row[k]) for k in ("config_sha256", "rollback_sha256"))
            and row["identity_binding"] == "enrolled"
            and set(row["task_flags"]) == {"goal", "stop", "parked", "private", "once"}
            and all(type(flag) is bool for flag in row["task_flags"].values())
            and names(row["holds"])
            and names(row["pending"]),
            "R3_identity",
        )
        owners.add(row["owner"])
        if row["kind"] != "shell":
            require(identifier(row["caller"]) and names(row["expected_tools"]) and row["expected_tools"], "R3_caller")
            require(row["caller"] not in callers, "caller_identity")
            callers.add(row["caller"])
        if row["kind"] == "claude":
            require(
                row["launcher"] == "byobu-session-state+byobu-claude-role"
                and row["role"] == row["profile"]
                and row["role"] in ("claude", "claude-review")
                and SHA256.fullmatch(row["role_manifest_sha256"]),
                "BSS_role_binding",
            )
    require(not by_pane, "R3_missing_row")
    return rows


def readiness(stage, ctx, epoch, now):
    binding, adm = ctx["binding"], ctx["admission"]
    r1 = receipt(stage["R1"], "R1", binding, now)
    require(
        r1["epoch"] == epoch
        and r1["operator_generation"] == adm["operator_generation"]
        and r1["outside_WSL"] is True
        and r1["survives_chief_loss"] is True
        and r1["single_writer"] is True
        and r1["journal_readback"] is True,
        "R1",
    )
    r2 = receipt(stage["R2"], "R2", binding, now)
    require(
        r2["epoch"] == epoch
        and r2["participants"] == adm["participants"]
        and set(r2["drains"]) == set(adm["participants"]),
        "R2_coverage",
    )
    require(
        r1["manifest_digest"] == r2["manifest_digest"] == stage["R3"]["manifest_digest"], "R1_R2_R3_manifest_digest"
    )
    require(r2["queued_work_preserved"] is True and r2["pending_approvals_accounted"] is True, "R2_custody")
    for owner, row in r2["drains"].items():
        require(
            row["epoch"] == epoch
            and identifier(row["owner_generation"])
            and row["owner_generation"] == adm["owners"][owner]
            and row["atomic_fence"] is True
            and row["preserved_order"] is True
            and integer(row["outstanding"])
            and row["outstanding"] == 0
            and row["unknown"] is False,
            "R2_drain",
        )
    rows = verify_manifest(stage["R3"], binding, epoch, now, ctx["tabs"])
    require(
        set(adm["enrolled_callers"]) == {row["owner"] for row in rows if row["kind"] != "shell"}, "R3_caller_coverage"
    )
    for row in rows:
        if row["kind"] != "shell":
            require(adm["enrolled_callers"][row["owner"]] == row["caller"], "R3_caller_binding")
        if row["kind"] == "claude":
            require(adm["role_map"].get(row["role"]) == row["role_manifest_sha256"], "R3_role_map")
    return rows


def verify_restore(value, ctx, epoch, now, observed_versions):
    r = receipt(value, "verification", ctx["binding"], now)
    require(
        r["epoch"] == epoch
        and identifier(r["new_boot"])
        and (r["new_boot"] != ctx["binding"]["old_boot"]) == ctx["shutdown_confirmed"]
        and r["manifest_digest"] == digest(ctx["rows"])
        and r["hold_states"] == dict.fromkeys(ctx["snapshot"]["holds"], True)
        and all(state is True for state in r["hold_states"].values())
        and set(r["hold_generations"]) == set(ctx["startup_generations"])
        and all(identifier(gen) for gen in r["hold_generations"].values())
        and r["service_states"] == ctx["snapshot"]["services"]
        and r["service_enabled"] == ctx["snapshot"]["service_enabled"]
        and r["timer_states"] == ctx["snapshot"]["timers"]
        and r["holds_preserved"] is True
        and r["ETF_never_started"] is True
        and r["installed"] == observed_versions
        and r["running"] == observed_versions,
        "restore_observations",
    )
    expected = {row["owner"]: row for row in ctx["rows"]}
    require(isinstance(r["rows"], list) and len(expected) == len(r["rows"]), "restore_row_count")
    order = []
    require(r["at"] >= ctx["verification_open"], "stale_restore_verification")
    for raw in r["rows"]:
        audit = receipt(raw, "row", ctx["binding"], now)
        owner = audit["owner"]
        require(
            owner in expected
            and audit["epoch"] == epoch
            and audit["new_boot"] == r["new_boot"]
            and audit["manifest_digest"] == r["manifest_digest"],
            "restore_owner_generation",
        )
        row = expected.pop(owner)
        require(
            audit["at"] >= ctx["verification_open"]
            and audit["observed_identity"] == row
            and audit["continuity"] is True,
            "restore_identity",
        )
        if row["kind"] != "shell":
            require(
                audit["caller"] == row["caller"]
                and audit["non_consuming"] is True
                and audit["method"] in ("tool_listing", "ops_status")
                and names(audit["tools"])
                and set(row["expected_tools"]) <= set(audit["tools"]),
                "caller_audit",
            )
        order.append(owner)
    require(not expected and ("chief" not in order or order[-1] == "chief"), "restore_order")


def decision(state, reason, **details):
    return {
        "mode": "offline",
        "eligible": False,
        "live_status": "HOLD",
        "credential_and_browser_readiness": "UNKNOWN",
        "unqualified_ports": list(REAL_PORTS),
        "fixture_state": state,
        "reason": reason,
        **details,
    }


def unwind(reason, changes, current, applied):
    """Describe only generation-matching reversible changes in the fixture."""
    if (
        not isinstance(current, dict)
        or any(not identifier(current.get(key)) for key in changes)
        or ("dispatcher" in changes and type(current.get("other_stop")) is not bool)
    ):
        return decision("HOLD", "current_generations_missing", retain_fences=True)
    release, preserve = [], []
    for key, generation in reversed(list(changes.items())):
        if current[key] != generation or (key == "dispatcher" and current.get("other_stop") is not False):
            preserve.append(key)
        else:
            release.append(key)
    if applied:
        return decision(
            "HOLD",
            reason,
            retain_fences=True,
            rollback_review=applied,
            recovery="reconcile_pinned_rollback_then_restore_and_verify",
            suspend_update=True,
        )
    return decision(
        "UNWIND",
        reason,
        release_matching=release,
        preserve=preserve,
        rollback_review=applied,
        queue_order="original",
        resume_attempt=False,
        suspend_update=reason != "presence_input" or "dispatcher" in changes,
    )


def evaluate(raw, now):
    binding = raw["binding"]
    require(
        set(binding) == {"machine", "distro", "attempt", "old_boot"} and all(identifier(binding[k]) for k in binding),
        "attempt_binding",
    )
    snapshot = raw["inventory_snapshot"]
    cfg, tabs = parse_snapshot(snapshot)
    require(
        set(snapshot["holds"]) == set(cfg["hold_paths"])
        and all(type(v) is bool for v in snapshot["holds"].values())
        and set(snapshot["services"]) == set(cfg["services"])
        and all(v in ("active", "inactive", "failed") for v in snapshot["services"].values()),
        "initial_hold_or_service_state",
    )
    require(
        type(snapshot["dispatcher_stopped"]) is bool
        and names(cfg["timers"])
        and set(snapshot["timers"]) == set(cfg["timers"])
        and cfg["timers"]
        and set(snapshot["service_enabled"]) == set(cfg["services"])
        and all(type(v) is bool for v in snapshot["service_enabled"].values())
        and all(
            set(state) == {"enabled", "active"} and all(type(v) is bool for v in state.values())
            for state in snapshot["timers"].values()
        ),
        "C4_snapshot",
    )
    require(cfg["distro"] == binding["distro"] and cfg["home"] == binding["machine"], "inventory_binding")
    for key in ("restore_wrapper_sha256", "startup_wrapper_sha256"):
        require(raw["inventory_snapshot"].get(key) == cfg[key], "wrapper_hash")
    gpre = raw["pre"]
    start = gpre["now"]
    require(integer(start) and 0 <= start - snapshot["at"] <= 300, "inventory_freshness")
    require(integer(now) and integer(start) and start <= now, "pre_clock")
    detected = receipt(raw.get("version_read"), "versions", binding, start)
    changes = versions(detected["tools"], cfg)
    if not changes:
        return decision("SKIP", "no_update")
    notice = receipt(raw.get("notice"), "notice", binding, start)
    require(
        identifier(notice["headsup_id"])
        and identifier(notice["slack_ts"])
        and notice["digest_confirmed"] is True
        and notice["journaled"] is True
        and notice["update_id"] == digest(changes)
        and start - notice["at"] >= 600,
        "proven_heads_up",
    )
    history_gate(raw["history"], notice, start)
    require(gpre["boundary"] == "G-pre", "G_pre_boundary")
    preconditions(gpre, start, binding, notice)
    adm = admission(raw.get("admission"), binding, start)
    ctx = {"admission": adm, "binding": binding, "tabs": tabs, "snapshot": snapshot, "shutdown_confirmed": False}
    stages = [
        "stop_dispatcher",
        *["update_" + tool for tool in changes],
        "shutdown",
        "start_distro",
        "start_services",
        "restore_byobu",
        "resume_tabs",
        "verify_tabs",
        "resume_dispatcher",
        "report",
    ]
    flags = ["fence", "drain", "manifest", "ready"]
    now_versions = {name: version(row["installed"]) for name, row in detected["tools"].items()}
    owned = {}
    installed = {}
    races = []
    epoch = None
    pending = None
    consumed = set()
    facts = {n: [{"stage": "detected", "installed": v}] for n, v in now_versions.items()}
    recovery = False
    issued_shutdown = False
    last = start
    i = 0
    trace = raw["trace"]
    require(isinstance(trace, list), "journal_trace")
    for sequence, event in enumerate(trace, start=1):
        try:
            event_time = event["at"]
            require(integer(event_time) and last <= event_time <= now, "event_clock")
            previous = last
            last = event_time
            receipt(event, "event", binding, event_time)
            require(
                integer(event.get("sequence"))
                and event["sequence"] == sequence
                and event["prior_sequence"] == sequence - 1
                and event["writer_generation"] == adm["operator_generation"],
                "R1_journal_order_or_writer",
            )
            kind = event["kind"]
            if flags:
                require(kind == flags[0], "admission_is_not_ready")
                if kind == "fence":
                    require(event_time - gpre["presence"]["at"] <= 5, "G_pre_expired")
                    require(
                        event_time
                        <= min(adm["expires"], notice["expires"], detected["expires"], gpre["presence"]["expires"]),
                        "admission_expired",
                    )
                    epoch = event["epoch"]
                    require(identifier(epoch), "fence_epoch")
                    owned["fence"] = epoch
                    expected = {path for path, present in snapshot["holds"].items() if not present}
                    require(
                        event["etf_hold_path"] in snapshot["holds"]
                        and snapshot["holds"][event["etf_hold_path"]] is True,
                        "unknown_fence_writes",
                    )
                    tagged = event["startup_holds"]
                    require(
                        isinstance(tagged, dict)
                        and set(tagged) == expected
                        and all(identifier(g) for g in tagged.values()),
                        "unknown_fence_writes",
                    )
                    ctx["startup_generations"] = {"hold:" + path: generation for path, generation in tagged.items()}
                    owned.update(ctx["startup_generations"])
                else:
                    require(event["epoch"] == epoch, "stale_fence")
                    if kind == "drain":
                        ctx["drain"] = event["drains"]
                    elif kind == "manifest":
                        ctx["manifest"] = event["R3"]
                    else:
                        require(
                            ctx["drain"] == event["R2"]["drains"] and ctx["manifest"] == event["R3"],
                            "under_fence_evidence_changed",
                        )
                        require(
                            all(event[k]["at"] >= ctx["fenced_at"] for k in ("R1", "R2", "R3"))
                            and event["R3"]["at"] >= ctx["drained_at"],
                            "pre_fence_evidence",
                        )
                        ctx["rows"] = readiness(event, ctx, epoch, event_time)
                        ctx["ready_until"] = min(event[k]["expires"] for k in ("R1", "R2", "R3"))
                if kind == "fence":
                    ctx["fenced_at"] = event_time
                elif kind == "drain":
                    ctx["drained_at"] = event_time
                flags.pop(0)
                continue
            require(i < len(stages) and event["epoch"] == epoch, "stage_epoch")
            if kind == "interrupted":
                require(pending is None, "unresolved_intent")
                if i == 0:
                    return unwind("interrupted_before_stop", owned, raw.get("current_generations"), installed)
                require(not recovery, "duplicate_recovery")
                recovery = True
                # Completed actions remain in history. Skip any remaining update or shutdown.
                i = max(i, stages.index("start_distro") if issued_shutdown else stages.index("start_services"))
                continue
            step = stages[i]
            require(event["step"] == step and identifier(event["operation_id"]), "journal_stage")
            if kind == "intent":
                require(pending is None and event["operation_id"] not in consumed, "unresolved_intent")
                if step == "stop_dispatcher" or step.startswith("update_") or step == "shutdown":
                    require(not races, "presence_input")
                    require(event_time <= ctx["ready_until"], "readiness_expired")
                    gate = event["gate"]
                    require(gate["boundary"] == step and gate["opened"] >= previous, "G_k_boundary")
                    preconditions(gate, event_time, binding, notice)
                if step == "shutdown":
                    recheck = receipt(event["recheck"], "C4", binding, event_time)
                    require(
                        recheck["epoch"] == epoch
                        and recheck["at"] >= gate["opened"]
                        and recheck["drains"] == ctx["drain"]
                        and recheck["protected_effect_pending"] is False,
                        "C4_shutdown_recheck",
                    )
                if step == "resume_dispatcher":
                    require(
                        event.get("current_dispatcher") == raw["current_generations"]["dispatcher"]
                        and type(event.get("other_stop")) is bool
                        and event["other_stop"] is raw["current_generations"]["other_stop"],
                        "dispatcher_readback",
                    )
                    release_dispatcher = (
                        "dispatcher" in owned
                        and event["current_dispatcher"] == owned["dispatcher"]
                        and not event["other_stop"]
                        and not snapshot["dispatcher_stopped"]
                    )
                    require(
                        event["disposition"] == ("release_own" if release_dispatcher else "preserve_stop"),
                        "dispatcher_ownership",
                    )
                if step == "report":
                    require(raw["current_generations"]["fence"] == epoch, "fence_release_generation")
                if step == "verify_tabs":
                    ctx["verification_open"] = event_time
                if step == "start_distro" and event.get("needs_wake") is not False:
                    wake = receipt(event.get("restore_wake"), "restore_wake", binding, event_time)
                    require(
                        ctx["shutdown_confirmed"]
                        and wake["epoch"] == epoch
                        and wake["holder"] == adm["operator_generation"]
                        and wake["journal_holder"] == wake["holder"]
                        and wake["journal_epoch"] == epoch
                        and wake["admitted_restore_step"] is True
                        and wake["disabled"] is False
                        and wake["sleep_intended"] is False
                        and wake["veto_read_ok"] is True,
                        "restore_wake_veto",
                    )
                intent_time = event_time
                pending = event["operation_id"]
                consumed.add(pending)
                if step == "shutdown":
                    issued_shutdown = True
                continue
            require(kind in ("ack", "reconcile") and pending == event["operation_id"], "journal_ack")
            if event["outcome"] == "UNKNOWN":
                require(kind == "ack", "unresolved_reconciliation")
                # Keep the intent outstanding. Only authoritative readback can resolve it.
                ctx["ambiguous"] = True
                continue
            require(not ctx.get("ambiguous") or kind == "reconcile", "durable_reconciliation_required")
            if kind == "reconcile":
                require(event["durable_readback"] is True, "reconciliation_missing")
            require(event["observed"] is True, "observation_missing")
            if step in ("stop_dispatcher", "shutdown") or step.startswith("update_"):
                post = receipt(event["post_presence"], "P0", binding, event_time)
                gate_sample = gate["presence"]["at"]
                require(
                    integer(event.get("effect_started_at"))
                    and intent_time
                    <= event["effect_started_at"]
                    <= min(gate_sample + 5, ctx["ready_until"], gate["presence"]["expires"])
                    and post["boundary"] == step
                    and post["at"] >= event["effect_started_at"]
                    and integer(post["last_input_time"])
                    and post["last_input_time"] <= post["at"],
                    "post_presence",
                )
                if gate_sample <= post["last_input_time"] <= post["at"]:
                    races.append(step)
            if step.startswith("update_"):
                tool = step.removeprefix("update_")
                require(
                    event.get("tool") == tool
                    and event.get("before") == changes[tool][0]
                    and event.get("target") == changes[tool][1],
                    "tool_observation_binding",
                )
                now_versions[tool] = version(event["observed_version"])
                if now_versions[tool] != changes[tool][0]:
                    installed[tool] = now_versions[tool]
            if step.startswith("update_") and event["outcome"] == "rolled_back":
                require(now_versions[tool] == changes[tool][0], "rollback_observed_version")
                installed.pop(tool, None)
                facts[tool].append({"stage": "rolled_back", "installed": now_versions[tool]})
                recovery = True
                pending = None
                ctx["ambiguous"] = False
                i = stages.index("start_services")
                continue
            if event["outcome"] == "failed":
                pending = None
                if step.startswith("update_") or step == "shutdown":
                    # A definite failed shutdown did not change boot. Restore proven prior state.
                    recovery = True
                    issued_shutdown = False
                    i = stages.index("start_services")
                    ctx["ambiguous"] = False
                    continue
                return decision(
                    "HOLD",
                    "confirmed_failure:" + step,
                    retain_fences=True,
                    recovery="qualified_restore_required",
                    observed_versions=now_versions,
                )
            require(event["outcome"] == "done", "unresolved_outcome")
            if step in ("stop_dispatcher", "start_services", "resume_tabs", "verify_tabs"):
                stage_name = {
                    "stop_dispatcher": "stopped",
                    "start_services": "restarted",
                    "resume_tabs": "restored",
                    "verify_tabs": "verified",
                }[step]
                for entries in facts.values():
                    entries.append({"stage": stage_name})
            if step.startswith("update_"):
                facts[tool].append({"stage": "updated", "installed": now_versions[tool]})
            if step == "stop_dispatcher":
                if snapshot["dispatcher_stopped"]:
                    require(event["written_generation"] is None, "preexisting_dispatcher_stop")
                else:
                    require(identifier(event["written_generation"]), "dispatcher_generation")
                    owned["dispatcher"] = event["written_generation"]
            if step.startswith("update_"):
                require(now_versions[tool] == changes[tool][1], "unexpected_observed_version")
            if step == "shutdown":
                ctx["shutdown_confirmed"] = True
            if step == "resume_tabs":
                order = event["restored_owners"]
                require(
                    names(order)
                    and set(order) == {row["owner"] for row in ctx["rows"]}
                    and ("chief" not in order or order[-1] == "chief")
                    and event["manifest_digest"] == digest(ctx["rows"])
                    and event["wrapper_only"] is True,
                    "restore_execution_order",
                )
            if step == "verify_tabs":
                verify_restore(event["verification"], ctx, epoch, event_time, now_versions)
                ctx["verified_hold_generations"] = event["verification"]["hold_generations"]
            if step == "resume_dispatcher":
                expected_release = owned["dispatcher"] if release_dispatcher else None
                require(event["released_generation"] == expected_release, "resume_readback")
            if step == "report":
                hold_writes = ctx["startup_generations"]
                current = raw["current_generations"]
                require(all(identifier(current.get(key)) for key in hold_writes), "hold_generation_missing")
                releases = {key: gen for key, gen in hold_writes.items() if current[key] == gen}
                require(
                    all(ctx["verified_hold_generations"][key] == gen for key, gen in releases.items()),
                    "retired_hold_generation",
                )
                require(event["released_holds"] == releases, "hold_release_readback")
                post = {key: None if key in releases else current[key] for key in hold_writes}
                states = {
                    path: present or post["hold:" + path] is not None for path, present in snapshot["holds"].items()
                }
                require(
                    event["post_hold_generations"] == post
                    and event["post_hold_states"] == states
                    and all(type(state) is bool for state in event["post_hold_states"].values()),
                    "post_release_hold_readback",
                )
                require(
                    event["released_fence"] == epoch and raw["current_generations"]["fence"] == epoch,
                    "fence_release_readback",
                )
            ctx["ambiguous"] = False
            pending = None
            i += 1
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, Hold) else "incomplete_journal_or_gate"
            if pending is not None or issued_shutdown:
                return decision(
                    "UNKNOWN",
                    reason,
                    retain_fences=True,
                    unresolved=pending,
                    recovery="reconcile_then_restore" if issued_shutdown else "durable_readback",
                    last_confirmed_versions=now_versions,
                )
            if epoch:
                if not isinstance(exc, Hold) or reason in {
                    "unknown_fence_writes",
                    "R1_journal_order_or_writer",
                    "stage_epoch",
                    "event_clock",
                    "event_binding",
                    "journal_stage",
                    "journal_ack",
                    "stale_fence",
                    "duplicate_recovery",
                    "unresolved_intent",
                }:
                    return decision("UNKNOWN", reason, retain_fences=True, recovery="durable_readback")
                return unwind(reason, owned, raw.get("current_generations"), installed)
            return decision("HOLD", reason, effects=0, suspend_update=reason != "presence_input")
    if pending is not None:
        return decision(
            "UNKNOWN",
            "intent_without_definite_outcome",
            unresolved=pending,
            retain_fences=True,
            recovery="durable_readback",
            last_confirmed_versions=now_versions,
        )
    if flags:
        if epoch is None and (now > adm["expires"] or now - gpre["presence"]["at"] > 5):
            return decision("HOLD", "G_pre_expired", effects=0, suspend_update=True)
        return decision("ADMISSION" if epoch is None else "HOLD", "await_" + flags[0], retain_fences=bool(epoch))
    if i == len(stages):
        return decision(
            "VERIFIED",
            "fixture_only",
            lastpass_unlock="human_only_after_reboot" if issued_shutdown else "not_assessed",
            observed_versions=now_versions,
            tool_stages=facts,
            presence_races=races,
        )
    if not issued_shutdown and not recovery and now > ctx["ready_until"]:
        return unwind("readiness_expired", owned, raw.get("current_generations"), installed)
    return decision(
        "RECOVERY" if recovery else ("READY" if not i else "IN_PROGRESS"),
        "await_bound_stage",
        next_stage=stages[i],
        retain_fences=True,
        observed_versions=now_versions,
        tool_stages=facts,
        presence_races=races,
    )


def build_plan(raw, now, disabled=False):
    if disabled is not False or not isinstance(raw, dict) or raw.get("schema") != "public-fixture.375.v6":
        return decision("HOLD", "disabled_or_unqualified_evidence", effects=0)
    try:
        return evaluate(raw, now)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
        reason = str(exc) if isinstance(exc, Hold) else "invalid_fixture"
        return decision("HOLD", reason, effects=0, suspend_update=reason != "presence_input")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path, help="public offline fixture")
    parser.add_argument("--now", required=True, type=int, help="fixture clock, epoch seconds")
    parser.add_argument("--dry-run", action="store_true", help="only supported operation")
    args = parser.parse_args(argv)
    try:
        result = build_plan(json.loads(args.snapshot.read_bytes()), args.now)
    except (ValueError, OSError):
        result = decision("HOLD", "unreadable_fixture")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
