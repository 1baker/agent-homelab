#!/usr/bin/env python3
"""Bastion-side read-only update planner. There is deliberately no apply command."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from uuid import UUID
from zoneinfo import ZoneInfo

CT = ZoneInfo("America/Chicago")
STEPS = (
    "stop_dispatcher", "update", "shutdown", "start_distro", "start_services",
    "restore_byobu", "resume_tabs", "verify_tabs", "resume_dispatcher", "report",
)
VERSION = re.compile(r"(?:codex-cli\s+)?(\d+\.\d+\.\d+)(?:\s+\(Claude Code\))?")
SHA256 = re.compile(r"[a-f0-9]{64}")

# Fixed read-only program, sent on stdin to Python over SSH. Inventory is JSON
# data, never Python or a shell command. No package installs, tmux writes, queue
# consumption, process signals, service actions, or file writes occur here.
COLLECTOR = r'''
import hashlib, json, pathlib, subprocess, sys, time, urllib.request

cfg = json.loads(sys.argv[1])
def read_command(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        if p.returncode == 0 or (argv[:3] == ['systemctl', '--user', 'is-active'] and p.returncode == 3):
            return p.stdout.rstrip('\n')
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None

def present(relative):
    try:
        (pathlib.Path.home() / relative).lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return None

def digest(path):
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError:
        return None

def available(package, channel):
    # Direct public metadata GET avoids npm's cache/log writes and npmrc auth.
    url = 'https://registry.npmjs.org/-/package/' + package + '/dist-tags'
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return json.dumps(json.loads(response.read(1048576))[channel])
    except (OSError, ValueError, KeyError):
        return None

try:
    busy = json.loads((pathlib.Path.home() / '.local/state/agent-wake/state.json').read_text())
except (OSError, ValueError):
    busy = None

versions = {}
for name, package in (('codex', '@openai/codex'), ('claude', '@anthropic-ai/claude-code')):
    channel = cfg['tools'][name]['channel']
    versions[name] = {
        'installed': read_command([name, '--version']),
        'available': available(package, channel),
    }
fmt = '\t'.join(('#{session_name}', '#{window_id}', '#{pane_id}', '#{pane_current_path}',
                 '#{@byobu-codex-thread-id}', '#{@byobu-claude-session-id}'))
print(json.dumps({
    'schema': 'update-agent.snapshot.v1', 'at': int(time.time()), 'inventory': cfg,
    'versions': versions, 'busy': busy,
    'human_present': present('.config/update-agent/HUMAN_PRESENT'),
    'tmux': read_command(['tmux', 'list-panes', '-a', '-F', fmt]),
    'holds': {p: present(p) for p in cfg['hold_paths']},
    'services': {u: read_command(['systemctl', '--user', 'is-active', u]) for u in cfg['services']},
    'restore_wrapper_sha256': digest(cfg['restore_wrapper']),
    'startup_wrapper_sha256': digest(cfg['startup_wrapper']),
}))
'''


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


def idle_gate(state, now, human_present=False):
    """Candidate #364 JSON = dataclasses.asdict(BusyState(at, reasons))."""
    if human_present is not False:
        return "human_present_or_unknown"
    if not isinstance(state, dict) or set(state) != {"at", "reasons"}:
        return "missing_or_unknown_busy_state"
    if not integer(now) or not integer(state["at"]) or not 0 <= now - state["at"] < 600:
        return "stale_or_future_busy_state"
    reasons = state["reasons"]
    known = ("turn", "handoff", "pro", "helper", "waiter")
    if not isinstance(reasons, list) or reasons != [r for r in known if r in reasons]:
        return "unknown_busy_reasons"
    return "busy:" + ",".join(reasons) if reasons else "idle"


def window_gate(now):
    local = datetime.fromtimestamp(now, CT)
    return "in_window" if 1 <= local.hour < 5 else "outside_01_05_CT"


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
    if any(not isinstance(u, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@_.-]*\.service", u)
           for u in cfg["services"]):
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


def collect(cfg, runner=subprocess.run):
    """Only SSH entrypoint; strict existing host trust, bounded read-only program."""
    validate_inventory(cfg)
    command = "python3 - " + shlex.quote(json.dumps(cfg))
    result = runner(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
         "--", cfg["home"], command],
        input=COLLECTOR, capture_output=True, text=True, timeout=180, check=True,
    )
    return json.loads(result.stdout)


@contextmanager
def journal_lock(path):
    """Only offline journal APIs write; CLI dry runs never call them."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def atomic_write(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".journal-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Journal:
    """Durable once-per-night reservation and append-only step outcomes.

    Future operational integration must reserve *before* stopping the dispatcher,
    begin each step before its effect and finish it only with verified evidence.
    Any reopened incomplete journal offers verification only, even if the last
    recorded step preceded the update. UNKNOWN effects are never replayed.
    """

    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        value = json.loads(self.path.read_text())
        if value.get("schema") != "update-agent.journal.v1" or not isinstance(value.get("events"), list):
            raise ValueError("invalid journal; manual reconciliation required")
        if value.get("night") != self.path.stem or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.path.stem):
            raise ValueError("journal night mismatch")
        if hashlib.sha256(canonical(value["snapshot"])).hexdigest() != value.get("snapshot_sha256"):
            raise ValueError("journal snapshot digest mismatch")
        parse_snapshot(value["snapshot"])
        events = value["events"]
        for event in events:
            if event.get("step") not in STEPS or event.get("status") not in ("started", "done", "UNKNOWN"):
                raise ValueError("invalid journal event")
        updates = [e for e in events if e == {"step": "update", "status": "started"}]
        if len(updates) > 1:
            raise ValueError("duplicate update reservation")
        return value

    def reserve(self, snapshot, now):
        parse_snapshot(snapshot)
        night = datetime.fromtimestamp(now, CT).date().isoformat()
        if self.path.name != night + ".json":
            raise ValueError("journal filename must match the CT night")
        with journal_lock(self.path):
            if os.path.lexists(self.path):
                raise ValueError("night already reserved; resume at verify")
            atomic_write(self.path, {
                "schema": "update-agent.journal.v1", "night": night, "snapshot": snapshot,
                "snapshot_sha256": hashlib.sha256(canonical(snapshot)).hexdigest(), "events": [],
            })

    def record(self, step, status):
        if step not in STEPS or status not in ("started", "done", "UNKNOWN"):
            raise ValueError("invalid step outcome")
        with journal_lock(self.path):
            value = self.read()
            events = value["events"]
            if events and events[-1] == {"step": "report", "status": "done"}:
                raise ValueError("run already complete")
            prior = [e for e in events if e["step"] == step]
            if step == "update" and status == "started" and prior:
                raise ValueError("update already attempted; verify instead")
            if status == "started" and prior and step != "verify_tabs":
                raise ValueError("step already attempted; verify instead")
            if status == "started" and step == "verify_tabs":
                if events and events[-1]["status"] == "started":
                    events.append({"step": events[-1]["step"], "status": "UNKNOWN"})
            elif status == "started":
                index = STEPS.index(step)
                if index == 0:
                    if events:
                        raise ValueError("run already started; verify instead")
                elif not events or events[-1] != {"step": STEPS[index - 1], "status": "done"}:
                    raise ValueError("previous step has not completed")
            if status != "started" and (not events or events[-1] != {"step": step, "status": "started"}):
                raise ValueError("no matching step reservation")
            if step == "resume_dispatcher" and status == "started":
                if not events or events[-1] != {"step": "verify_tabs", "status": "done"}:
                    raise ValueError("all tabs must verify before dispatcher resumes")
            events.append({"step": step, "status": status})
            atomic_write(self.path, value)

    def resume_steps(self):
        events = self.read()["events"]
        if events and events[-1] == {"step": "report", "status": "done"}:
            return ()
        if any(e["step"] == "resume_dispatcher" for e in events):
            return ("verify_tabs", "report")
        return STEPS[7:]


def verify_tabs(expected, observed):
    """Consume qualified per-tab receipts; never call/claim a live inbox here."""
    results = []
    if not isinstance(observed, list):
        observed = []
    for tab in expected:
        if tab["kind"] == "shell":
            continue
        matches = [r for r in observed if isinstance(r, dict)
                   and all(r.get(k) == tab[k] for k in ("session", "window", "pane"))]
        passed = len(matches) == 1
        if passed:
            receipt = matches[0]
            passed = (receipt.get("id") == tab["id"] and receipt.get("profile") == tab["profile"]
                      and receipt.get("last_message_continuity") is True)
            if tab["kind"] == "codex":
                tools = receipt.get("tools")
                passed = passed and isinstance(tools, list) and "codex-ops.inbox_read" in tools
        results.append({"id": tab["id"], "result": "PASS" if passed else "UNKNOWN"})
    return results


def build_plan(raw, now, disabled=False, journal=None):
    if journal is not None:
        raw = journal.read()["snapshot"]
    cfg, tabs = parse_snapshot(raw)
    blockers = []
    if disabled is not False:
        blockers.append("DISABLE_present_or_unknown")
    if journal is None:
        for gate in (window_gate(now), idle_gate(raw.get("busy"), now, raw.get("human_present"))):
            if gate not in ("in_window", "idle"):
                blockers.append(gate)
        if not 0 <= now - raw["at"] < 600:
            blockers.append("stale_snapshot")
    for key in ("restore_wrapper_sha256", "startup_wrapper_sha256"):
        if raw.get(key) != cfg[key]:
            blockers.append(key + "_mismatch")
    holds = raw.get("holds", {})
    if set(holds) != set(cfg["hold_paths"]) or any(type(v) is not bool for v in holds.values()):
        blockers.append("startup_holds_unknown")
    if set(raw.get("services", {})) != set(cfg["services"]):
        blockers.append("service_snapshot_incomplete")
    elif any(value not in ("active", "inactive", "failed") for value in raw["services"].values()):
        blockers.append("service_state_unknown")
    updates = []
    for name, package in (("codex", "@openai/codex"), ("claude", "@anthropic-ai/claude-code")):
        try:
            values = raw["versions"][name]
            before = version(values["installed"])
            target = version(json.loads(values["available"]))
        except (ValueError, KeyError, TypeError):
            blockers.append(name + "_version_unknown")
            continue
        method = cfg["tools"][name]["method"]
        command = ["npm", "install", "--global", package + "@" + target]
        rollback = ["npm", "install", "--global", package + "@" + before]
        if method == "native":
            command, rollback = ["claude", "install", target], ["claude", "install", before]
        newer = tuple(map(int, target.split("."))) > tuple(map(int, before.split(".")))
        updates.append({"tool": name, "channel": cfg["tools"][name]["channel"], "before": before,
                        "target": target, "needed": newer,
                        "method": method, "command": command, "rollback": rollback,
                        "verification": "exact installed version; retain previous binary/package before update"})
    plan = {
        "mode": "DRY-RUN", "eligible": not blockers, "blockers": blockers,
        "night_CT": datetime.fromtimestamp(now, CT).date().isoformat(),
        "snapshot_at": raw["at"], "snapshot_sha256": hashlib.sha256(canonical(raw)).hexdigest(),
        "tabs": tabs, "holds_preserved": holds, "services_before": raw.get("services"), "updates": updates,
        "steps": [], "report_delivery": "local report / #369 adapter pending; Derpy and Slack not sent",
    }
    details = {
        "stop_dispatcher": "STOP dispatcher; settle inflight work; interrupted outcomes UNKNOWN, never retry",
        "update": [u for u in updates if u["needed"]],
        "shutdown": ["ssh", cfg["windows"], "wsl", "--shutdown"],
        "start_distro": ["ssh", cfg["windows"], "wsl", "--distribution", cfg["distro"], "--exec", "/bin/true"],
        "start_services": {"reviewed_wrapper": cfg["startup_wrapper"], "respect_all_holds": True,
                           "services_to_verify": cfg["services"]},
        "restore_byobu": {"reviewed_wrapper": cfg["restore_wrapper"], "sha256": cfg["restore_wrapper_sha256"],
                          "snapshot": cfg["restore_snapshot"], "profiles": [t.get("profile") for t in tabs],
                          "launch_owner": "wrapper only; no second pane launch/resume"},
        "resume_tabs": [{"pane": t["pane"], "profile": t["profile"], "cwd": t["cwd"],
                         "command": ["codex", "--profile", t["profile"], "resume", t["id"]]
                         if t["kind"] == "codex" else ["claude", "--resume", t["id"]],
                         "via": "reviewed restore wrapper, exactly once"} for t in tabs if t["kind"] != "shell"],
        "verify_tabs": "verify installed AND running versions, completed WSL restart, unchanged holds, "
                       "same UUID/profile, codex-ops.inbox_read catalog and last-message continuity; "
                       "missing receipt is UNKNOWN; keep dispatcher STOPped",
        "resume_dispatcher": "only after ALL per-tab and version checks PASS; retain every startup hold",
        "report": "versions before/after and each tab PASS/UNKNOWN; preserve interrupted outcomes; no Send",
    }
    selected = journal.resume_steps() if journal else STEPS
    plan["steps"] = [{"step": step, "detail": details[step]} for step in selected]
    if journal:
        plan["recovery"] = "verify only; never repeat stop/update/shutdown/restore/resume effects"
        outcomes = {}
        for event in journal.read()["events"]:
            outcomes[event["step"]] = event["status"]
        plan["unknown_outcomes"] = [step for step, outcome in outcomes.items() if outcome != "done"]
        if outcomes.get("resume_dispatcher") in ("started", "UNKNOWN"):
            blockers.append("dispatcher_outcome_requires_reconciliation")
            plan["eligible"] = False
        plan["verify_expected_versions"] = {
            u["tool"]: u["target"] if "update" in outcomes and u["needed"] else u["before"] for u in updates
        }
    elif updates and not any(u["needed"] for u in updates):
        plan["steps"] = [{"step": "report", "detail": "No newer release on configured channels; skip restart"}]
    return plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inventory", type=Path, help="private reviewed inventory; collect over read-only ssh home")
    source.add_argument("--snapshot", type=Path, help="offline snapshot fixture or privately retained capture")
    source.add_argument("--journal", type=Path, help="resume an existing journal at verify; no effects are replayed")
    parser.add_argument("--dry-run", action="store_true", help="explicit spelling of the only supported mode")
    parser.add_argument("--disable-file", type=Path, default=Path.home() / ".config/update-agent/DISABLE")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/update-agent")
    parser.add_argument("--now", type=int, help="epoch seconds for deterministic offline checks")
    args = parser.parse_args(argv)
    now = int(time.time()) if args.now is None else args.now
    try:
        # lstat preserves symlinks as a disable signal; errors fail closed.
        try:
            args.disable_file.lstat()
            disabled = True
        except FileNotFoundError:
            disabled = False
        if disabled:
            print(json.dumps({"mode": "DRY-RUN", "eligible": False, "blockers": ["DISABLE_present_or_unknown"]}))
            return 0
        journal = Journal(args.journal) if args.journal else None
        if journal is None and args.state_dir.exists():
            candidates = [Journal(p) for p in sorted(args.state_dir.glob("*.json"))]
            pending = [j for j in candidates if j.resume_steps()]
            if len(pending) > 1:
                raise ValueError("multiple unfinished journals; reconcile without replay")
            if pending:
                journal = pending[0]
            else:
                night = datetime.fromtimestamp(now, CT).date().isoformat()
                if (args.state_dir / (night + ".json")).exists():
                    print(json.dumps({"mode": "DRY-RUN", "eligible": False, "blockers": ["night_already_reserved"]}))
                    return 0
        if journal:
            raw = journal.read()["snapshot"]
        elif args.snapshot:
            raw = json.loads(args.snapshot.read_text())
        else:
            raw = collect(json.loads(args.inventory.read_text()))
        print(json.dumps(build_plan(raw, now, disabled, journal), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # No captured stdout/stderr or arbitrary remote data in errors.
        print(json.dumps({"mode": "DRY-RUN", "eligible": False, "blockers": [type(error).__name__]}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
