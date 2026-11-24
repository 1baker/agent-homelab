"""Offline acceptance tests. No SSH, services, binaries or real journals are used."""

import copy
import importlib.util
import io
import json
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

MODULE = Path(__file__).parents[1] / "update-agent" / "update_agent.py"
SPEC = importlib.util.spec_from_file_location("update_agent", MODULE)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)
FIXTURES = MODULE.parent / "fixtures"
SNAPSHOT = json.loads((FIXTURES / "snapshot.json").read_text())
NOW = SNAPSHOT["at"]


class IdleGateTests(unittest.TestCase):
    def test_all_five_busy_signals_refuse_idle(self):
        busy = json.loads((FIXTURES / "busy-state.json").read_text())
        self.assertEqual(agent.idle_gate(busy, NOW), "busy:turn,handoff,pro,helper,waiter")
        for signal in ("turn", "handoff", "pro", "helper", "waiter"):
            with self.subTest(signal=signal):
                self.assertEqual(agent.idle_gate({"at": NOW, "reasons": [signal]}, NOW), "busy:" + signal)

    def test_only_fresh_complete_empty_signal_is_idle(self):
        self.assertEqual(agent.idle_gate({"at": NOW, "reasons": []}, NOW), "idle")
        self.assertEqual(agent.idle_gate({"at": NOW - 599, "reasons": []}, NOW), "idle")
        for state in (None, {}, [], {"at": NOW}, {"at": NOW, "reasons": [], "extra": False},
                      {"at": NOW, "reasons": ["unknown"]}, {"at": NOW, "reasons": ""},
                      {"at": NOW, "reasons": ["pro", "turn"]}, {"at": NOW, "reasons": ["pro", "pro"]},
                      {"at": NOW - 600, "reasons": []}, {"at": NOW + 1, "reasons": []},
                      {"at": True, "reasons": []}):
            with self.subTest(state=state):
                self.assertNotEqual(agent.idle_gate(state, NOW), "idle")

    def test_human_override_and_unknown_refuse_idle(self):
        for override in (True, None, 0, "false"):
            self.assertEqual(agent.idle_gate(SNAPSHOT["busy"], NOW, override), "human_present_or_unknown")

    def test_CT_window_and_fall_back_repeated_hour(self):
        from datetime import datetime

        for iso, expected in (("2026-11-24T06:59:59+00:00", "outside_01_05_CT"),
                              ("2026-11-24T07:00:00+00:00", "in_window"),
                              ("2026-11-24T10:59:59+00:00", "in_window"),
                              ("2026-11-24T11:00:00+00:00", "outside_01_05_CT"),
                              ("2026-11-01T06:30:00+00:00", "in_window"),
                              ("2026-11-01T07:30:00+00:00", "in_window")):
            self.assertEqual(agent.window_gate(int(datetime.fromisoformat(iso).timestamp())), expected)


class SnapshotTests(unittest.TestCase):
    def test_matrix_preserves_UUIDs_profiles_and_paths(self):
        _, tabs = agent.parse_snapshot(SNAPSHOT)
        self.assertEqual([t["id"] for t in tabs[:2]],
                         ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"])
        self.assertEqual(tabs[0]["profile"], "ops")
        self.assertEqual(tabs[1]["cwd"], "/srv/example/project with spaces")
        self.assertTrue(SNAPSHOT["holds"][".config/example/ETF-HOLD"])

    def test_reject_missing_changed_duplicate_and_unmapped_panes(self):
        for operation in ("missing", "changed", "duplicate", "unmapped", "wrong_kind", "malformed"):
            raw = copy.deepcopy(SNAPSHOT)
            if operation == "missing":
                raw["tmux"] = "\n".join(raw["tmux"].splitlines()[:-1])
            elif operation == "changed":
                raw["tmux"] = raw["tmux"].replace("000000000001", "000000000099")
            elif operation == "duplicate":
                raw["inventory"]["tabs"].append(raw["inventory"]["tabs"][0])
            elif operation == "unmapped":
                raw["inventory"]["tabs"].pop()
            elif operation == "wrong_kind":
                raw["inventory"]["tabs"][0]["kind"] = "shell"
            else:
                raw["tmux"] = "example\t@1"
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                agent.parse_snapshot(raw)

    def test_unknown_inventory_and_unsafe_alias_refused(self):
        for key, value in (("schema", "v0"), ("home", "-oProxyCommand=bad"), ("home", "home;bad"),
                           ("hold_paths", ["../other"]), ("services", ["--help"]),
                           ("restore_wrapper_sha256", "unknown")):
            cfg = copy.deepcopy(SNAPSHOT["inventory"])
            cfg[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                agent.validate_inventory(cfg)

    def test_real_collector_uses_readonly_SSH_and_preserves_trailing_tabs(self):
        # Execute the actual remote collector against temporary synthetic files
        # and a process fake. The trailing empty tmux fields must survive.
        cfg = copy.deepcopy(SNAPSHOT["inventory"])
        commands = []

        def process(argv, **kwargs):
            commands.append(argv)
            if argv[0] == "tmux":
                return SimpleNamespace(returncode=0, stdout=SNAPSHOT["tmux"] + "\n")
            if argv[0] == "systemctl":
                return SimpleNamespace(returncode=3, stdout="inactive\n")
            return SimpleNamespace(returncode=0, stdout="1.0.0\n")

        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch("pathlib.Path.home", return_value=Path(directory)),
                patch("subprocess.run", side_effect=process),
                patch("urllib.request.urlopen",
                      side_effect=lambda *a, **k: io.BytesIO(b'{"latest":"9.0.0","stable":"8.0.0"}')),
                patch("sys.argv", ["-", json.dumps(cfg)]),
                redirect_stdout(output),
            ):
                exec(compile(agent.COLLECTOR, "<collector>", "exec"), {})  # noqa: S102 - trusted source constant
        raw = json.loads(output.getvalue())
        self.assertEqual(raw["tmux"], SNAPSHOT["tmux"])
        self.assertEqual(raw["services"]["example-agent.service"], "inactive")
        self.assertIsNone(raw["busy"])
        self.assertEqual(agent.idle_gate(raw["busy"], NOW), "missing_or_unknown_busy_state")
        self.assertTrue(all(c[0] in ("codex", "claude", "tmux", "systemctl") for c in commands))
        self.assertTrue(all(c[1] == "--version" for c in commands if c[0] in ("codex", "claude")))
        self.assertTrue(all(c[1:3] == ["--user", "is-active"] for c in commands if c[0] == "systemctl"))

    def test_SSH_collect_is_fixed_program_and_quotes_inventory_as_data(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(stdout=json.dumps(SNAPSHOT))

        self.assertEqual(agent.collect(SNAPSHOT["inventory"], runner), SNAPSHOT)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:3], ["ssh", "-o", "BatchMode=yes"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertEqual(argv[-2], "home")
        self.assertEqual(kwargs["input"], agent.COLLECTOR)
        self.assertTrue(kwargs["check"])


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "2026-11-24.json"
        self.journal = agent.Journal(self.path)
        self.journal.reserve(SNAPSHOT, NOW)

    def test_exclusive_nightly_reservation_and_private_permissions(self):
        with self.assertRaises(ValueError):
            self.journal.reserve(SNAPSHOT, NOW)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_interruption_before_during_or_after_update_always_resumes_at_verify(self):
        self.assertEqual(self.journal.resume_steps(), ("verify_tabs", "resume_dispatcher", "report"))
        self.journal.record("stop_dispatcher", "started")
        self.journal.record("stop_dispatcher", "done")
        self.journal.record("update", "started")
        self.assertEqual(agent.Journal(self.path).resume_steps()[0], "verify_tabs")
        self.journal.record("update", "UNKNOWN")
        with self.assertRaises(ValueError):
            agent.Journal(self.path).record("update", "started")
        self.assertNotIn("shutdown", self.journal.resume_steps())

    def test_concurrent_update_reservation_has_exactly_one_winner(self):
        self.journal.record("stop_dispatcher", "started")
        self.journal.record("stop_dispatcher", "done")
        def reserve_once(_):
            try:
                agent.Journal(self.path).record("update", "started")
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(reserve_once, range(2))), 1)
        self.assertEqual(len(self.journal.read()["events"]), 3)

    def test_no_dispatcher_resume_without_successful_verification(self):
        with self.assertRaises(ValueError):
            self.journal.record("resume_dispatcher", "started")
        self.journal.record("verify_tabs", "started")
        self.journal.record("verify_tabs", "UNKNOWN")
        with self.assertRaises(ValueError):
            self.journal.record("resume_dispatcher", "started")

    def test_complete_run_is_not_reopened_or_updated(self):
        for step in agent.STEPS:
            self.journal.record(step, "started")
            self.journal.record(step, "done")
        self.assertEqual(agent.Journal(self.path).resume_steps(), ())
        with self.assertRaises(ValueError):
            self.journal.record("update", "started")

    def test_corruption_and_changed_snapshots_fail_closed(self):
        data = self.journal.read()
        data["snapshot"]["at"] += 1
        self.path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.journal.read()

    def test_effects_cannot_skip_steps_or_finish_without_reservation(self):
        for step in ("update", "shutdown", "resume_dispatcher", "report"):
            with self.subTest(step=step), self.assertRaises(ValueError):
                self.journal.record(step, "started")
        with self.assertRaises(ValueError):
            self.journal.record("update", "done")

    def test_recovery_records_interrupted_effect_as_unknown(self):
        self.journal.record("stop_dispatcher", "started")
        self.journal.record("stop_dispatcher", "done")
        self.journal.record("update", "started")
        agent.Journal(self.path).record("verify_tabs", "started")
        self.assertEqual(self.journal.read()["events"][-2], {"step": "update", "status": "UNKNOWN"})
        self.journal.record("verify_tabs", "done")
        self.journal.record("resume_dispatcher", "started")
        with self.assertRaises(ValueError):
            self.journal.record("update", "started")


class PlanTests(unittest.TestCase):
    def plan(self, raw=None, **kwargs):
        return agent.build_plan(copy.deepcopy(SNAPSHOT) if raw is None else raw, NOW, **kwargs)

    def test_plan_contains_pinned_updates_rollback_holds_and_each_session(self):
        plan = self.plan()
        self.assertTrue(plan["eligible"])
        self.assertEqual(plan["mode"], "DRY-RUN")
        self.assertEqual([s["step"] for s in plan["steps"]], list(agent.STEPS))
        self.assertEqual(plan["updates"][0]["command"], ["npm", "install", "--global", "@openai/codex@1.2.4"])
        self.assertEqual(plan["updates"][0]["rollback"][-1], "@openai/codex@1.2.3")
        self.assertEqual(plan["updates"][1]["command"], ["claude", "install", "2.3.5"])
        self.assertEqual(plan["steps"][2]["detail"], ["ssh", "home-windows", "wsl", "--shutdown"])
        self.assertTrue(plan["holds_preserved"][".config/example/ETF-HOLD"])
        self.assertEqual(len(plan["steps"][6]["detail"]), 2)

    def test_gates_missing_busy_disable_stale_hold_and_wrapper_mismatch(self):
        for key, replacement in (("busy", None), ("human_present", True), ("at", NOW - 601),
                                 ("holds", {}), ("restore_wrapper_sha256", "b" * 64)):
            raw = copy.deepcopy(SNAPSHOT)
            raw[key] = replacement
            with self.subTest(key=key):
                self.assertFalse(self.plan(raw)["eligible"])
        self.assertFalse(self.plan(disabled=True)["eligible"])

    def test_prereleases_unknown_versions_and_shell_text_never_become_commands(self):
        for bad in ('"2.0.0-beta.1"', '"2.0.0; bad"', "null", '"latest"'):
            raw = copy.deepcopy(SNAPSHOT)
            raw["versions"]["codex"]["available"] = bad
            result = self.plan(raw)
            self.assertFalse(result["eligible"])
            self.assertIn("codex_version_unknown", result["blockers"])

    def test_unchanged_or_older_channel_never_restarts(self):
        raw = copy.deepcopy(SNAPSHOT)
        raw["versions"]["codex"]["available"] = '"1.2.3"'
        raw["versions"]["claude"]["available"] = '"2.3.3"'
        self.assertEqual([s["step"] for s in self.plan(raw)["steps"]], ["report"])

    def test_mixed_updates_never_schedule_a_channel_downgrade(self):
        raw = copy.deepcopy(SNAPSHOT)
        raw["versions"]["claude"]["available"] = '"2.3.3"'
        update_step = next(s for s in self.plan(raw)["steps"] if s["step"] == "update")
        self.assertEqual([item["tool"] for item in update_step["detail"]], ["codex"])

    def test_recovery_uses_original_UUIDs_and_skips_all_effect_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = agent.Journal(Path(directory) / "2026-11-24.json")
            journal.reserve(SNAPSHOT, NOW)
            journal.record("stop_dispatcher", "started")
            journal.record("stop_dispatcher", "done")
            journal.record("update", "started")
            plan = self.plan(journal=journal)
            self.assertEqual([s["step"] for s in plan["steps"]], ["verify_tabs", "resume_dispatcher", "report"])
            self.assertEqual(plan["tabs"][0]["id"], SNAPSHOT["inventory"]["tabs"][0]["id"])
            self.assertEqual(plan["unknown_outcomes"], ["update"])
            self.assertEqual(plan["verify_expected_versions"], {"codex": "1.2.4", "claude": "2.3.5"})

    def test_interrupted_dispatcher_resume_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = agent.Journal(Path(directory) / "2026-11-24.json")
            journal.reserve(SNAPSHOT, NOW)
            for step in agent.STEPS[:8]:
                journal.record(step, "started")
                journal.record(step, "done")
            journal.record("resume_dispatcher", "started")
            plan = self.plan(journal=journal)
            self.assertFalse(plan["eligible"])
            self.assertEqual([s["step"] for s in plan["steps"]], ["verify_tabs", "report"])
            self.assertIn("dispatcher_outcome_requires_reconciliation", plan["blockers"])

    def test_per_tab_verification_requires_identity_tools_profile_and_continuity(self):
        _, tabs = agent.parse_snapshot(SNAPSHOT)
        receipts = [{**t, "tools": ["codex-ops.inbox_read"], "last_message_continuity": True} for t in tabs[:2]]
        self.assertEqual([r["result"] for r in agent.verify_tabs(tabs, receipts)], ["PASS", "PASS"])
        for key, value in (("id", "wrong"), ("profile", "wrong"), ("tools", []),
                           ("last_message_continuity", False)):
            observed = copy.deepcopy(receipts)
            observed[0][key] = value
            self.assertEqual(agent.verify_tabs(tabs, observed)[0]["result"], "UNKNOWN")
        self.assertEqual(agent.verify_tabs(tabs, [])[0]["result"], "UNKNOWN")
        self.assertEqual(agent.verify_tabs(tabs, None)[0]["result"], "UNKNOWN")
        self.assertEqual(agent.verify_tabs(tabs, [None, "invalid"])[0]["result"], "UNKNOWN")
        self.assertEqual(agent.verify_tabs(tabs, receipts + [receipts[0]])[0]["result"], "UNKNOWN")

    def test_offline_CLI_has_no_subprocess_or_writes_and_no_apply_option(self):
        with tempfile.TemporaryDirectory() as directory:
            before = (FIXTURES / "snapshot.json").read_bytes()
            output = io.StringIO()
            arguments = ["--snapshot", str(FIXTURES / "snapshot.json"), "--now", str(NOW),
                         "--disable-file", directory + "/DISABLE", "--state-dir", directory + "/state"]
            with patch.object(agent.subprocess, "run") as run, redirect_stdout(output):
                self.assertEqual(agent.main(arguments), 0)
            run.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["mode"], "DRY-RUN")
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(before, (FIXTURES / "snapshot.json").read_bytes())
            with self.assertRaises(SystemExit), patch("sys.stderr", io.StringIO()):
                agent.main(arguments + ["--apply"])

    def test_disable_symlink_prevents_eligibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disable = root / "DISABLE"
            disable.symlink_to(root / "missing")
            output = io.StringIO()
            arguments = ["--snapshot", str(FIXTURES / "snapshot.json"), "--now", str(NOW),
                         "--disable-file", str(disable), "--state-dir", str(root / "state")]
            with redirect_stdout(output):
                self.assertEqual(agent.main(arguments), 0)
            self.assertFalse(json.loads(output.getvalue())["eligible"])

    def test_completed_night_blocks_a_second_CLI_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = agent.Journal(root / "2026-11-24.json")
            journal.reserve(SNAPSHOT, NOW)
            for step in agent.STEPS:
                journal.record(step, "started")
                journal.record(step, "done")
            output = io.StringIO()
            with redirect_stdout(output), patch.object(agent, "collect") as collect:
                result = agent.main(["--inventory", str(root / "missing"), "--state-dir", str(root),
                                     "--now", str(NOW), "--disable-file", str(root / "DISABLE")])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["blockers"], ["night_already_reserved"])
            collect.assert_not_called()

    def test_older_unfinished_journal_takes_precedence_over_missing_new_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = agent.Journal(root / "2026-11-23.json")
            journal.reserve(SNAPSHOT, NOW - 86400)
            before = journal.path.read_bytes()
            output = io.StringIO()
            with redirect_stdout(output), patch.object(agent, "collect") as collect:
                result = agent.main(["--inventory", str(root / "missing"), "--state-dir", str(root),
                                     "--now", str(NOW), "--disable-file", str(root / "DISABLE")])
            self.assertEqual(result, 0)
            self.assertEqual([s["step"] for s in json.loads(output.getvalue())["steps"]],
                             ["verify_tabs", "resume_dispatcher", "report"])
            self.assertEqual(before, journal.path.read_bytes())
            collect.assert_not_called()

    def test_multiple_pending_journals_refuse_a_fresh_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent.Journal(root / "2026-11-23.json").reserve(SNAPSHOT, NOW - 86400)
            agent.Journal(root / "2026-11-24.json").reserve(SNAPSHOT, NOW)
            output = io.StringIO()
            with redirect_stdout(output), patch.object(agent, "collect") as collect:
                result = agent.main(["--inventory", str(root / "missing"), "--state-dir", str(root),
                                     "--now", str(NOW), "--disable-file", str(root / "DISABLE")])
            self.assertEqual(result, 2)
            self.assertFalse(json.loads(output.getvalue())["eligible"])
            collect.assert_not_called()

    def test_DISABLE_prevents_collection_even_with_missing_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            disable = Path(directory) / "DISABLE"
            disable.touch()
            with patch.object(agent, "collect") as collect, redirect_stdout(io.StringIO()):
                self.assertEqual(agent.main(["--inventory", directory + "/missing", "--disable-file", str(disable)]), 0)
            collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
