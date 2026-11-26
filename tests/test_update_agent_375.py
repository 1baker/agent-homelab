"""Public fixture-only contract for PR11. No live adapters or unit execution."""

import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

MODULE = Path(__file__).parents[1] / "update-agent" / "update_agent.py"
SPEC = importlib.util.spec_from_file_location("update_agent", MODULE)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)
FIXTURES = MODULE.parent / "fixtures"


def fixture():
    return json.loads((FIXTURES / "snapshot.json").read_text())


def result(raw):
    now = max([raw["pre"]["now"]] + [event["at"] for event in raw["trace"]])
    return agent.build_plan(raw, now)


def receipt(raw, schema, when, **fields):
    return dict(
        schema=f"fixture.{schema}.v1", binding=copy.deepcopy(raw["binding"]), at=when, expires=when + 300, **fields
    )


def append(raw, kind, **fields):
    t = raw["trace"][-1]["at"] + 1
    event = receipt(raw, "event", t, kind=kind, epoch="epoch-A", **fields)
    event.update(sequence=len(raw["trace"]) + 1, prior_sequence=len(raw["trace"]), writer_generation="op-A")
    raw["trace"].append(event)
    return event


def intent(raw, step):
    event = append(raw, "intent", step=step, operation_id=step + "-1")
    gate = copy.deepcopy(raw["pre"])
    gate.update(boundary=step, opened=event["at"])
    gate["presence"].update(at=event["at"], boundary=step)
    event["gate"] = gate
    if step == "shutdown":
        event["recheck"] = receipt(
            raw,
            "C4",
            event["at"],
            epoch=event["epoch"],
            drains=copy.deepcopy(raw["trace"][1]["drains"]),
            protected_effect_pending=False,
        )
    if step == "start_distro":
        event["needs_wake"] = False
    if step == "resume_dispatcher":
        event.update(current_dispatcher="stop-A", other_stop=False, disposition="release_own")
    return event


def ack(raw, step, kind="ack"):
    event = append(raw, kind, step=step, operation_id=step + "-1", outcome="done", observed=True, durable_readback=True)
    if step == "stop_dispatcher":
        event["written_generation"] = "stop-A"
    if step == "stop_dispatcher" or step.startswith("update_") or step == "shutdown":
        p = copy.deepcopy(raw["pre"]["presence"])
        p.update(at=event["at"], boundary=step)
        event["effect_started_at"] = event["at"]
        event["post_presence"] = p
    if step.startswith("update_"):
        event.update(tool=step.removeprefix("update_"), before="1.0.0", target="1.0.1", observed_version="1.0.1")
    if step == "resume_dispatcher":
        event["released_generation"] = "stop-A"
    if step == "resume_tabs":
        manifest = raw["trace"][3]["R3"]
        event.update(
            restored_owners=[r["owner"] for r in manifest["rows"]],
            manifest_digest=manifest["manifest_digest"],
            wrapper_only=True,
        )
    if step == "report":
        event["released_fence"] = "epoch-A"
        event["released_holds"] = {
            "hold:" + p: g
            for p, g in raw["trace"][0]["startup_holds"].items()
            if raw["current_generations"]["hold:" + p] == g
        }
        event["post_hold_generations"] = {
            "hold:" + path: None
            if "hold:" + path in event["released_holds"]
            else raw["current_generations"]["hold:" + path]
            for path in raw["trace"][0]["startup_holds"]
        }
        event["post_hold_states"] = {
            path: present or event["post_hold_generations"].get("hold:" + path) is not None
            for path, present in raw["inventory_snapshot"]["holds"].items()
        }
    return event


def complete(raw, steps):
    for step in steps:
        intent(raw, step)
        ack(raw, step)


def verification(raw, when):
    manifest = raw["trace"][3]["R3"]
    boot = "boot-B"
    common = dict(epoch="epoch-A", new_boot=boot, manifest_digest=manifest["manifest_digest"])
    rows = []
    for row in manifest["rows"]:
        rows.append(
            receipt(
                raw,
                "row",
                when,
                **common,
                owner=row["owner"],
                observed_identity=copy.deepcopy(row),
                continuity=True,
                caller=row.get("caller"),
                non_consuming=True,
                method="ops_status",
                tools=["ops_status"],
            )
        )
    vs = {"codex": "1.0.1", "claude": "1.0.1"}
    return receipt(
        raw,
        "verification",
        when,
        **common,
        installed=vs,
        running=dict(vs),
        hold_states={path: True for path in raw["inventory_snapshot"]["holds"]},
        hold_generations={"hold:" + path: gen for path, gen in raw["trace"][0]["startup_holds"].items()},
        service_states=raw["inventory_snapshot"]["services"],
        service_enabled=raw["inventory_snapshot"]["service_enabled"],
        timer_states=raw["inventory_snapshot"]["timers"],
        holds_preserved=True,
        ETF_never_started=True,
        rows=rows,
    )


class AdmissionTests(unittest.TestCase):
    def test_legacy_input_is_never_eligible(self):
        p = agent.build_plan(fixture()["inventory_snapshot"], 0)
        self.assertFalse(p["eligible"])
        self.assertEqual(p["fixture_state"], "HOLD")
        self.assertNotIn('["claude", "--resume"', json.dumps(p))

    def test_busy_shape_boundary_and_unknown(self):
        now = 1000
        base = dict(seq=1, at=700, busy=False, reasons=[])
        self.assertEqual(agent.idle_gate(base, now), "idle")
        for delta in [
            dict(at=699),
            dict(at=1001),
            dict(seq=True),
            dict(busy=True),
            dict(reasons=["helper"]),
            dict(extra=1),
            dict(reasons=["x"]),
        ]:
            self.assertNotEqual(agent.idle_gate(dict(base, **delta), now), "idle")
        self.assertNotEqual(agent.idle_gate(dict(at=401, reasons=[]), now), "idle")
        busy = json.loads((FIXTURES / "busy-state.json").read_text())
        self.assertEqual(agent.idle_gate(busy, busy["at"]), "busy")

    def test_any_time_ready_and_live_hold(self):
        def shifted(value, seconds):
            if isinstance(value, list):
                return [shifted(item, seconds) for item in value]
            if isinstance(value, dict):
                return {
                    k: v + seconds
                    if k in ("at", "expires", "opened", "now", "last_input_time")
                    else shifted(v, seconds)
                    for k, v in value.items()
                }
            return value

        for shift in (0, 12 * 3600):
            p = result(shifted(fixture(), shift))
            self.assertEqual(p["fixture_state"], "READY")
            self.assertFalse(p["eligible"])
            self.assertEqual(p["live_status"], "HOLD")

    def test_trace_a_and_frontier_controls(self):
        for case in (
            "trace_A",
            "uncertainty",
            "pre_gate",
            "future",
            "wrong_boot",
            "no_notice",
            "digest_missing",
            "too_soon",
            "unknown_u",
            "stale_C1",
            "ETF_active",
            "ETF_hold_missing",
            "C2_unknown",
            "DISABLE",
            "unqualified_version",
        ):
            with self.subTest(case=case):
                raw = fixture()
                gate = raw["pre"]
                t = gate["now"]
                p = gate["presence"]
                if case == "trace_A":
                    raw["notice"]["at"] = t - 1800
                    p["last_input_time"] = t - 1500
                if case == "uncertainty":
                    raw["notice"]["at"] = t - 1800
                    p["last_input_time"] = t - 1801
                if case == "pre_gate":
                    p["at"] -= 1
                if case == "future":
                    p["at"] += 1
                if case == "wrong_boot":
                    p["binding"]["old_boot"] = "foreign"
                if case == "no_notice":
                    raw["notice"]["journaled"] = False
                if case == "digest_missing":
                    raw["notice"]["digest_confirmed"] = False
                if case == "too_soon":
                    raw["notice"]["at"] += 1
                if case == "unknown_u":
                    p["u"] = None
                if case == "stale_C1":
                    gate["busy"]["at"] -= 301
                if case == "ETF_active":
                    gate["etf"]["families"]["etf-agent-*"] = "active"
                if case == "ETF_hold_missing":
                    gate["etf"]["hold_present"] = False
                if case == "C2_unknown":
                    gate["sleep_intended"] = None
                if case == "DISABLE":
                    gate["disabled"] = True
                if case == "unqualified_version":
                    raw["version_read"]["tools"]["claude"]["side_effect_free_observation"] = False
                decision = result(raw)
                self.assertEqual(decision["fixture_state"], "HOLD")
                self.assertEqual(decision["effects"], 0)

    def test_notice_history_and_suspension(self):
        raw = fixture()
        n = raw["notice"]
        raw["history"]["prior_attempts"] = [
            dict(
                attempt="A",
                posted_at=n["at"] - 60,
                update_id=n["update_id"],
                outcome="presence_cancelled",
                ended_at=n["at"] - 1,
            )
        ]
        self.assertEqual(result(raw)["reason"], "notice_cooldown")
        raw["history"]["prior_attempts"] = [
            dict(
                attempt=str(i),
                posted_at=n["at"] - (4 + i * 4) * 3600,
                ended_at=n["at"] - 1 - i * 14400,
                outcome="presence_cancelled",
                update_id=n["update_id"],
            )
            for i in range(3)
        ]
        self.assertEqual(result(raw)["reason"], "presence_daily_limit")
        raw["history"].update(prior_attempts=[], suspended=True)
        self.assertEqual(result(raw)["fixture_state"], "HOLD")

    def test_admission_is_not_readiness(self):
        raw = fixture()
        raw["trace"] = []
        self.assertEqual(result(raw)["fixture_state"], "ADMISSION")
        raw["trace"] = [fixture()["trace"][-1]]
        self.assertEqual(result(raw)["fixture_state"], "HOLD")

    def test_invalid_fleet_and_manifest(self):
        for case in (
            "operator",
            "competitor",
            "missing_ingress",
            "uncertain_slot",
            "expired",
            "unmapped",
            "manifest_digest",
            "legacy_profile",
            "role_launcher",
        ):
            with self.subTest(case=case):
                raw = fixture()
                ready = raw["trace"][-1]
                if case == "operator":
                    ready["R1"]["survives_chief_loss"] = False
                if case == "competitor":
                    ready["R1"]["single_writer"] = False
                if case == "missing_ingress":
                    del ready["R2"]["drains"]["native-queue"]
                if case == "uncertain_slot":
                    ready["R2"]["drains"]["helpers"]["unknown"] = True
                if case == "expired":
                    ready["R1"]["expires"] = raw["pre"]["now"] - 1
                if case == "manifest_digest":
                    ready["R1"]["manifest_digest"] = "0" * 64
                if case in ("unmapped", "legacy_profile", "role_launcher"):
                    rows = ready["R3"]["rows"]
                    if case == "unmapped":
                        rows[1]["pane"] = rows[0]["pane"]
                    if case == "legacy_profile":
                        rows[0]["profile"] = None
                    if case == "role_launcher":
                        rows[1]["launcher"] = "generic-resume"
                    for k in ("R1", "R2", "R3"):
                        ready[k]["manifest_digest"] = agent.digest(rows)
                raw["trace"][1]["drains"] = copy.deepcopy(ready["R2"]["drains"])
                raw["trace"][2]["R3"] = copy.deepcopy(ready["R3"])
                self.assertEqual(result(raw)["fixture_state"], "UNWIND")


class RecoveryTests(unittest.TestCase):
    def test_each_boundary_requires_fresh_sample(self):
        raw = fixture()
        gate = intent(raw, "stop_dispatcher")["gate"]
        gate["presence"]["last_input_time"] = gate["opened"] - 1
        p = result(raw)
        self.assertEqual(p["fixture_state"], "UNWIND")
        self.assertEqual(p["release_matching"], ["hold:.config/example/STARTUP-HOLD", "fence"])
        self.assertFalse(p["suspend_update"])
        raw = fixture()
        complete(raw, ["stop_dispatcher"])
        gate = intent(raw, "update_codex")["gate"]
        gate["presence"]["at"] = gate["opened"] - 1
        raw["current_generations"].update(dispatcher="new-stop", other_stop=True)
        p = result(raw)
        self.assertEqual(p["release_matching"], ["hold:.config/example/STARTUP-HOLD", "fence"])
        self.assertIn("dispatcher", p["preserve"])

    def test_five_second_residual_and_presence_race(self):
        raw = fixture()
        e = intent(raw, "stop_dispatcher")
        e["at"] += 6
        self.assertEqual(result(raw)["fixture_state"], "UNWIND")
        raw = fixture()
        e = intent(raw, "stop_dispatcher")
        ack(raw, "stop_dispatcher")["post_presence"]["last_input_time"] = e["at"]
        intent(raw, "update_codex")
        self.assertEqual(result(raw)["reason"], "presence_input")

    def test_effect_delayed_after_admitted_intent_retains_fence(self):
        raw = fixture()
        admitted = intent(raw, "stop_dispatcher")
        done = ack(raw, "stop_dispatcher")
        done["at"] = done["effect_started_at"] = done["post_presence"]["at"] = admitted["at"] + 6
        outcome = result(raw)
        self.assertEqual(outcome["fixture_state"], "UNKNOWN")
        self.assertTrue(outcome["retain_fences"])

    def test_reused_presence_sample_is_refused_at_another_boundary(self):
        raw = fixture()
        intent(raw, "stop_dispatcher")["gate"]["presence"]["boundary"] = "G-pre"
        self.assertEqual(result(raw)["fixture_state"], "UNWIND")

    def test_unknown_intent_cannot_release_or_infer_a_version(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher", "update_codex"])
        intent(raw, "update_claude")
        p = result(raw)
        self.assertEqual(p["fixture_state"], "UNKNOWN")
        self.assertTrue(p["retain_fences"])
        self.assertEqual(p["last_confirmed_versions"], {"codex": "1.0.1", "claude": "1.0.0"})
        ack(raw, "update_claude")["outcome"] = "UNKNOWN"
        intent(raw, "shutdown")
        self.assertEqual(result(raw)["fixture_state"], "UNKNOWN")
        raw["trace"].pop()
        ack(raw, "update_claude", kind="reconcile")
        self.assertEqual(result(raw)["next_stage"], "shutdown")

    def test_changed_hold_generation_is_preserved(self):
        raw = fixture()
        key = "hold:.config/example/STARTUP-HOLD"
        raw["current_generations"][key] = "new-owner-generation"
        append(raw, "interrupted")
        plan = result(raw)
        self.assertEqual(plan["preserve"], [key])
        self.assertEqual(plan["release_matching"], ["fence"])
        del raw["current_generations"][key]
        self.assertTrue(result(raw)["retain_fences"])

    def test_interruption_before_and_after_stop(self):
        raw = fixture()
        append(raw, "interrupted")
        self.assertEqual(result(raw)["release_matching"], ["hold:.config/example/STARTUP-HOLD", "fence"])
        raw = fixture()
        complete(raw, ["stop_dispatcher", "update_codex"])
        append(raw, "interrupted")
        p = result(raw)
        self.assertEqual(p["next_stage"], "start_services")
        self.assertEqual(p["observed_versions"], {"claude": "1.0.0", "codex": "1.0.1"})

    def test_shutdown_rechecks_drain_and_protected_work(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher", "update_codex", "update_claude"])
        event = intent(raw, "shutdown")
        event["recheck"]["drains"]["helpers"]["unknown"] = True
        self.assertEqual(result(raw)["reason"], "C4_shutdown_recheck")
        self.assertTrue(result(raw)["retain_fences"])

    def test_prior_dispatcher_stop_is_never_overwritten(self):
        raw = fixture()
        raw["inventory_snapshot"]["dispatcher_stopped"] = True
        intent(raw, "stop_dispatcher")
        e = ack(raw, "stop_dispatcher")
        self.assertEqual(result(raw)["fixture_state"], "UNKNOWN")
        e["written_generation"] = None
        self.assertEqual(result(raw)["next_stage"], "update_codex")

    def test_confirmed_failed_update_restores_before_verifying(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher"])
        intent(raw, "update_codex")
        ack(raw, "update_codex").update(outcome="failed", observed_version="1.0.0")
        self.assertEqual(result(raw)["next_stage"], "start_services")
        intent(raw, "verify_tabs")
        self.assertNotIn(result(raw)["fixture_state"], ("VERIFIED", "READY"))

    def through_verification(self):
        raw = fixture()
        complete(
            raw,
            [
                "stop_dispatcher",
                "update_codex",
                "update_claude",
                "shutdown",
                "start_distro",
                "start_services",
                "restore_byobu",
                "resume_tabs",
            ],
        )
        intent(raw, "verify_tabs")
        event = ack(raw, "verify_tabs")
        event["verification"] = verification(raw, event["at"])
        return raw

    def test_startup_hold_phase_readback(self):
        path = ".config/example/STARTUP-HOLD"
        key = "hold:" + path
        for case, expected in (
            ("present", "VERIFIED"),
            ("early_removal", "UNKNOWN"),
            ("missing_generation", "UNKNOWN"),
            ("still_present_after_release", "UNKNOWN"),
            ("false_release", "UNKNOWN"),
            ("foreign_preserved", "VERIFIED"),
            ("foreign_removed", "UNKNOWN"),
            ("old_generation_reappeared", "UNKNOWN"),
            ("missing_post_state", "UNKNOWN"),
        ):
            with self.subTest(case=case):
                raw = self.through_verification()
                verified = raw["trace"][-1]["verification"]
                if case == "early_removal":
                    verified["hold_states"][path] = False
                if case == "missing_generation":
                    del verified["hold_generations"][key]
                if case in ("foreign_preserved", "foreign_removed", "false_release"):
                    raw["current_generations"][key] = "foreign-B"
                if case in ("foreign_preserved", "old_generation_reappeared"):
                    verified["hold_generations"][key] = "foreign-B"
                complete(raw, ["resume_dispatcher", "report"])
                report = raw["trace"][-1]
                if case == "still_present_after_release":
                    report["post_hold_states"][path] = True
                if case == "false_release":
                    report["released_holds"][key] = "startup-A"
                if case == "foreign_removed":
                    report["post_hold_generations"][key] = None
                    report["post_hold_states"][path] = False
                if case == "missing_post_state":
                    del report["post_hold_states"]
                outcome = result(raw)
                self.assertEqual(outcome["fixture_state"], expected, outcome["reason"])
                if expected == "UNKNOWN":
                    self.assertTrue(outcome["retain_fences"])

    def test_verified_restore_and_foreign_receipts(self):
        raw = self.through_verification()
        for case in ("caller", "attempt", "config", "tool", "partial", "consuming", "wrong_boot", "running"):
            with self.subTest(case=case):
                other = copy.deepcopy(raw)
                v = other["trace"][-1]["verification"]
                row = v["rows"][1]
                if case == "caller":
                    row["caller"] = "another-tab"
                if case == "attempt":
                    row["binding"]["attempt"] = "old"
                if case == "config":
                    row["observed_identity"]["config_sha256"] = "9" * 64
                if case == "tool":
                    row["tools"] = []
                if case == "partial":
                    v["rows"].pop()
                if case == "consuming":
                    row["method"] = "inbox_read"
                if case == "wrong_boot":
                    v["new_boot"] = raw["binding"]["old_boot"]
                if case == "running":
                    v["running"]["claude"] = "1.0.0"
                p = result(other)
                self.assertEqual(p["fixture_state"], "UNKNOWN")
                self.assertTrue(p["retain_fences"])
        complete(raw, ["resume_dispatcher", "report"])
        self.assertEqual(result(raw)["fixture_state"], "VERIFIED")
        self.assertFalse(result(raw)["eligible"])

    def test_cli_and_templates_have_no_operational_entrypoint(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(
                agent.main(
                    [
                        "--dry-run",
                        "--snapshot",
                        str(FIXTURES / "snapshot.json"),
                        "--now",
                        str(fixture()["pre"]["now"] + 4),
                    ]
                ),
                0,
            )
        self.assertEqual(json.loads(out.getvalue())["live_status"], "HOLD")
        for path in (MODULE.parent / "systemd").glob("*.in"):
            self.assertTrue(all(not line.strip() or line.startswith("#") for line in path.read_text().splitlines()))


class JournalAndInventoryTests(unittest.TestCase):
    def test_wrong_writer_or_gap_after_fence_retains_fence(self):
        for change in ({"writer_generation": "retired"}, {"sequence": 99}, {"epoch": "foreign"}):
            raw = fixture()
            raw["trace"][-1].update(change)
            p = result(raw)
            self.assertEqual(p["fixture_state"], "UNKNOWN")
            self.assertTrue(p["retain_fences"])

    def test_unknown_version_no_update_and_downgrade(self):
        raw = fixture()
        for observed in raw["version_read"]["tools"].values():
            observed["available"] = "0.8.4"
        self.assertEqual(result(raw)["fixture_state"], "SKIP")
        raw["version_read"]["tools"]["claude"]["available"] = "unknown"
        self.assertEqual(result(raw)["fixture_state"], "HOLD")

    def test_rollback_requires_observed_original_tool_version(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher"])
        intent(raw, "update_codex")
        event = ack(raw, "update_codex")
        event["outcome"] = "rolled_back"
        self.assertEqual(result(raw)["fixture_state"], "UNKNOWN")
        event["observed_version"] = "1.0.0"
        p = result(raw)
        self.assertEqual(p["next_stage"], "start_services")
        self.assertEqual(p["tool_stages"]["codex"][-1]["stage"], "rolled_back")

    def test_presence_after_update_preserves_fence_for_rollback_decision(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher", "update_codex"])
        gate = intent(raw, "update_claude")["gate"]
        gate["presence"]["last_input_time"] = gate["opened"] - 1
        p = result(raw)
        self.assertTrue(p["retain_fences"])
        self.assertEqual(p["rollback_review"], {"codex": "1.0.1"})

    def test_conditional_restore_wake_needs_exact_veto_and_holder(self):
        raw = fixture()
        complete(raw, ["stop_dispatcher", "update_codex", "update_claude", "shutdown"])
        event = intent(raw, "start_distro")
        event["needs_wake"] = True
        self.assertEqual(result(raw)["fixture_state"], "UNKNOWN")
        wake = receipt(
            raw,
            "restore_wake",
            event["at"],
            epoch="epoch-A",
            holder="op-A",
            journal_epoch="epoch-A",
            journal_holder="op-A",
            admitted_restore_step=True,
            disabled=False,
            sleep_intended=False,
            veto_read_ok=True,
        )
        event["restore_wake"] = wake
        ack(raw, "start_distro")
        self.assertEqual(result(raw)["next_stage"], "start_services")
        wake["sleep_intended"] = True
        self.assertTrue(result(raw)["retain_fences"])
        self.assertNotIn("next_stage", result(raw))

    def test_partial_bound_evidence_and_non_consuming_replay(self):
        raw = fixture()
        initial = copy.deepcopy(raw)
        self.assertEqual(result(raw), result(raw))
        self.assertEqual(initial, raw)
        raw["pre"]["presence"] = None
        self.assertEqual(result(raw)["reason"], "P0_binding")
        raw = fixture()
        raw["inventory_snapshot"]["tmux"] += "\nother\t@8\t%8\t/empty\t\t"
        self.assertEqual(result(raw)["fixture_state"], "HOLD")
