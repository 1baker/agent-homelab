import unittest
from unittest.mock import Mock

from agent_homelab import agent_wake as wake


class AgentWakeTests(unittest.TestCase):
    def sample(self, **changes):
        fields = dict(
            now=100_000,
            seq=17,
            turns=(),
            live_handoff_age=3600,
            pro_pending=0,
            helpers_active=0,
            claude_unclaimed=0,
            claude_running=False,
        )
        return wake.busy_state(**(fields | changes))

    def check(self, **changes):
        fields = dict(
            now=100_400,
            last_good=self.sample(turns=((0, "work"),)),
            pulled_at=100_000,
            polls=((100_100, "unreachable"), (100_250, "unreachable"), (100_400, "unreachable")),
            attempts=(),
            read_veto=lambda: (False, False, False),
        )
        return wake.dry_run(**(fields | changes))

    def test_content_free_schema_real_activity_only(self):
        self.assertEqual(self.sample(), dict(at=100_000, seq=17, busy=False, reasons=[]))
        for field, value, reason in [
            ("turns", ((599, "work"), (0, "nudge_no_work")), "turn"),
            ("live_handoff_age", 3599, "handoff"),
            ("pro_pending", 1, "pro"),
            ("helpers_active", 1, "helper"),
            ("claude_unclaimed", 1, "waiter"),
            ("claude_running", True, "waiter"),
        ]:
            self.assertEqual(self.sample(**{field: value})["reasons"], [reason])
        self.assertEqual(self.sample(turns=((600, "work"), (0, "nudge_blocked"), (1, "nudge_no_work")))["reasons"], [])

    def test_unknown_inputs(self):
        for changes in [
            dict(pro_pending=None),
            dict(turns=((-1, "work"),)),
            dict(seq=True),
            dict(helpers_active=True),
            dict(claude_running=1),
            dict(now=False),
        ]:
            self.assertIsNone(self.sample(**changes))

    def test_qualified_ordinary_wake_and_lease(self):
        self.assertEqual(self.check(), "would_wake")
        self.assertEqual(self.check(last_good=self.sample(now=99_700, pro_pending=1)), "would_wake")
        self.assertEqual(self.check(last_good=self.sample(now=99_699, pro_pending=1)), "stale_state")
        self.assertEqual(self.check(pulled_at=99_999), "stale_state")
        polls = tuple((100_480 + 120 * i, "unreachable") for i in range(57))
        self.assertEqual(self.check(now=107_200, polls=polls), "would_wake")
        self.assertNotEqual(self.check(now=107_320, polls=polls + ((107_320, "unreachable"),)), "would_wake")
        late = tuple((at + 1, state) for at, state in polls)
        self.assertNotEqual(self.check(now=107_201, polls=late), "would_wake")

    def test_fresh_veto_and_refused_unknown(self):
        for veto in [
            (True, False, False),
            (False, True, False),
            (False, False, True),
            (False, None, False),
            (0, 0, 0),
            None,
        ]:
            with self.subTest(veto=veto):
                self.assertNotEqual(self.check(read_veto=Mock(return_value=veto)), "would_wake")
        self.assertNotEqual(self.check(read_veto=Mock(side_effect=OSError)), "would_wake")

    def test_invalid_inputs_misses_and_caps(self):
        for changes in [
            dict(last_good=None),
            dict(last_good=self.sample()),
            dict(last_good=self.sample() | {"busy": True}),
            dict(now=100_401),
            dict(polls=((100_400, "unreachable"),) * 3),
            dict(polls=((100_100, "unreachable"), (100_250, "reachable"), (100_400, "unreachable"))),
            dict(polls=((100_001, "unreachable"), (100_250, "unreachable"), (100_400, "unreachable"))),
            dict(attempts=None),
            dict(attempts=(100_401,)),
            dict(attempts=(100_399,)),
            dict(attempts=(98000,) * 2),
            dict(attempts=tuple(range(90000, 90006))),
        ]:
            self.assertNotEqual(self.check(**changes), "would_wake")
        self.assertEqual(self.check(attempts=(99200,)), "would_wake")

    def test_keep_awake_holds_system_only_then_releases_on_all_exit_paths(self):
        busy = self.sample(pro_pending=1)
        for second in [
            (100_301, busy, False),
            (100_100, busy, True),
            (100_100, busy, None),
            (100_100, self.sample(), False),
            (99_999, busy, False),
            (100_100, None, False),
        ]:
            setter = Mock(return_value=1)
            wake.keep_awake(iter([(100_300, busy, False), second]), setter)
            self.assertEqual([c.args[0] for c in setter.call_args_list], [0x80000001, 0x80000000])

        def interrupted():
            yield (100_000, busy, False)
            raise OSError

        setter = Mock(return_value=1)
        with self.assertRaises(OSError):
            wake.keep_awake(interrupted(), setter)
        self.assertEqual(setter.call_args_list[-1].args, (0x80000000,))
