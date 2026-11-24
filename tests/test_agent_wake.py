import unittest

from agent_homelab.agent_wake import BusyState, busy_state, dry_run


class AgentWakeTests(unittest.TestCase):
    def sample(self, **changes):
        data = dict(now=100_000, turn_age=600, live_handoff_age=3600,
                    pro_pending=0, helpers_active=0, waiter_armed=False)
        return busy_state(**(data | changes))

    def check(self, **changes):
        data = dict(now=100_400, last_good=self.sample(turn_age=0),
                    polls=((100_100, "unreachable"), (100_250, "unreachable"),
                           (100_400, "unreachable")), disabled=False, attempts=())
        return dry_run(**(data | changes))

    def test_busy_rules(self):
        self.assertEqual(self.sample().reasons, ())
        for field, value, reason in [('turn_age', 599, 'turn'), ('live_handoff_age', 3599, 'handoff'),
                                     ('pro_pending', 1, 'pro'), ('helpers_active', 1, 'helper'),
                                     ('waiter_armed', True, 'waiter')]:
            with self.subTest(field=field):
                self.assertEqual(self.sample(**{field: value}).reasons, (reason,))

    def test_unknown_inputs(self):
        for changes in [dict(pro_pending=None), dict(turn_age=-1), dict(helpers_active=True),
                        dict(waiter_armed=1), dict(now=False)]:
            self.assertIsNone(self.sample(**changes))

    def test_would_wake_only(self):
        self.assertEqual(self.check(), 'would_wake')

    def test_gates(self):
        for changes in [dict(disabled=True), dict(disabled=None), dict(last_good=None),
                        dict(last_good=self.sample()), dict(last_good=BusyState(100_401, ('turn',))),
                        dict(now=100_601), dict(attempts=(100_399,)), dict(attempts=None),
                        dict(attempts=(100_401,)), dict(attempts=tuple(range(90_000,90_006)))]:
            self.assertNotEqual(self.check(**changes), 'would_wake')
        self.assertEqual(self.check(attempts=(99_200,)), 'would_wake')

    def test_misses_must_be_consecutive_current_and_distinct(self):
        for polls in [(), ((100_400, 'unreachable'),) * 3,
                      ((100_100,'unreachable'),(100_250,'unknown'),(100_400,'unreachable')),
                      ((100_100,'unreachable'),(100_250,'reachable'),(100_400,'unreachable')),
                      ((100_001,'unreachable'),(100_250,'unreachable'),(100_400,'unreachable'))]:
            self.assertNotEqual(self.check(polls=polls), 'would_wake')

    def test_poll_history_and_attempt_history(self):
        self.assertEqual(self.check(attempts=(99_200, 98_000)), 'unknown_attempts')
        self.assertEqual(self.check(attempts=(98_000,) * 2), 'unknown_attempts')
        self.assertEqual(self.check(attempts=tuple(range(90_000, 90_006))), 'attempt_limit')
        self.assertEqual(self.check(attempts=(14_000,) + tuple(range(90_000, 90_005))), 'would_wake')
        self.assertEqual(self.check(last_good=BusyState(100_100, ('turn',))), 'unqualified_polls')
        self.assertEqual(self.check(now=100_401), 'unqualified_polls')
        self.assertEqual(self.check(last_good=BusyState(100_000, ('unexpected',))), 'unknown_state')
