# Offline update decision for #375

This directory evaluates **public synthetic traces** of a proposed WSL maintenance attempt. It has no live collector, scheduler, updater, restore executor, journal writer or network adapter. Both unit templates contain comments only. The CLI reads one explicitly supplied fixture and a caller-supplied clock. Every result has `eligible=false` and `live_status=HOLD`, including a complete simulated verification.

From the repository root, run `python3 -IB update-agent/update_agent.py --dry-run --snapshot update-agent/fixtures/snapshot.json --now 1795507204` to inspect the fixture just after its simulated fence, drain and manifest. The expected fixture state is READY for a new sample at the first disruptive boundary. A different clock can expire the evidence. Run the focused controls with `python3 -IB -m unittest discover -s tests -p test_update_agent_375.py`.

## Reading a result

| Fixture state | Meaning |
| --- | --- |
| SKIP | No newer installable version on the selected channels. |
| ADMISSION | Pre-fence gates passed. No fence or under-fence readiness has been established. |
| READY | The fixture supplied matching, current under-fence receipts. Each boundary still needs its own presence sample. |
| IN_PROGRESS / RECOVERY | The journal prefix has a definite next stage. Recovery skips further updates. |
| UNWIND | The decision describes generation-matching reversible changes to release and newer changes to preserve. The attempt ends. |
| HOLD | A prerequisite is absent, invalid or stale, or rollback/restore needs separate qualification. |
| UNKNOWN | An issued action has ambiguous evidence or the fenced trace cannot be reconciled. Keep fences; consult durable readback. |
| VERIFIED | The simulated restore, per-caller checks, release and local reporting trace completed. |

A running system would need trustworthy producers for every input described in [SPEC.md](SPEC.md). The JSON format below the fixture namespace is local to this evaluator. A copied tab name, journal path, receipt field or digest cannot confer enrollment or certify current ownership. A simulated observation of a version has no bearing on the installed or running version of either real CLI. Even invoking a CLI with a version flag requires independent qualification of its side effects. This evaluator never invokes either CLI.

The original nightly candidate and its author evidence are retained in Git at `61d445816bc4225b1911ba8fb98d1321f50e4f2c`. Its live SSH inventory option, mutable local journal APIs and executable command previews are outside the accepted inert interface. A real journal, off-WSL continuity and human-only actions such as unlocking LastPass after reboot require their respective owners.
