# Bastion update-agent — Source dry run

This directory implements the bounded Source assignment for work-tracker #375.
It collects observations over read-only SSH, checks eligibility and prints a JSON
plan. **It has no apply/execute command.** The systemd files are templates only;
even if separately rendered and installed, this revision only prints plans.
The complete approved product specification is on #375. [SPEC.md](SPEC.md)
records this slice's acceptance boundary and remaining operational dependencies.

## Try the offline flow

```sh
python3 update-agent/update_agent.py --dry-run --snapshot update-agent/fixtures/snapshot.json --now 1795507200 --disable-file /tmp/example-update-agent-DISABLE --state-dir /tmp/example-update-agent-state
python3 -m unittest discover -s tests -p test_update_agent_375.py -v
```

In plain English: the first command prints the proposed sequence for synthetic
panes and chat IDs at 02:00 Central. The second runs the offline tests. Neither
command contacts the host or changes services, binaries, holds or chat sessions.
The example temporary paths are read only; an existing DISABLE file or journal
there can intentionally prevent eligibility. No journal is created by a dry run.

Python 3.11+ and its standard library are sufficient. The tests also run through
the repository's normal pytest discovery. No installation is needed.

## Private inventory and collection

For a later operator-run read-only check on the bastion, `--inventory` takes a
private `update-agent.inventory.v1` JSON file. Use the `inventory` object in the
synthetic snapshot fixture as the schema example, not as a deployment config.
Set the existing SSH aliases, distro, all pane identities/profiles, service list,
complete known startup-hold paths and reviewed wrapper/snapshot paths. The
`home` and `home-windows` aliases are the aliases named in #375; no IP addresses
or user identities belong in source. Keep actual inventories and snapshots
outside the repository. Snapshot output contains private topology and chat IDs;
do not publish it as a test fixture or attach raw output to GitHub.

`--inventory` runs one fixed Python reader through `ssh home`, using existing
SSH host trust, BatchMode, explicit timeouts and no host-key enrollment. Its
only process calls are `codex --version`, `claude --version`, `tmux list-panes`
and `systemctl --user is-active`. It fetches release tags directly from the
public npm registry over verified HTTPS; it never runs `npm view`, installs,
reads npm authentication settings or writes the npm cache. A missing configured
tag, prerelease, failed request or malformed version prevents eligibility.

`tools.codex.method` supports an operator-declared npm installation;
`tools.claude.method` supports npm or the native installer. Supported channels
are `latest` and `stable`, accepted only when the vendor publishes that tag.
This does not auto-detect or migrate installation ownership. The later operator
must confirm that the declared method owns the actual binary. Unknown methods
are rejected. Plans use exact release versions, never a moving tag, and include
the previous pinned version as rollback. Before any future real update, retain
and verify the previous artifact locally so recovery does not depend solely on
network reinstallation; verify target integrity through the owning installer.

Pinned methods follow the official [Codex source installation guidance](https://github.com/openai/codex#installing-and-running-codex-cli)
and [Claude's versioned native install command](https://code.claude.com/docs/en/cli-reference).
The registry `stable`/`latest` tag selects the version; no beta/next tag is used.
This Source plan does not claim an installed method or rollback was qualified.

## Snapshot and safety gates

The tmux listing has six tab-separated fields: session, window ID, pane ID,
working directory, `@byobu-codex-thread-id`, `@byobu-claude-session-id`. The last
two are the existing Byobu window options. Empty trailing columns matter.
The private static matrix must cover **every** pane, including shell panes;
each agent's current UUID must match its matrix entry. Changed, duplicate,
unmapped or missing panes reject the snapshot. Profiles come from the reviewed
static matrix, not a guessed tmux option or the active model. Duplicate window
metadata on split panes is deliberately rejected rather than resuming a chat
twice. Resolve the matrix explicitly before a later operational run.

The reader records presence/absence of every inventoried startup hold, including
the ETF hold, without reading contents or modifying any hold. Permission errors
stay unknown. Startup goes through the hash-pinned normal-startup wrapper that
respects those holds; the planner never starts each listed service directly.
The reviewed restore wrapper is also hash checked. It owns the per-tab launch
and UUID/profile restoration; the `resume_tabs` step describes that wrapper's
work and never asks a second dispatcher to type a duplicate resume command.
The paths and argument contract of the reviewed 8a/46e1 wrapper must be qualified
by Ops before integration; this slice does not invent or invoke that contract.

Busy state is read from `~/.local/state/agent-wake/state.json`. The candidate
wire shape is JSON serialization of #364's `BusyState(at, reasons)`:

```json
{"at": 1795507200, "reasons": []}
```

In plain English: the timestamp says when the observation was made, and an empty
list means the producer saw none of its known busy signals. This sample is
synthetic; it does not prove the real machine is idle.

Only a timestamp less than 600 seconds old, no future timestamp, an exact known
shape and an empty reasons list qualify as idle. Known ordered reasons are
`turn`, `handoff`, `pro`, `helper`, `waiter`. Missing/invalid/unknown/stale state
never means idle. `~/.config/update-agent/HUMAN_PRESENT`, or an unreadable
override, also blocks. #364's open PR10 exposes the dataclass but has **no frozen
state.json serializer or trusted producer yet**. Both fixtures are synthetic
consumer examples, not producer golden bytes. Native serialization, provenance,
clock continuity and completeness must be confirmed with Ops before adoption.

## Window, DISABLE and journal

Fresh plans require 01:00 inclusive to 05:00 exclusive in `America/Chicago`,
including daylight-saving changes. The uninstalled timer retries at 15-minute
boundaries and includes a 05:00 final skip/report check. It has no daytime
catch-up. The CLI checks `~/.config/update-agent/DISABLE`; the service template
has the same guard. A dangling DISABLE symlink is still disabled. Permission or
read errors fail closed. A blocked plan may show steps for review but they are
never executed, regardless of `eligible`.

The `Journal` API is a Source primitive for the later authorized orchestrator.
It reserves a CT-date-named journal before the first effect, with a process lock,
atomic replace, file and directory fsync and mode 0600. It retains the exact
snapshot and SHA-256. Reserve before STOP; record `started` before each effect,
then `done` only with evidence, otherwise `UNKNOWN`. An update reservation is
never reused, including after a timeout or an unknown outcome. No fresh run may
replace a same-night journal. Do not delete a journal to retry an update.

`--journal` reads an existing journal and prints a verification-only recovery
plan using its original UUIDs and versions. Without that option the CLI scans
the bastion state directory for unfinished journals, including older nights,
before considering a new night. More than one unfinished journal or corruption
requires reconciliation; it never authorizes a new update. A completed nightly
journal suppresses another run on that CT date, including a repeated DST hour.
Dry runs do not consume the nightly reservation or write real journal state.

The verification contract requires qualified per-pane receipts: same address,
same UUID and profile, explicit last-message continuity, and for Codex an exact
`codex-ops.inbox_read` tool in the catalog. `verify_tabs` tests those receipts
without calling or consuming a live inbox. Missing evidence yields UNKNOWN.
The operational adapter must also verify installed and running versions,
completion of the WSL restart and unchanged holds before resuming the dispatcher.
An already attempted dispatcher resumption is not replayed; an uncertain outcome
requires reconciliation. Keep STOP on any verification failure.

The final report plan includes before/after versions and each tab's result.
#369 digest integration is pending; no Derpy/Slack messages are sent. Wake-on-LAN,
real stop/update/shutdown/start/restore, qualified runtime verification, a watched
run and nightly enablement remain outside this temporary Source helper.
