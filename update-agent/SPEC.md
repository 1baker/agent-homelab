# #375 bounded Source spec sheet

State: OPEN for independent exact-head review; runtime remains unqualified.
The original approved design and product plan live on work-tracker #375.
This sheet covers the helper's narrower scripts/tests/dry-run assignment.

## Problem

Updates currently require manual host restart, restoration and chat resumption.
An agent executing in WSL cannot survive its own WSL shutdown. A safe Source
foundation must run from the bastion and preserve identity, holds and uncertain
outcomes before any later operational integration.

## Solution

Add an isolated standard-library planner, synthetic fixtures and tests, a durable
journal API, conservative idle gate, snapshot validation and uninstalled user
systemd templates. Print the full sequence with observed values; provide no
live executor. Reuse Baker's settled nightly/full-restart/two-tool choices.
No new grill decision is open in this Source slice.

## User stories

- As the operator, I can inspect real read-only observations and the proposed
  update/rollback/restore sequence before authorizing execution.
- As a recovering orchestrator, I retain the original snapshot and verify the
  outcome of an interrupted run without repeating the update.
- As a chat owner, my original UUID/profile and startup holds remain explicit;
  absent evidence never becomes idle or successful restoration.

## Implementation decisions

- Architecture: one bastion-side CLI with a fixed SSH reader and pure decision
  functions. No services, browser lifecycle, credentials or shared files change.
- Scale: one operator, one host, one update reservation per CT night, 15-minute
  eligibility checks from 01:00 until a final 05:00 skip/report.
- Data: versioned JSON inventory, snapshot and journal. Journal stores the full
  snapshot digest plus append-only step events; lock + atomic fsync protects
  reservation/update transitions. Existing/corrupt journals fail closed.
- Interfaces: the CLI's default and sole mode is DRY-RUN. Offline `--snapshot`,
  read-only `--inventory`, and recovery `--journal` are mutually exclusive.
  It emits JSON; exit 2 is an observation/validation error. An ineligible plan
  is a successful policy decision, with explicit blockers and no effects.
- Snapshot: complete static pane matrix matched against live tmux listing;
  profiles remain operator-reviewed. Record startup holds and service states,
  and pin normal-startup/Byobu wrapper source hashes. Never invoke a second
  per-pane launcher after the restore wrapper owns restoration.
- Versions: query installed versions and public vendor release tags over SSH;
  reject betas/unknown tags. Print exact version install and rollback commands
  for the declared npm/native method. Method ownership, retained rollback
  artifacts and real install integrity remain operational qualification gates.
- Recovery: reserve before effects, never reserve the update twice, recover at
  verify rather than replaying STOP/update/shutdown/restore/tab resumes. Preserve
  UNKNOWN outcomes. Dispatcher resumption follows successful verification.
- Safety: existing SSH trust only; no auto enrollment; fixed commands with
  JSON data, no eval of inventory and no arbitrary inventory shell command.
  Direct metadata GETs avoid npm cache/config effects. No provider extraction,
  paid API, Send, real restart or timer installation.
- Dependency: #364's `at`/`reasons` wire shape is provisional until its serializer
  is frozen with producer golden bytes. #321 wrapper invocation, #369 digest,
  trusted per-tab verification receipts and runtime install ownership require
  later integration. Missing prerequisites cannot become runtime PASS.
- Trade-off: implement a testable dry-run foundation instead of embedding an
  unqualified live restart runner. This meets the assigned orchestration-plan
  boundary and avoids guessing existing operational controls.
- Policy continuity: policy bundle provenance is unknown; this slice follows
  the checked-out AGENTS/policies without changing their adoption. No graph
  memory is used. CodeGraph status reports this fresh clone uninitialized;
  direct source reads suffice for the new isolated files. No index is installed.

## Plan and checks

1. Claim the exact new files and isolated branch; exclude PR10's files.
2. Build release detection + idle gate; test missing, stale, busy and override.
3. Build snapshot parser + journal; test identity/coverage and interrupted runs.
4. Build plan + timer templates; test ordering, pinned versions/rollback and
   that dry-run invokes no mutating subprocess and creates no journal.
5. Verify targeted tests, repository lint/privacy checks and an offline CLI flow.
6. Open a tested draft PR and send exact-head FYIs to Claude and Chief. Stop;
   both required reviews, any merge and operational follow-through stay with Ops.

The critical path is serialized under one helper writer. No child agent is
needed; independent native Codex and Claude reviews remain merge gates.

## Testing decisions and acceptance

The normal test tree contains `test_update_agent_375.py` so CI can discover the
new cases without changing shared CI configuration. Tests use only synthetic
observations, fake processes/network, and temporary journals. The remote reader
itself is exercised against the process fake, including trailing empty fields.
Acceptance covers busy decisions, CT/DST timing, versions, full pane coverage,
holds/wrappers, journal interruption/concurrency, per-tab receipt verification
and default dry-run output/no effects. A CLI user-flow check uses the committed
fixture. Ruff and the public-tree privacy scan apply to all new files.

Standards and Spec grades must remain separate. Author checks are not independent
review or permission to merge. The PR records final counts and exact-head
evidence; native Codex and actual Claude reviews remain pending at handoff.
Token use is UNKNOWN in this integration; expiry is the hard helper boundary.

### Author review card (not independent approval)

- Standards: PASS for the eight new files under the claimed scope. The changed
  Python files pass Ruff; the new source and normal test tree pass the privacy
  scanner. Whole-repository lint has 147 identical base/candidate findings in
  existing policy files; the full privacy scan has the same three existing
  policy-file home-path findings at both revisions. No shared file was changed.
- Spec: PASS for the assigned Source dry-run-plan boundary: 31 offline tests
  pass under pytest; the fixture CLI flow prints all ten planned stages and
  retains both synthetic UUIDs/profiles and the ETF hold. The remote reader is
  tested with fake process/network inputs. User systemd templates validate as
  files, including the quarter-hour CT schedule and final 05:00 check.
- Independent native Codex and Claude grades: NOT REVIEWED at helper handoff.
  Installation, a real read-only host dry run, a watched restart and end-to-end
  product acceptance: NOT RUN. #375 remains open. Source plan readiness must
  not be presented as operational update-agent completion.

## Out of scope

Real SSH qualification, installs/rollback, service/dispatcher changes, browser
or credential custody, WSL shutdown/start, WoL, pane typing, inbox claims, Send,
timer installation/enabling, watched runtime run, merge and whole-issue closure.
No shared install helper, service unit or PR10-owned file is edited. No real
snapshot, account details, host addresses or private logs are committed.
