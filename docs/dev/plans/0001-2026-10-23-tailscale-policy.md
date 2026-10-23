# Scoped Tailscale policy integration

State: OPEN
Date: 2026-10-23

## Current State

The selected source slice is implemented on an isolated feature worktree.
Existing inventory, mesh installation, ingress, browser custody and deployed
software remain unchanged. The lead independently verified 112 passing tests and
product lint. Claude source review, installation and actual provider use remain
separate acceptance steps. Full-tree lint and privacy scans reproduce unchanged
baseline findings in installed policy-tool metadata; product changes add none.

## Objective and scope

Allow an operator to enroll a scoped OAuth credential privately, read the
canonical raw policy and its ETag, and validate reviewed candidate bytes. A
separate optional writer supports explicit conditional apply and rollback.
The reader is the initial operational configuration; no writer is provisioned.

Keep the provider API in `tailscale_policy.py`, separate from SSH directory
deployment. Add an optional inventory section with explicit authority and
credential references. Old inventories continue to validate. Inline credentials
are rejected, existing secret rules remain intact, and no environment scanning
or API-key fallback is permitted.

Non-goals: installing a mesh, replacing ingress or authentication, automated
provider sign-in, credential creation, policy rewriting, direct API writes for
GitOps-owned policy, and public release or main-branch integration.

## Work units and ownership

| Unit | Owner | Write surface | Depends on | Exit |
| --- | --- | --- | --- | --- |
| Core API and private state | Codex worker `ts1_policy_module` | module and focused tests | selected contract | tests and actual source returned |
| Integration and operator contract | Codex lead | CLI, schema, model/CLI tests, guide, this plan | selected contract | documented interfaces match source |
| Reconciliation and validation | Codex lead | accepted findings only | both source units | full suite, lint, public scan |
| Claude source review | exact existing peer task | read-only sanitized packet | validation | reviewed result or explicit findings |
| Installed reader bootstrap | lead and human | separately declared private DEV runtime | source review | installed smoke, then human enrollment |

Use at most two concurrent implementation agents including the lead. Do not edit
the worker's files until its terminal handoff. Preserve the worker runtime
handle in local evidence. No nested agents or peer chains. One consolidated
source discovery pass and one bounded remediation pass; later verification is
closed-world against accepted findings and critical regressions. Preserve the
existing task counters and shared budget across compaction or worker replacement.

## Acceptance criteria

- Human-only enrollment uses a real terminal and hidden prompts. Exclusive
  private files are owned by the operator, outside Git, with no symlinks or
  overwrites. Tokens remain in memory.
- Only fixed HTTPS vendor endpoints are used. Redirects, raw error bodies and
  credential-bearing output are rejected. Named environment references read
  only the named variable.
- Read preserves raw HuJSON comments, unknown fields and exact ETag, with a
  private digest-bound snapshot. Plan retains an exact private diff and records
  validation; only an empty 200 validation response is success.
- Apply requires console authority, a distinct writer reference, explicit apply,
  candidate hash and expected version. Verify baseline bytes, current version
  and writer validation before one conditional POST. A 412 stops; uncertain
  writes are observed without retry. Readback proves effect.
- Rollback validates the original snapshot and only writes while this operation's
  produced ETag remains current. It never overwrites a later policy version.
- Tests cover privacy, rejected references, raw bytes, validation availability,
  stale/hash failures, conditional writes, uncertainty and rollback. Existing
  inventories and commands pass their regressions. Public source uses reserved
  fixture values only.

## Verification and closeout

Run `python -m pytest`, `ruff check .`, `ruff format --check .`,
`python scripts/scan_public.py` and `git diff --check` in the task worktree.
Record exact candidate hashes and main-checkout integrity in the local review
packet. Inspect returned source rather than accepting a worker summary alone.
Report Standards and Spec separately, distinguishing source/offline acceptance
from installation and actual API acceptance. A credential reference is not proof
of enrollment or of real read/validation.

The lead inspected the worker's actual source and accepted two integration
findings: bind rollback eligibility to the policy POST response's ETag, and
classify truncated HTTP responses as uncertain transport outcomes. Worker
`/root/ts1_policy_module` returned both scoped repairs, with regression failures
observed before repair; the lead independently reran the full passing suite.
This records delegated provenance without importing runtime inventories or logs.

Continue safe in-scope work under the selected implementation authority. No new
permission form is needed for ordinary repairs. Stop only on an applicable
credential, runtime, peer-limit or user-decision gate, after finishing independent
work. Do not claim merge readiness while changes are uncommitted.
