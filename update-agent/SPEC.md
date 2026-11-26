# #375 inert Source contract

## Problem

A maintenance decision must remain safe when an owner returns after an idle check, an ingress owner cannot drain, or an acknowledgment disappears during an update. The governing contracts are NINE v3 (`d4591c0d3bf92e12f0e1696e6b3920ddf77cf308c7c3a0ef901d9d6fd91d35fc`) and the #375 v6 amendment (`ffc30879cab7c4c14c06adc8ff705b89d98e3dfc03801be876dcb14c7a5ef4f1`). The amendment replaces the nightly window with eligibility whenever idle.

## Solution

Evaluate an attempt as an ordered fixture trace. A fixture event carries an attempt, machine, distro, old boot, sequence, expected prior sequence, writer generation and time. Under-fence receipts additionally join on epoch and manifest digest. Fixture inputs can model observations that the real system cannot yet produce. The evaluator never grants operational eligibility.

## User stories

An owner returning between notice and fence cancels the attempt. An owner returning after the fence can trigger a safe unwind before shutdown. A later STOP survives. An unresolved install stays UNKNOWN until a durable reconciliation for that operation. After a definite partial update, recovery uses the observed versions of the individual tools and restores before verifying. After shutdown has been issued there is no presence abort; ambiguity keeps the fences.

## Implementation decisions

- C1 accepts exactly busy, reasons, at and seq. A future sample or age over five minutes is unknown. C2 must be clear, DISABLE absent, both ETF unit families fully covered and inactive, and ETF-350-HOLD present. No operation may touch ETF. A version observation must describe the configured method and channel and a side-effect-free source. An unsupported actual observer is held.
- Require an attempt-bound, journaled heads-up confirmed by the #349 poster and #369 digest, a ten-minute wait, at most one notice per four hours, twenty minutes idle and a fresh P-0 reading. At G-pre and each G-k, require a sample collected after the boundary opened, last input strictly before notice time minus the stated uncertainty, and at most five seconds from sample to effect. A post-effect presence race is recorded. Before shutdown it is considered at the next gate; after shutdown it is reported. Three presence cancellations for the same update in 24 hours stop further attempts until the next calendar day. A non-presence fault suspends automation until cleared. No automatic retry follows a disruptive failure.
- G-pre evaluates R1 availability, R2 participant coverage and the installed R3 schema/role mapping. READY requires successful fence and drain, a manifest built under that fence, and independent R1/R2/R3 evidence for one attempt, epoch and digest. R1 models a surviving operator and single writer. R2 requires every ingress owner, including pending approvals, transfers and uncertain helper slots, with original queue order preserved. An available participant is not a drained participant.
- R1 intent precedes each simulated action. Match operation ID, expected stage and writer before consuming a definite observation. A missing or ambiguous acknowledgment keeps the last **confirmed** versions; never infer the target version or issue another update. Durable reconciliation is required after an explicit unknown acknowledgment. A confirmed rollback must observe the original version. A confirmed interruption before STOP permits only the owned fence to unwind; after STOP the recovery sequence includes service and tab restore and verification. An installed change at a failed presence gate holds for rollback disposition before release.
- On unwind, preserve foreign or changed generations. Resume the dispatcher only when this attempt owns its STOP and no other STOP exists. After shutdown an optional restore wake requires the exact held epoch, journal holder, admitted restore stage and successful veto/marker/DISABLE readbacks. Partial or unknown restore keeps the fence. The startup and restore wrappers are digest-bound; a Claude row needs BSS plus the adopted role launcher, expected role map and configuration digest. Each agent requires its own non-consuming audit matching the attempt, observed boot, manifest, owner, generation, placement, settings, profile, continuity and caller. Chief comes last. Verification checks installed and running versions plus observed hold and service states. LastPass unlock remains human-only.
- The evaluator reads a synthetic R1 trace and emits a pure decision. It does not create real durable reservations, clear a suspension, deliver a notice, or certify a surviving operator. Proposed names in `fixture.*` describe test data only. Real P-0 belongs to the PC/#364 custodian; Chief and the bastion/Windows owners must qualify R1; each ingress owner supplies R2; BSS/Root, the Claude role custodians and each registered caller supply R3. Missing real enrollment keeps all operational paths held.

## Testing decisions

Use synthetic C1 and snapshot files and isolated, in-memory trace variations. Check exact freshness and frontier bounds, both phases of admission, empty/missing/foreign generations, notice cooldown, presence before and after fence, crashes before and after intent, post-update UNKNOWN and rollback, stale and cross-caller verification, boot/veto checks and retention of prior STOPs. Verify the no-effect CLI and inert templates. A passing fixture does not qualify the real suppliers or any restart.

## Out of scope

Deployment, installing or enabling services, real journal or registry access, version queries, the Windows/WSL control route, actual operator failover, credential access, wake/restore/queue actions and any live rehearsal. Future producer or runtime work requires separate custody and selection. No new machinery is implied by the two source templates.
