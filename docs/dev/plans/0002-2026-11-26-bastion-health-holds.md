# Bounded expected-down classification (#409)

State: OPEN

## Current State

The pure classifier and 28 offline public-interface tests exist. No actual
checker call site or alert transport is integrated. The existing PM request
for canonical checker Source is pending. No deployment or production policy
entry is included. Full health-check delivery remains incomplete.

## Problem and solution

A deliberately down route needs a visible HELD result without hiding real
outages. Classify supplied observations using explicit exact-route/backend
records with owner, reason, ticket and expiry of at most 14 days. Never infer
producer intent from another machine's consumer STOP marker.

## Scope and user stories

Implement only the stdlib pure classifier, its tests and this operator guidance.
An operator can distinguish healthy listeners, bounded intentional downtime and
failures that require alerts. Missing or invalid policy never disables checks.

## Implementation decisions

One deep pure boundary receives bytes, observations and clock. It returns a
small value-free status and alert obligation, with no runtime I/O, CLI, hidden
configuration lookup or notification side effect. A reviewed operator policy
attests intent but does not prove current runtime custody. Retain the route.
No speculative general alerting framework or changes to the inert update agent.

## Testing decisions and plan

1. Observe an absent-interface RED, then a valid explicit HELD GREEN.
2. Observe expiry-boundary and overlong-lifetime REDs, then enforce both.
3. Test missing, mismatched, future, malformed and ambiguous records fail closed.
4. Compose the real module with fake observations and a fake alert receiver.
5. Run relevant checks, freeze a PR and obtain the required independent native
   and actual Claude reviews at the same head. Bind canonical checker Source
   before describing the overall checker repair as complete.

## Non-goals and definition of done

No live route/service change, installed checker execution, host probe, credentials,
browser action, notification Send or deploy. Real policy requires producer-owner
confirmation and separate operational authorization. This mechanism is done
when its accepted Source PR is merged/read back; the delivery ticket stays open
for checker integration, actual alert visibility and qualified live acceptance.
