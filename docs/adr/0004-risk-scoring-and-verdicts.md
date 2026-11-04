# ADR-0004: Severities, verdicts and a noisy-or risk score

- **Status:** Accepted
- **Date:** 2026-11-04

## Context
A scanner that only says "safe" or "unsafe" forces one threshold on every user. A CI gate wants
few false alarms; an incident responder wants every unusual import.

## Decision
Every rule has a default severity (info, low, medium, high, critical) and some findings raise it
when the evidence is stronger (a dynamic import that is also called is critical). The verdict
follows the worst finding: critical is *malicious*, high is *unsafe*, medium is *suspicious*,
anything else is *clean*. The risk score is a noisy-or of per-severity weights (critical 0.95,
high 0.6, medium 0.25, low 0.05), scaled to 0 to 100, so many medium findings add up but never
outrank one critical finding. The CLI fails on `high` by default (`--fail-on`).

## Alternatives considered
- **Sum of weights.** Unbounded and dominated by the number of imports in large checkpoints.
- **Learned classifier.** No labeled real-world malicious set of useful size exists.

## Consequences
- The benchmark reports detection at the default threshold and at `medium`.
- Weights are a convention, not a probability; they are documented and tested.
